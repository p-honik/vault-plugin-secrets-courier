package backend

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathConfig is courier/config: the delivery
// settings every mount has plus the parameters of the mount's credential type,
// written and read through one endpoint.
func pathConfig(b *backend) []*framework.Path {
	fields := map[string]*framework.FieldSchema{
		"delivery_retry":   {Type: framework.TypeString, Default: defaultDeliveryRetry, Description: "never or once"},
		"retry_delay":      {Type: framework.TypeDurationSecond, Default: int(defaultRetryDelay.Seconds()), Description: "Wait before the single retry."},
		"delivery_timeout": {Type: framework.TypeDurationSecond, Default: int(defaultDeliveryTimeout.Seconds()), Description: "Per delivery attempt."},
		"max_inflight":     {Type: framework.TypeInt, Default: defaultMaxInflight, Description: "Maximum concurrent deliveries."},
		"allowed_networks": {Type: framework.TypeCommaStringSlice, Description: "CIDRs deliveries may connect to. Mutually exclusive with denied_networks."},
		"denied_networks":  {Type: framework.TypeCommaStringSlice, Description: "CIDRs deliveries must not connect to. Mutually exclusive with allowed_networks."},
	}
	for k, v := range b.ctype.configFields() {
		fields[k] = v
	}
	return []*framework.Path{{
		Pattern: "config",
		Fields:  fields,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.guard(kindAuthenticated, "config.read", b.handleConfigRead)},
			logical.CreateOperation: &framework.PathOperation{Callback: b.guard(kindAuthenticated, "config.write", b.handleConfigWrite)},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.guard(kindAuthenticated, "config.write", b.handleConfigWrite)},
		},
		ExistenceCheck: b.guardExistence("config.exists", func(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
			entry, err := req.Storage.Get(ctx, storageConfig)
			return entry != nil, err
		}),
		HelpSynopsis: "Configure delivery behavior, process-wide limits and the credential type.",
	}}
}

// handleConfigRead returns the effective values, defaults included, and the
// mount's type. Before the first write only the delivery defaults exist.
func (b *backend) handleConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	cfg, exists, err := loadConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	data := map[string]interface{}{
		"type":             b.ctype.name(),
		"delivery_retry":   cfg.DeliveryRetry,
		"retry_delay":      int(cfg.RetryDelay.Seconds()),
		"delivery_timeout": int(cfg.DeliveryTimeout.Seconds()),
		"max_inflight":     cfg.MaxInflight,
		"allowed_networks": cfg.AllowedNetworks,
		"denied_networks":  cfg.DeniedNetworks,
	}
	if exists {
		for k, v := range b.ctype.configData(cfg) {
			data[k] = v
		}
	}
	return &logical.Response{Data: data}, nil
}

// handleConfigWrite is a partial update under the configuration lock: unsent
// parameters keep their stored values (defaults on the first write), the merged
// result is validated, and a rejected write changes nothing.
// The first write must include the type's required parameters (for jwt, the
// issuer); it records the mount's type and, for jwt, creates the initial key set.
// Keys are generated before any storage write, and the key set is stored before
// the config.
func (b *backend) handleConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.configLock.Lock()
	defer b.configLock.Unlock()
	if !b.WriteSafeReplicationState() {
		return nil, logical.ErrReadOnly
	}

	old, exists, err := loadConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	first := !exists
	merged := copyConfig(old)
	merged.Type = b.ctype.name()

	if v, ok := d.GetOk("delivery_retry"); ok {
		merged.DeliveryRetry = v.(string)
	}
	if v, ok := d.GetOk("retry_delay"); ok {
		merged.RetryDelay = time.Duration(v.(int)) * time.Second
	}
	if v, ok := d.GetOk("delivery_timeout"); ok {
		merged.DeliveryTimeout = time.Duration(v.(int)) * time.Second
	}
	if v, ok := d.GetOk("max_inflight"); ok {
		merged.MaxInflight = v.(int)
	}
	if v, ok := d.GetOk("allowed_networks"); ok {
		merged.AllowedNetworks = nonNil(v.([]string))
	}
	if v, ok := d.GetOk("denied_networks"); ok {
		merged.DeniedNetworks = nonNil(v.([]string))
	}
	if msg := b.ctype.mergeConfig(merged, d, first); msg != "" {
		return logical.ErrorResponse(msg), nil
	}

	roles, err := loadAllRoles(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if err := validateMountConfig(&merged.mountConfig); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	if err := b.ctype.validateConfig(merged, roles); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	var prev *storedConfig
	if exists {
		prev = old
	}
	store, msg, err := b.ctype.prepareWrite(ctx, req.Storage, prev, merged, b.now())
	if err != nil {
		return nil, err
	}
	if msg != "" {
		return logical.ErrorResponse(msg), nil
	}

	// The cache is cleared after the writes, whatever their outcome.
	defer b.invalidate()
	if store != nil {
		if err := store(ctx, req.Storage); err != nil {
			return nil, err
		}
	}
	if err := putJSON(ctx, req.Storage, storageConfig, merged); err != nil {
		return nil, err
	}
	// Tightening applies at once, including to the retry of an in-flight delivery.
	// Invalidate first: a request that read the old config must not be able to
	// replace the new policy afterwards.
	b.invalidate()
	b.installPolicy(&merged.mountConfig)
	return nil, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
