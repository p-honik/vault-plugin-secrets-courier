package backend

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathRole is courier/roles/:name and the role list.
//
// The :name segment accepts any single path segment and the handlers validate
// it against the role name rule (validRoleName): create or update rejects a bad
// name with a 400, read and delete treat it as not found.
func pathRole(b *backend) []*framework.Path {
	fields := map[string]*framework.FieldSchema{
		"name":                 {Type: framework.TypeString, Description: "Role name: lowercase letters, digits, - and _, at most 64 characters."},
		"allowed_receipt_urls": {Type: framework.TypeStringSlice, Description: "Exact-match allowlist, at most 64 entries, validated against the strict format."},
		"require_nonce":        {Type: framework.TypeBool, Default: false, Description: "Refuse requests that omit a nonce."},
		"min_request_interval": {Type: framework.TypeDurationSecond, Default: int(defaultMinRequestInterval.Seconds()), Description: "Minimum time between accepted requests for the same role and receipt URL."},
		"receipt_ca_pem":       {Type: framework.TypeString, Description: "PEM CA bundle trusted when delivering to this role's URLs."},
	}
	// The mount's type adds exactly its own fields.
	for k, v := range b.ctype.roleFields() {
		fields[k] = v
	}
	return []*framework.Path{
		{
			Pattern: "roles/" + `(?P<name>[^/]+)`,
			Fields:  fields,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation:   &framework.PathOperation{Callback: b.guard(kindAuthenticated, "role.read", b.handleRoleRead)},
				logical.CreateOperation: &framework.PathOperation{Callback: b.guard(kindAuthenticated, "role.write", b.handleRoleWrite)},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.guard(kindAuthenticated, "role.write", b.handleRoleWrite)},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.guard(kindAuthenticated, "role.delete", b.handleRoleDelete)},
			},
			ExistenceCheck: b.guardExistence("role.exists", func(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
				name, _ := d.Get("name").(string)
				if !validRoleName(name) {
					return false, nil
				}
				r, err := loadRole(ctx, req.Storage, name)
				return r != nil, err
			}),
			HelpSynopsis: "Manage roles: the receipt URLs allowed to receive credentials, and what the mount's type needs.",
		},
		{
			Pattern: "roles/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.guard(kindAuthenticated, "role.list", b.handleRoleList)},
			},
			HelpSynopsis: "List roles.",
		},
	}
}

// handleRoleWrite is a partial update under the configuration lock: unsent
// parameters keep their stored values (defaults on the first write), and the
// merged role is validated against the stored config.
func (b *backend) handleRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if !validRoleName(name) {
		return logical.ErrorResponse("role name must match [a-z0-9]([a-z0-9_-]*[a-z0-9])? and be at most 64 characters"), nil
	}
	b.configLock.Lock()
	defer b.configLock.Unlock()
	if !b.WriteSafeReplicationState() {
		return nil, logical.ErrReadOnly
	}

	existing, err := loadRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	merged := &role{MinRequestInterval: defaultMinRequestInterval}
	merged.TTL = defaultRoleTTL
	if existing != nil {
		c := *existing
		merged = &c
	}
	if v, ok := d.GetOk("allowed_receipt_urls"); ok {
		merged.AllowedReceiptURLs = v.([]string)
	}
	if v, ok := d.GetOk("require_nonce"); ok {
		merged.RequireNonce = v.(bool)
	}
	if v, ok := d.GetOk("min_request_interval"); ok {
		merged.MinRequestInterval = time.Duration(v.(int)) * time.Second
	}
	if v, ok := d.GetOk("receipt_ca_pem"); ok {
		merged.ReceiptCAPEM = v.(string)
	}

	// Roles cannot be created before the first config write.
	cfg, exists, err := loadConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if !exists {
		return logical.ErrorResponse("a role cannot be created before config is written"), nil
	}
	if msg := b.ctype.mergeRole(cfg, existing, merged, d); msg != "" {
		return logical.ErrorResponse(msg), nil
	}
	if err := validateRoleGeneric(name, merged); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	if err := b.ctype.validateRole(merged, cfg); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	err = putJSON(ctx, req.Storage, storageRolePrefix+name, merged)
	b.invalidate()
	if err != nil {
		return nil, err
	}
	return nil, nil
}

// handleRoleRead: a name that fails validRoleName is simply not found.
func (b *backend) handleRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if !validRoleName(name) {
		return nil, nil
	}
	r, err := loadRole(ctx, req.Storage, name)
	if err != nil || r == nil {
		return nil, err
	}
	data := map[string]interface{}{
		"allowed_receipt_urls": r.AllowedReceiptURLs,
		"require_nonce":        r.RequireNonce,
		"min_request_interval": int(r.MinRequestInterval.Seconds()),
		"receipt_ca_pem":       r.ReceiptCAPEM,
	}
	for k, v := range b.ctype.roleData(r) {
		data[k] = v
	}
	return &logical.Response{Data: data}, nil
}

// handleRoleDelete removes a role under the configuration lock. Deleting an
// absent role, or a name that fails validRoleName, is a no-op.
func (b *backend) handleRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if !validRoleName(name) {
		return nil, nil
	}
	b.configLock.Lock()
	defer b.configLock.Unlock()
	if !b.WriteSafeReplicationState() {
		return nil, logical.ErrReadOnly
	}
	err := req.Storage.Delete(ctx, storageRolePrefix+name)
	b.invalidate()
	return nil, err
}

func (b *backend) handleRoleList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	names, err := req.Storage.List(ctx, storageRolePrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(names), nil
}
