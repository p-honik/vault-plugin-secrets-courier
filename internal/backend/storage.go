package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/hashicorp/vault/sdk/logical"
)

// getJSON reads one storage entry into out. It reports whether the entry exists.
func getJSON(ctx context.Context, s logical.Storage, key string, out interface{}) (bool, error) {
	entry, err := s.Get(ctx, key)
	if err != nil {
		return false, err
	}
	if entry == nil {
		return false, nil
	}
	if err := json.Unmarshal(entry.Value, out); err != nil {
		return false, fmt.Errorf("decoding %q: %w", key, err)
	}
	return true, nil
}

func putJSON(ctx context.Context, s logical.Storage, key string, v interface{}) error {
	entry, err := logical.StorageEntryJSON(key, v)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

// loadConfig returns the stored config, or the defaults (with an empty Type and
// no JWT part) when none has been written. exists reports whether an entry is
// stored.
func loadConfig(ctx context.Context, s logical.Storage) (cfg *storedConfig, exists bool, err error) {
	cfg = &storedConfig{mountConfig: *defaultMountConfig()}
	exists, err = getJSON(ctx, s, storageConfig, cfg)
	if err != nil {
		return nil, false, err
	}
	return cfg, exists, nil
}

// loadJWTConfig returns nil when the config has not been written.
func loadJWTConfig(ctx context.Context, s logical.Storage) (*jwtConfig, error) {
	cfg, _, err := loadConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	return cfg.JWT, nil
}

// loadKeySet returns nil when no key set has been stored.
func loadKeySet(ctx context.Context, s logical.Storage) (*keySet, error) {
	ks := &keySet{}
	ok, err := getJSON(ctx, s, storageKeySet, ks)
	if err != nil || !ok {
		return nil, err
	}
	return ks, nil
}

// loadRole returns nil when the role does not exist.
func loadRole(ctx context.Context, s logical.Storage, name string) (*role, error) {
	r := &role{}
	ok, err := getJSON(ctx, s, storageRolePrefix+name, r)
	if err != nil || !ok {
		return nil, err
	}
	return r, nil
}

// loadAllRoles reads every stored role, keyed by name. Used for
// cross-validation under the configuration lock.
func loadAllRoles(ctx context.Context, s logical.Storage) (map[string]*role, error) {
	names, err := s.List(ctx, storageRolePrefix)
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	out := make(map[string]*role, len(names))
	for _, n := range names {
		r, err := loadRole(ctx, s, n)
		if err != nil {
			return nil, err
		}
		if r != nil {
			out[n] = r
		}
	}
	return out, nil
}
