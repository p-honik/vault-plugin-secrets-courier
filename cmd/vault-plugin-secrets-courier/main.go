// Command vault-plugin-secrets-courier serves the Courier secrets engine as a
// Vault plugin.
package main

import (
	"log"
	"os"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"

	"github.com/p-honik/vault-plugin-secrets-courier/internal/backend"
)

func main() {
	meta := &api.PluginAPIClientMeta{}
	flags := meta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		log.Fatal(err)
	}

	err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: backend.Factory,
		TLSProviderFunc:    api.VaultPluginTLSProvider(meta.GetTLSConfig()),
	})
	if err != nil {
		log.Fatal(err)
	}
}
