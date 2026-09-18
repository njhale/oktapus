// Oktapus creates throwaway Okta groups and assigns them to users, for exercising Obot's Okta auth
// provider group sync at sizes that are tedious to set up by hand.
//
// It needs an Okta API Services app whose key it can sign with, granted okta.groups.manage,
// okta.groups.read and okta.users.read, and holding an admin role that can manage groups.
// Organization Administrator or Super Administrator are the roles that can create and delete
// groups; Group Administrator only covers membership.
//
//	export OKTA_ORG_URL=https://your-org.okta.com
//	export OKTA_SERVICE_CLIENT_ID=0oa...
//	export OKTA_SERVICE_PRIVATE_KEY_FILE=./key.pem
//	oktapus create 50
package main

import (
	"github.com/njhale/oktapus/pkg/cli"
	"github.com/obot-platform/cmd"
)

func main() {
	cmd.Main(cli.New())
}
