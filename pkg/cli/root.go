// Package cli implements the oktapus command tree.
package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/obot-platform/cmd"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	root := &Oktapus{}
	return cmd.Command(root,
		&Create{root: root},
		&List{root: root},
		&Assign{root: root},
		&Remove{root: root},
		&Groups{root: root},
		&Limits{root: root},
		&Delete{root: root},
		&Menu{root: root},
	)
}

type Oktapus struct {
	Org      string `usage:"Okta org URL, with no path" env:"OKTA_ORG_URL"`
	ClientID string `usage:"API Services app client ID" env:"OKTA_SERVICE_CLIENT_ID"`
	KeyFile  string `usage:"PEM private key file; OKTA_SERVICE_PRIVATE_KEY holds the PEM itself" env:"OKTA_SERVICE_PRIVATE_KEY_FILE"`
	Workers  int    `usage:"Concurrent Okta requests" default:"4"`

	client *Client
}

// GroupFilter is shared by every command that selects groups by name. It is embedded rather than
// hung off the root so that --prefix stays local to the commands it means something for.
type GroupFilter struct {
	Prefix string `usage:"Group name prefix" default:"obot-test-"`
}

func (o *Oktapus) Customize(c *cobra.Command) {
	c.Use = "oktapus"
	c.Short = "Create throwaway Okta groups and assign them to users"
}

func (o *Oktapus) Run(c *cobra.Command, _ []string) error {
	return c.Help()
}

// PersistentPre builds the Okta client once for whichever subcommand is running, and authenticates
// before any of them start work so a misconfigured app fails with Okta's own message rather than
// partway through a bulk run.
func (o *Oktapus) PersistentPre(c *cobra.Command, _ []string) error {
	// Bare `oktapus` only prints help, which should not demand credentials.
	if !c.HasParent() {
		return nil
	}

	keyPEM := os.Getenv("OKTA_SERVICE_PRIVATE_KEY")
	if o.KeyFile != "" {
		b, err := os.ReadFile(o.KeyFile)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", o.KeyFile, err)
		}
		keyPEM = string(b)
	}

	switch {
	case o.Org == "":
		return errors.New("set --org or OKTA_ORG_URL")
	case o.ClientID == "":
		return errors.New("set --client-id or OKTA_SERVICE_CLIENT_ID")
	case keyPEM == "":
		return errors.New("set --key-file, OKTA_SERVICE_PRIVATE_KEY_FILE, or OKTA_SERVICE_PRIVATE_KEY")
	}

	client, err := NewClient(o.Org, o.ClientID, keyPEM)
	if err != nil {
		return err
	}

	if _, err := client.accessToken(c.Context()); err != nil {
		return fmt.Errorf("authentication failed: %w\n\nCheck that %s has %s granted, exactly one key registered,\nand client authentication set to Public key / Private key", err, o.ClientID, strings.Join(requiredScopes, ", "))
	}

	fmt.Printf("Authenticated to %s as %s\n", client.orgURL, client.clientID)
	o.client = client

	return nil
}
