# oktapus

Creates throwaway Okta groups and assigns them to users, for exercising Obot's Okta auth provider
group sync at sizes that are tedious to set up by hand. It also has a probe for the rate limit on
the group fetch the provider performs during login.

## Build

Requires Go 1.26.4 or newer.

```bash
make build
```

The binary lands at `bin/oktapus`. Other targets: `make test`, `make vet`, `make fmt`, `make tidy`,
`make clean`, and `make ci` for everything CI checks.

## Configuration

oktapus authenticates as an Okta API Services app, signing a client assertion with that app's
private key. In Okta, create the app with client authentication set to **Public key / Private key**,
register exactly one key, and grant these scopes:

- `okta.groups.manage`
- `okta.groups.read`
- `okta.users.read`

The app also needs an admin role that can create and delete groups — Organization Administrator or
Super Administrator. Group Administrator only covers membership.

Configure the tool through environment variables or the equivalent global flags:

| Variable | Flag | Meaning |
| --- | --- | --- |
| `OKTA_ORG_URL` | `--org` | Org URL with no path, e.g. `https://your-org.okta.com` |
| `OKTA_SERVICE_CLIENT_ID` | `--client-id` | API Services app client ID |
| `OKTA_SERVICE_PRIVATE_KEY_FILE` | `--key-file` | Path to the PEM private key |
| `OKTA_SERVICE_PRIVATE_KEY` | — | The PEM itself, instead of a file |
| — | `--workers` | Concurrent Okta requests (default 4) |

The key may be PKCS#1 or PKCS#8 RSA PEM, with real newlines or the escaped `\n` that Obot stores in
the provider credential.

```bash
export OKTA_ORG_URL=https://your-org.okta.com
export OKTA_SERVICE_CLIENT_ID=0oa...
export OKTA_SERVICE_PRIVATE_KEY_FILE=./key.pem
```

Every subcommand authenticates before doing any work, so a misconfigured app fails immediately with
Okta's own error rather than partway through a bulk run.

## Usage

Groups are named `<prefix>NNNN`, with `--prefix` defaulting to `obot-test-`. Commands that select
groups by name all accept `--prefix`. `USER` is anything Okta's user search matches — login, email,
or name; an ambiguous query prompts you to pick.

```bash
oktapus create 50              # create obot-test-0001 through obot-test-0050
oktapus list                   # list groups matching the prefix
oktapus assign alice@corp.com  # add a user to every matching group
oktapus remove alice@corp.com  # remove a user from every matching group
oktapus groups alice@corp.com  # show the groups a user belongs to
oktapus delete                 # delete every matching group (--yes skips the prompt)
oktapus menu                   # the same operations, interactively
```

`create` numbers from `--start` (default 1) and is idempotent: a name that already exists is
skipped.

### Rate limits

`oktapus limits USER` replays the auth provider's own group fetch and reports what Okta says about
the rate-limit bucket. It skips the 429 retry the rest of the tool uses, so rejections are observed
rather than absorbed.

```bash
oktapus limits alice@corp.com                          # one quiet fetch, printed page by page
oktapus limits alice@corp.com --until-limited          # push until Okta returns a 429
oktapus limits alice@corp.com --concurrency 8 --for 30s
```

Flags: `--page-size` (1–1000, default 200, matching the provider), `--concurrency` (default 1),
`--repeat` (default 1; 0 runs until interrupted), `--for` (a duration such as `30s`, instead of a
fixed count), `--until-limited`.
