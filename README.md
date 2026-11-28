# ghmint

[![CI](https://github.com/yagihash/ghmint/actions/workflows/ci.yml/badge.svg)](https://github.com/yagihash/ghmint/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Reference](https://pkg.go.dev/badge/github.com/yagihash/ghmint.svg)](https://pkg.go.dev/github.com/yagihash/ghmint)

> [!CAUTION]
> **Not production ready.** This project is under active development. Breaking changes may be introduced at any time, and no versioned releases are planned for the near future. Use at your own risk.

A lightweight Security Token Service (STS) that issues GitHub App Installation Access Tokens to callers who present a valid OIDC ID Token and satisfy a [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) policy.

## How it works

```
Caller presents OIDC ID Token
         │
         ▼
  Verify JWT signature, aud, exp, iat
         │
         ▼
  Fetch .github/ghmint/<policy>.rego
  from the target repository
         │
         ▼
  Evaluate Rego policy against token claims
  → permissions, repositories
         │  (deny → 403)
         ▼
  Issue GitHub App Installation Access Token
  scoped to the resolved permissions/repositories
         │
         ▼
  Return token to caller
```

Policies live alongside the code they protect — each repository (or organization) manages its own `.github/ghmint/*.rego` files.

## Getting started

### Prerequisites

- A [GitHub App](https://docs.github.com/en/apps/creating-github-apps/about-creating-github-apps/about-creating-github-apps) installed on the target organizations/repositories
- Google Cloud project with:
  - Cloud KMS asymmetric signing key (RSA 2048, SHA-256) holding the GitHub App private key
  - Cloud Run (or any container runtime)
- An OIDC provider (e.g., GitHub Actions, Google Cloud, etc.)

### Deploying to Cloud Run

1. **Create a GitHub App** and note the App ID. Upload the private key to Cloud KMS as an asymmetric signing key.

2. **Build and push the container image:**

   ```sh
   docker build -t gcr.io/<PROJECT>/ghmint .
   docker push gcr.io/<PROJECT>/ghmint
   ```

3. **Deploy to Cloud Run:**

   ```sh
   gcloud run deploy ghmint \
     --image gcr.io/<PROJECT>/ghmint \
     --set-env-vars "STS_APP_ID=<APP_ID>" \
     --set-env-vars "STS_AUDIENCE=<CLOUD_RUN_HOSTNAME>" \
     --set-env-vars "STS_KMS_PROJECT_ID=<PROJECT>" \
     --set-env-vars "STS_KMS_LOCATION=global" \
     --set-env-vars "STS_KMS_KEYRING_ID=<KEYRING>" \
     --set-env-vars "STS_KMS_KEY_ID=<KEY>" \
     --set-env-vars "STS_KMS_KEY_VERSION=1"
   ```

4. **Call the STS from GitHub Actions:**

   The easiest way is to use [yagihash/ghmint-action](https://github.com/yagihash/ghmint-action):

   ```yaml
   permissions:
     id-token: write   # required for OIDC token

   steps:
     - uses: yagihash/ghmint-action@<ref>
       id: token
       with:
         hostname: <CLOUD_RUN_HOSTNAME>
         scope: <org>          # or <org>/<repo>
         policy: <policy-name>

     - run: echo "${{ steps.token.outputs.token }}"
   ```

   <details>
   <summary>Manual curl equivalent</summary>

   ```yaml
   - name: Get GitHub token
     id: token
     run: |
       OIDC_TOKEN=$(curl -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
         "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=<CLOUD_RUN_HOSTNAME>" | jq -r .value)
       RESPONSE=$(curl -sSf https://<CLOUD_RUN_HOSTNAME>/token \
         -H "Authorization: Bearer $OIDC_TOKEN" \
         -H "Content-Type: application/json" \
         -d '{"scope":"<org>","policy":"<policy-name>"}')
       echo "token=$(echo $RESPONSE | jq -r .token)" >> $GITHUB_OUTPUT
   ```

   </details>

   <details>
   <summary>RFC 7523 (JWT Bearer grant) form</summary>

   `POST /token` also accepts `application/x-www-form-urlencoded` and behaves as an [RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523) token endpoint:

   ```sh
   curl -sSf https://<CLOUD_RUN_HOSTNAME>/token \
     --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" \
     --data-urlencode "assertion=$OIDC_TOKEN" \
     --data-urlencode "scope=<org>:<policy-name>"   # or <org>/<repo>:<policy-name>
   # => {"access_token":"ghs_...","token_type":"Bearer","expires_in":3599,...}
   ```

   Errors use the RFC 6749 §5.2 format (`{"error":"invalid_grant",...}`).

   </details>

## Configuration

All environment variables use the `STS_` prefix.

| Variable | Required | Default | Description |
|---|---|---|---|
| `STS_APP_ID` | ✓ | — | GitHub App ID |
| `STS_AUDIENCE` | ✓ | — | Hostname of this service (plain hostname, no scheme) |
| `STS_KMS_PROJECT_ID` | ✓ | — | Google Cloud project ID containing the KMS key |
| `STS_KMS_LOCATION` | ✓ | — | KMS key location (e.g. `global`) |
| `STS_KMS_KEYRING_ID` | ✓ | — | KMS key ring name |
| `STS_KMS_KEY_ID` | ✓ | — | KMS key name |
| `STS_KMS_KEY_VERSION` | ✓ | — | KMS key version (integer) |
| `STS_ALLOWED_ISSUERS` | | `https://token.actions.githubusercontent.com` | Comma-separated list of accepted OIDC issuer URLs |
| `STS_WEBHOOK_SECRET` | | — | GitHub webhook secret; enables `POST /webhook` for Rego policy validation on PRs |
| `STS_APPS` | | — | Comma-separated names of additional GitHub Apps (see [Multiple GitHub Apps](#multiple-github-apps)) |
| `STS_PORT` | | `8080` | HTTP listen port |
| `STS_DEBUG` | | `false` | Enable debug logging |

### Multiple GitHub Apps

`STS_APP_ID` and `STS_KMS_*` define the App named `default`. It fetches policy files, receives webhooks, and issues tokens for policies that do not select an App. Existing deployments keep working without any change.

To register more Apps, list their names in `STS_APPS` and set one group of variables per name. A name must match `[a-z][a-z0-9-]{0,31}`, and `default` is reserved. In the variable names the name is upper-cased and `-` becomes `_`:

| Variable | Required | Description |
|---|---|---|
| `STS_APP_<NAME>_ID` | ✓ | GitHub App ID |
| `STS_APP_<NAME>_KMS_PROJECT_ID` | ✓ | Google Cloud project ID containing the KMS key |
| `STS_APP_<NAME>_KMS_LOCATION` | ✓ | KMS key location |
| `STS_APP_<NAME>_KMS_KEYRING_ID` | ✓ | KMS key ring name |
| `STS_APP_<NAME>_KMS_KEY_ID` | ✓ | KMS key name |
| `STS_APP_<NAME>_KMS_KEY_VERSION` | ✓ | KMS key version (integer) |

For example, to add an App named `release-bot`:

```sh
STS_APPS=release-bot
STS_APP_RELEASE_BOT_ID=789012
STS_APP_RELEASE_BOT_KMS_PROJECT_ID=<PROJECT>
STS_APP_RELEASE_BOT_KMS_LOCATION=global
STS_APP_RELEASE_BOT_KMS_KEYRING_ID=<KEYRING>
STS_APP_RELEASE_BOT_KMS_KEY_ID=<KEY>
STS_APP_RELEASE_BOT_KMS_KEY_VERSION=1
```

The service refuses to start if a listed App has a missing variable, an invalid or duplicate name, or a non-integer key version. Each App must be installed on the owners (`scope`) that policies request tokens for.

## Writing policies

Policy files live at `.github/ghmint/<policy-name>.rego` in the repository specified by `scope`.

**Package declaration** must be `ghmint`:

```rego
package ghmint
```

**Required rules:**

| Rule | Type | Description |
|---|---|---|
| `issuer` | `string` | Accepted OIDC issuer URL. The STS checks `input.iss` against this value. |
| `allow` | `boolean` | Grant the token when `true`. `false` and `undefined` both deny; the latter is logged as a misconfiguration. |
| `permissions` | `object` | GitHub App permissions to grant (e.g. `{"contents": "read"}`). Keys and values must be valid GitHub App permission names. |
| `repositories` | `array` (optional) | Repositories to scope the token to. Omit to use the default (see below). Must be omitted when `scope` is `org/repo`. |
| `app` | `string` (optional) | Name of the GitHub App to issue the token from (see [Multiple GitHub Apps](#multiple-github-apps)). Omit to use `default`. |

**`repositories` defaults:**

| Definition | Behaviour |
|---|---|
| Omitted (`undefined`) | The repository inferred from `scope` (for `org/repo`) or `org/.github` (for `org`) |
| `[]` (empty array) | All repositories the App has access to |
| `["org/a", "org/b"]` | Exactly the listed repositories |

**`app`:**

The token is issued by the selected App, from its installation on the owner in `scope`. `permissions` and `repositories` behave exactly as without `app`. Policy files themselves are always fetched with the `default` App.

| Definition | Behaviour |
|---|---|
| Omitted | Issued by the `default` App |
| Name of a registered App | Issued by that App |
| Unregistered name | No token is issued. The client gets `403` (like any other policy failure); the reason is only in the server log. The webhook check also reports it on the pull request. |

```rego
app := "release-bot"
```

> **Note:** any policy can name any registered App. ghmint does not restrict which policies may use which App, so register an App only if every policy author whose repository the App is installed on may use it.

**Example — GitHub Actions caller:**

```rego
package ghmint

issuer := "https://token.actions.githubusercontent.com"

permissions := {"contents": "read"}

allow if {
    input.repository == "myorg/myrepo"
    input.ref == "refs/heads/main"
}
```

`input` contains all OIDC token claims (`sub`, `iss`, `repository`, `ref`, `workflow`, etc.).

## Using as a library

ghmint can be embedded in your own service with custom `Signer`, `Verifier`, and `PolicyStore` implementations:

```go
import (
    "github.com/yagihash/ghmint/pkg/app"
    "github.com/yagihash/ghmint/pkg/installation"
)

installClient := installation.New(appID, mySigner)

a, err := app.New(app.Config{
    Audience:     "my-sts.example.com",
    Installation: installClient,
    Logger:       myLogger,
    Verifier:     myVerifier, // implements pkg/verifier.Verifier
})
if err != nil {
    log.Fatal(err)
}
a.Serve(":8080")
```

See [`pkg/app`](./pkg/app), [`pkg/signer`](./pkg/signer), [`pkg/verifier`](./pkg/verifier), and [`pkg/policystore`](./pkg/policystore) for interface definitions.

## HTTP API

| Method | Path | Description |
|---|---|---|
| `GET` | `/healthz` | Health check — returns `{}` |
| `POST` | `/token` | Issue a GitHub App Installation Access Token |
| `POST` | `/webhook` | GitHub `pull_request` webhook for Rego policy validation (requires `STS_WEBHOOK_SECRET`) |

## Contributing

Pull requests and issues are welcome. Please open a [GitHub Issue](https://github.com/yagihash/ghmint/issues) for bugs or feature requests.

## Security

To report a vulnerability, please use [GitHub Private Security Advisories](https://github.com/yagihash/ghmint/security/advisories/new).

## License

[MIT](./LICENSE)
