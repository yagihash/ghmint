# ghmint

[![CI](https://github.com/yagihash/ghmint/actions/workflows/go-test.yml/badge.svg)](https://github.com/yagihash/ghmint/actions/workflows/go-test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Reference](https://pkg.go.dev/badge/github.com/yagihash/ghmint.svg)](https://pkg.go.dev/github.com/yagihash/ghmint)

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
| `STS_PORT` | | `8080` | HTTP listen port |
| `STS_DEBUG` | | `false` | Enable debug logging |

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

**`repositories` defaults:**

| Definition | Behaviour |
|---|---|
| Omitted (`undefined`) | The repository inferred from `scope` (for `org/repo`) or `org/.github` (for `org`) |
| `[]` (empty array) | All repositories the App has access to |
| `["org/a", "org/b"]` | Exactly the listed repositories |

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

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## Security

To report a vulnerability, please use [GitHub Private Security Advisories](https://github.com/yagihash/ghmint/security/advisories/new). See [SECURITY.md](./SECURITY.md) for details.

## License

[MIT](./LICENSE)
