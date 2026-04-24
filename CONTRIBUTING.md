# Contributing to ghmint

Thank you for your interest in contributing!

## Development setup

**Requirements:**
- Go 1.26 or later (`go version`)
- A Google Cloud project (for integration tests involving KMS; unit tests use a local RSA signer)

**Clone and build:**

```sh
git clone https://github.com/yagihash/ghmint.git
cd ghmint
go build ./...
```

**Run tests:**

```sh
go test -race ./...
```

## Local development without KMS

The reference implementation uses Cloud KMS for signing, but you can run ghmint locally with a generated RSA key via `internal/signer`. See `cmd/ghmint/main.go` for how the signer is wired; swapping in `internal/signer.NewRSASigner` avoids any cloud dependency.

## Code style

- Format: `gofmt` (run `go fmt ./...`)
- Lint: [`ghalint`](https://github.com/suzuki-shunsuke/ghalint) for GitHub Actions workflows
- Workflow lint: [`actionlint`](https://github.com/rhysd/actionlint)

CI enforces all of the above on every pull request.

## Pull request process

1. Fork the repository and create a branch from `main`.
2. Make your changes with tests.
3. Ensure `go test -race ./...` passes locally.
4. Open a pull request against `main`.

Please keep pull requests focused — one concern per PR makes review easier.

## Reporting bugs

Open a [GitHub Issue](https://github.com/yagihash/ghmint/issues/new) with:
- What you did
- What you expected
- What actually happened
- Go version and OS

For security vulnerabilities, see [SECURITY.md](./SECURITY.md).
