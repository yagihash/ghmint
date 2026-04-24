package ghmint

# Allow GitHub Actions workflows running on the main branch of a specific repository
# to receive a token with read access to repository contents.
#
# Place this file at:
#   .github/ghmint/github-actions.rego
# in the repository you want to protect, then call the STS with:
#   scope: "myorg/myrepo"
#   policy: "github-actions"

issuer := "https://token.actions.githubusercontent.com"

permissions := {"contents": "read"}

allow if {
    input.repository == "myorg/myrepo"
    input.ref == "refs/heads/main"
    input.event_name == "push"
}
