package ghmint

# Allow any repository in the organization to receive a token with read access
# to a fixed set of repositories, as long as the workflow runs on main.
#
# Place this file at:
#   .github/ghmint/org-wide.rego
# in the <org>/.github repository, then call the STS with:
#   scope: "myorg"
#   policy: "org-wide"
#
# Note: with scope="myorg", the policy file is fetched from myorg/.github.

issuer := "https://token.actions.githubusercontent.com"

permissions := {"contents": "read"}

# Explicitly list the repositories this token may access.
# Use [] to grant access to all repositories the App is installed on.
repositories := ["myorg/shared-lib", "myorg/common-config"]

allow if {
    startswith(input.repository, "myorg/")
    input.ref == "refs/heads/main"
}
