package ghmint

issuer := "https://token.actions.githubusercontent.com"

permissions := {"contents": "write", "pull_requests": "write"}

default allow := false

allow if {
	input.sub == "repo:yagihash/ghmint:ref:refs/heads/main"
}
