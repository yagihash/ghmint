package ghmint

issuer := "https://token.actions.githubusercontent.com"

permissions := {"contents": "read", "pull_requests": "read"}

default allow := false

allow if {
	regex.match(`^repo:yagihash/ghmint:.+$`, input.sub)
	input.ref == "refs/heads/main"
}
