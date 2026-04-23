package ghmint

issuer := "https://token.actions.githubusercontent.com"

permissions := {"contents": "read"}

default allow := false

allow if {
	input.sub == "repo:yagihash/ghmint:pull_request"
}
