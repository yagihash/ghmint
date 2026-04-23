package ghmint

issuer := "https://token.actions.githubusercontent.com"

permissions := {"contents": "read"}

default allow := false

allow if {
	regex.match(`^repo:yagihash/ghmint:.+$`, input.sub)
}
