package mini_gh_sts

issuer := "https://token.actions.githubusercontent.com"

permissions := {"contents": "read"}

default allow := false

allow if {
	regex.match(`^repo:yagihash/mini-gh-sts:.+$`, input.sub)
}
