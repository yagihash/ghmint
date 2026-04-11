package mini_gh_sts

default allow := false

allow if {
	input.iss == "https://token.actions.githubusercontent.com"
	regex.match(`^repo:yagihash/mini-gh-sts:.+$`, input.sub)
}
