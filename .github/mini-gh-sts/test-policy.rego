package mini_gh_sts

default allow := false

allow if {
	regex.match(`^repo:yagihash/mini-gh-sts:.+$`, input.sub)
}
