package mini_gh_sts

issuer := "https://token.actions.githubusercontent.com"

permissions := {"contents": "read"}

default allow := false

allow if {
	input.sub == "repo:yagihash/mini-gh-sts:pull_request"
}
