package mini_gh_sts

default allow := false

allow if {
	input.iss == "https://token.actions.githubusercontent.com"
	input.sub == "repo:yagihash/mini-gh-sts:pull_request"
}
