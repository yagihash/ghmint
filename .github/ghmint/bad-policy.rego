package ghmint

issuer := "https://token.actions.githubusercontent.com"

permissions := {"contents": "admin", "nonexistent_perm": "read"}

allow if {
	input.repository == "yagihash/ghmint"
}
