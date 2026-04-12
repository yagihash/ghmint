package policyerrors

// DenialError はポリシー起因の失敗を表す。
// server.go はこのエラーを受け取った場合 403 FORBIDDEN を返す（fail-closed 方針）。
// 内部エラー（INTERNAL_ERROR）と区別するために独立した型として定義する。
type DenialError struct {
	Reason string
}

func (e *DenialError) Error() string {
	return e.Reason
}
