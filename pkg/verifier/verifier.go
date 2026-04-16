package verifier

import "context"

type Verifier interface {
	// Verify は OIDC 検証済みの claims をポリシーで評価し、
	// 発行する permissions と repositories を返す。
	// deny・設定ミスを含むあらゆる失敗は *policyerrors.DenialError として返す。
	// それ以外の error は内部エラー（500）として扱われる。
	Verify(ctx context.Context, claims map[string]interface{}, scope, policy string) (permissions map[string]string, repositories []string, err error)
}
