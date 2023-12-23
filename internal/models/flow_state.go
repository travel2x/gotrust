package models

import (
	"fmt"
	"github.com/gofrs/uuid"
	"strings"
	"time"
)

type FlowType int
type CodeChallengeMethod int

type FlowState struct {
	ID                   uuid.UUID  `json:"id" db:"id"`
	UserID               *uuid.UUID `json:"user_id,omitempty" db:"user_id"`
	AuthCode             string     `json:"auth_code" db:"auth_code"`
	AuthenticationMethod string     `json:"authentication_method" db:"authentication_method"`
	CodeChallenge        string     `json:"code_challenge" db:"code_challenge"`
	CodeChallengeMethod  string     `json:"code_challenge_method" db:"code_challenge_method"`
	ProviderType         string     `json:"provider_type" db:"provider_type"`
	ProviderAccessToken  string     `json:"provider_access_token" db:"provider_access_token"`
	ProviderRefreshToken string     `json:"provider_refresh_token" db:"provider_refresh_token"`
	CreatedAt            time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at" db:"updated_at"`
}

const (
	PKCEFlow FlowType = iota
	ImplicitFlow
	SHA256 CodeChallengeMethod = iota
	Plain
)

func (flowType FlowType) String() string {
	switch flowType {
	case PKCEFlow:
		return "pkce"
	case ImplicitFlow:
		return "implicit"
	}
	return ""
}

func (FlowType) TableName() string {
	tableName := "flow_type"
	return tableName
}

func NewFlowState(providerType, codeChallenge string, codeChallengeMethod CodeChallengeMethod, authenticationMethod AuthenticationMethod) (*FlowState, error) {
	id := uuid.Must(uuid.NewV4())
	authCode := uuid.Must(uuid.NewV4())

	flowState := &FlowState{
		ID:                   id,
		ProviderType:         providerType,
		CodeChallenge:        codeChallenge,
		CodeChallengeMethod:  codeChallengeMethod.String(),
		AuthCode:             authCode.String(),
		AuthenticationMethod: authenticationMethod.String(),
	}
	return flowState, nil
}

func ParseCodeChallengeMethod(codeChallengeMethod string) (CodeChallengeMethod, error) {
	switch strings.ToLower(codeChallengeMethod) {
	case "s256":
		return SHA256, nil
	case "plain":
		return Plain, nil
	default:
		return 0, fmt.Errorf("unsupported code_challenge method %q", codeChallengeMethod)
	}
}

func (codeChallengeMethod CodeChallengeMethod) String() string {
	switch codeChallengeMethod {
	case SHA256:
		return "s256"
	case Plain:
		return "plain"
	}
	return ""
}
