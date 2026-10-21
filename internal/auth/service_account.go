package auth

import (
	"encoding/json"
	"encoding/base64"
	"encoding/pem"
	"sync"
	"time"
	"fmt"
)

const Scope = "https://www.googleapis.com/auth/adwords"
const Rsa = "RS256"
const Jwt = "JWT"

type ServiceAccount struct {
	Type string `json:"type"`
	ProjectId string `json:"project_id"`
	PrivateKeyId string `json:"private_key_id"`
	PrivateKey string `json:"private_key"`
	ClientEmail string `json:"client_email"`
	ClientId string `json:"client_id"`
	AuthUri string `json:"auth_uri"`
	TokenUri string `json:"token_uri"`
	AuthProviderX509CertUrl string `json:"auth_provider_x509_cert_url"`
	ClientX509CertUrl string `json:"client_x509_cert_url"`
	UniverseDomain string `json:"universe_domain"`

	// Optional attributes for OAuth
	Sub string `json:"-"`

	// Token response data
	AccessToken string `json:"access_token"`
	Scope string `json:"scope"`
	TokenType string `json:"token_type"`

	// Access management
	Mu sync.Mutex `json:"-"`
	Expiry time.Time `json:"-"`
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
}

type jwtClaim struct {
	Iss string `json:"iss"`
	Scope string `json:"scope"`
	Aud string `json:"aud"`
	Exp int64 `json:"exp"`
	Iat int64 `json:"iat"`
	Sub string `json:"sub,omitempty"`
}

type jwtPart interface {
	jwtHeader | jwtClaim
}

func encodePart[J jwtPart] (part J) (string, error) {
	enc, err := json.Marshal(part)
	if err != nil {
		return "", nil
	}

	return base64.RawURLEncoding.EncodeToString(enc)
}

func (s *ServiceAccount) buildJwt() (string, error) {
	header := jwtHeader{
		Alg : Rsa,
		Typ : Jwt,
		Kid : s.PrivateKeyId,
	}

	now := time.Now().Unix()
	claim := jwtClaim{
		Iss : s.ClientEmail,
		Scope : Scope,
		Aud : s.TokenUri,
		Exp : now + (59 * 60),
		Iat : now,
		Sub : s.Sub,
	}
}

func (s *ServiceAccount) createJws(header string, claim string) (string, error) {
	input := fmt.Sprintf("%s.%s", header, claim)
	block, _ := pem.Decode(s.PrivateKey)

	return "hello", nil
}
