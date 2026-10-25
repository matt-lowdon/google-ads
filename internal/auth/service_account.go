package auth

import (
	"encoding/json"
	"encoding/base64"
	"encoding/pem"
	"crypto"
	"crypto/x509"
	"crypto/rsa"
	"crypto/sha256"
	"sync"
	"time"
	"fmt"
	"errors"
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

	return base64.RawURLEncoding.EncodeToString(enc), nil
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

	encHeader, err := encodePart(header)
	encClaim, err := encodePart(claim)

	if err != nil {
		return "", nil
	}

	sig, err := s.createJws(encHeader, encClaim)

	if err != nil {
		return sig, err
	}

	return fmt.Sprintf("%s.%s.%s", encHeader, encClaim, sig), nil
}

func (s *ServiceAccount) createJws(header string, claim string) (string, error) {
	block, _ := pem.Decode([]byte(s.PrivateKey))
	if block == nil || block.Type != "PRIVATE KEY" {
		return "", errors.New("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	input := fmt.Sprintf("%s.%s", header, claim)
	hashed := sha256.Sum256([]byte(input))

	signature, err := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", nil
	}

	return base64.RawURLEncoding.EncodeToString(signature), nil
}


