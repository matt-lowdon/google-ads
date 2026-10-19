package auth

import (
	"fmt"
	"bytes"
	"time"
	"sync"
	"context"
	"net/http"
	"net/url"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"crypto"
	"crypto/sha256"
	"crypto/rsa"
	"crypto/x509"
)

// For marshalling JSON JWT header
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
}

// For marshalling JSON JWT claim
type jwtClaim struct {
	Iss string `json:"iss"`
	Scope string `json:"scope"`
	Aud string `json:"aud"`
	Exp int64 `json:"exp"`
	Iat int64 `json:"iat"`
	Sub string `json:"sub,omitempty"`
}

type serviceAccountKeys struct {
	Type string `json:"type"`
	ProjectId string `json:"project_id"`
	PrivateKeyId string `json:"private_key_id"`
	PrivateKey string `json:"private_key"`
	ClientEmail string `json:"client_email"`
	ClientId string `json:"client_id"`
	AuthUri string `json:"auth_uri"`
	TokenUri string `json:"token_uri"`
	AuthProviderCertUrl string `json:"auth_provider_x509_cert_url"`
	ClientCertUrl string `json:"client_x509_cert_url"`
	UniverseDomain string `json:"universe_domain"`

	// Optional keys
	Subject string
}

type serviceAccountAuthResponse struct {
	AccessToken string `json:"access_token"`
	Scope string `json:"string"`
	TokenType string `json:"token_type"`
	ExpiresIn int64 `json:"expires_in"`
}

type ServiceAccount struct {
	mu sync.Mutex
	token string
	expiry time.Time
}

func (s *ServiceAccount) Token (ctx context.Context) (string, error) {
	jwt, err := s.buildJwt()
	if err != nil {
		return "", err
	}

	authUrl, err := s.buildAuthUrl(jwt)
	if err != nil {
		return "", nil
	}

	body := new(bytes.Buffer)
	
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		authUrl.String(),
		body,
	)
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	defer resp.Body.Close()
	if err != nil {
		return "", err
	}
}

func (s *ServiceAccount) buildJwt() (string, error) {
	header := jwtHeader {
		Alg : "RS256",
		Typ : "JWT",
		Kid : s.ClientId,
	}

	now := time.Now().Unix()

	claim := jwtClaim {
		Iss : s.ClientEmail,
		Scope : "https://www.googleapis.com/auth/adwords",
		Aud : s.TokenUri,
		Exp : now + (59 * 60),
		Iat : now,
		Sub : s.Subject,
	}

	jsonHeader, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	jsonClaim, err := json.Marshal(claim)
	if err != nil {
		return "", err
	}

	block, _:= pem.Decode([]byte(s.PrivateKey))
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	encodedHeader := base64.URLEncoding.EncodeToString(jsonHeader)
	encodedClaim := base64.URLEncoding.EncodeToString(jsonClaim)

	sigInput := fmt.Sprintf("%s.%s", encodedHeader, encodedClaim)

	hashed := sha256.Sum256([]byte(sigInput))
	signature, err := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA256, hashed[:])

	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s.%s", sigInput, base64.URLEncoding.EncodeToString(signature)), nil
}

func (s *ServiceAccount) buildAuthUrl(jwt string) (url.URL, error){
	u, err := url.Parse(s.TokenUri)
	if err != nil {
		return "", err
	}

	query := u.Query()
	query.Add("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	query.Add("assertion", jwt)
	u.RawQuery = query.Encode()

	return u, nil
}

	body := new(bytes.Buffer)
	response, err := http.Post(u.String(), "application/x-www-form-urlencoded", body)
}
