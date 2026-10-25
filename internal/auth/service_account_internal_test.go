package auth

import (
	"testing"
)

func TestEncodeHeader(t *testing.T) {
	header := jwtHeader{
		Alg : "RS256",
		Typ : "JWT",
		Kid : "370ab79b4513eb9bad7c9bd16a95cb76b5b2a56a",
	}

	want := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjM3MGFiNzliNDUxM2ViOWJhZDdjOWJkMTZhOTVjYjc2YjViMmE1NmEifQ"	
	enc, err := encodePart(header)
	if !(want == enc) || err != nil {
		t.Errorf(`encodePart(header) = %s, %v, want %s`, enc, err, want)
	}
}
