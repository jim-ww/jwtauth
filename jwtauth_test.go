package jwtauth_test

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jim-ww/jwtauth/v6"
)

var (
	TokenAuthHS256 *jwtauth.JWTAuth
	TokenSecret    = []byte("secretpass")

	TokenAuthRS256 *jwtauth.JWTAuth

	PrivateKeyRS256String = `-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBALxo3PCjFw4QjgOX06QCJIJBnXXNiEYwDLxxa5/7QyH6y77nCRQy
J3x3UwF9rUD0RCsp4sNdX5kOQ9PUyHyOtCUCAwEAAQJARjFLHtuj2zmPrwcBcjja
IS0Q3LKV8pA0LoCS+CdD+4QwCxeKFq0yEMZtMvcQOfqo9x9oAywFClMSlLRyl7ng
gQIhAOyerGbcdQxxwjwGpLS61Mprf4n2HzjwISg20cEEH1tfAiEAy9dXmgQpDPir
C6Q9QdLXpNgSB+o5CDqfor7TTyTCovsCIQDNCfpu795luDYN+dvD2JoIBfrwu9v2
ZO72f/pm/YGGlQIgUdRXyW9kH13wJFNBeBwxD27iBiVj0cbe8NFUONBUBmMCIQCN
jVK4eujt1lm/m60TlEhaWBC3p+3aPT2TqFPUigJ3RQ==
-----END RSA PRIVATE KEY-----
`

	PublicKeyRS256String = `-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALxo3PCjFw4QjgOX06QCJIJBnXXNiEYw
DLxxa5/7QyH6y77nCRQyJ3x3UwF9rUD0RCsp4sNdX5kOQ9PUyHyOtCUCAwEAAQ==
-----END PUBLIC KEY-----
`
)

func init() {
	TokenAuthHS256 = jwtauth.New(jwt.SigningMethodHS256, TokenSecret)
}

//
// Tests
//

func TestSimple(t *testing.T) {
	r := chi.NewRouter()

	r.Use(
		TokenAuthHS256.Verifier(),
		TokenAuthHS256.Authenticator(),
	)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("welcome"))
	})

	ts := httptest.NewServer(r)
	defer ts.Close()

	tt := []struct {
		Name          string
		Authorization string
		Status        int
		RespContains  string
	}{
		{Name: "empty token", Authorization: "", Status: 401, RespContains: "no token found"},
		{Name: "wrong token", Authorization: "Bearer asdf", Status: 401, RespContains: "token is malformed"},
		{Name: "wrong secret", Authorization: "Bearer " + newJwtTokenHS256([]byte("wrong")), Status: 401, RespContains: "signature is invalid"},
		{Name: "wrong alg", Authorization: "Bearer " + newJwtTokenHS512(TokenSecret), Status: 401, RespContains: "algorithm mismatch"},
		{Name: "expired token", Authorization: "Bearer " + newJwtTokenHS256(TokenSecret, jwt.MapClaims{"exp": time.Now().Unix() - 1000}), Status: 401, RespContains: "token is expired"},
		{Name: "valid token", Authorization: "Bearer " + newJwtTokenHS256(TokenSecret), Status: 200, RespContains: "welcome"},
		{Name: "valid Bearer", Authorization: "Bearer " + newJwtTokenHS256(TokenSecret, jwt.MapClaims{"service": "test"}), Status: 200, RespContains: "welcome"},
		{Name: "valid BEARER", Authorization: "BEARER " + newJwtTokenHS256(TokenSecret), Status: 200, RespContains: "welcome"},
		{Name: "valid bearer", Authorization: "bearer " + newJwtTokenHS256(TokenSecret), Status: 200, RespContains: "welcome"},
		{Name: "valid claim", Authorization: "Bearer " + newJwtTokenHS256(TokenSecret, jwt.MapClaims{"service": "test"}), Status: 200, RespContains: "welcome"},
		{Name: "invalid bearer_", Authorization: "BEARER_" + newJwtTokenHS256(TokenSecret), Status: 401, RespContains: "no token found"},
		{Name: "invalid bearerx", Authorization: "BEARERx" + newJwtTokenHS256(TokenSecret), Status: 401, RespContains: "no token found"},
	}

	for _, tc := range tt {
		h := http.Header{}
		if tc.Authorization != "" {
			h.Set("Authorization", tc.Authorization)
		}
		status, resp := testRequest(t, ts, "GET", "/", h, nil)
		if status != tc.Status || !strings.Contains(resp, tc.RespContains) {
			t.Errorf("test '%s' failed: expected Status: %d containing %q, got %d %q", tc.Name, tc.Status, tc.RespContains, status, resp)
		}
	}
}

func TestSimpleRSA(t *testing.T) {
	privateKeyBlock, _ := pem.Decode([]byte(PrivateKeyRS256String))
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		t.Fatalf(err.Error())
	}

	publicKeyBlock, _ := pem.Decode([]byte(PublicKeyRS256String))
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// For RSA, we need to use the private key for signing and public key for verification
	rsaPublicKey := publicKey.(*rsa.PublicKey)

	// Create a custom keyfunc for RSA that can handle both signing and verification
	keyFunc := func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, fmt.Errorf("algorithm mismatch")
		}
		// For verification, return public key
		return rsaPublicKey, nil
	}

	// Create JWTAuth with custom keyfunc for RSA
	TokenAuthRS256 = &jwtauth.JWTAuth{
		Method:  jwt.SigningMethodRS256,
		Key:     privateKey,
		KeyFunc: keyFunc,
	}

	claims := jwt.MapClaims{
		"key":  "val",
		"key2": "val2",
		"key3": "val3",
	}

	_, tokenString, err := TokenAuthRS256.Encode(claims)
	if err != nil {
		t.Fatalf("Failed to encode claims %s\n", err.Error())
	}

	token, err := TokenAuthRS256.VerifyToken(tokenString)
	if err != nil {
		t.Fatalf("Failed to decode token string %s\n", err.Error())
	}

	tokenClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("Failed to get claims from token")
	}

	// Compare only the custom claims, ignoring standard claims like exp, iat, etc.
	for k, v := range claims {
		if tokenClaims[k] != v {
			t.Errorf("Claim %q: expected %v, got %v", k, v, tokenClaims[k])
		}
	}
}

func TestSimpleRSAVerifyOnly(t *testing.T) {
	// Use a pre-signed token for verification-only test
	tokenString := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJrZXkiOiJ2YWwiLCJrZXkyIjoidmFsMiIsImtleTMiOiJ2YWwzIn0.kLEK3FZZPsAlQNKR5yHyjRyrlCJFhvKmrh7o-GqDT_zaGQgvb0Dufp8uNSMeOFAlLGK5FbKX7BckjJqfvEyrTQ"
	claims := jwt.MapClaims{
		"key":  "val",
		"key2": "val2",
		"key3": "val3",
	}

	publicKeyBlock, _ := pem.Decode([]byte(PublicKeyRS256String))
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		t.Fatalf(err.Error())
	}

	rsaPublicKey := publicKey.(*rsa.PublicKey)

	// Create keyfunc for verification only
	keyFunc := func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, fmt.Errorf("algorithm mismatch")
		}
		return rsaPublicKey, nil
	}

	// Create verifier-only instance
	verifierOnly := &jwtauth.JWTAuth{
		Method:  jwt.SigningMethodRS256,
		Key:     nil, // No signing key
		KeyFunc: keyFunc,
	}

	// Should not be able to encode without private key
	_, _, err = verifierOnly.Encode(claims)
	if err == nil {
		t.Fatalf("Expecting error when encoding claims without signing key")
	}

	// Should be able to verify with public key only
	token, err := verifierOnly.VerifyToken(tokenString)
	if err != nil {
		t.Fatalf("Failed to decode token string: %s\n", err.Error())
	}

	tokenClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("Failed to get claims from token")
	}

	// Compare only the custom claims
	for k, v := range claims {
		if tokenClaims[k] != v {
			t.Errorf("Claim %q: expected %v, got %v", k, v, tokenClaims[k])
		}
	}
}

func TestMore(t *testing.T) {
	r := chi.NewRouter()

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(TokenAuthHS256.Verifier())

		authenticator := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				token, _, err := jwtauth.FromContext(r.Context())

				if err != nil {
					http.Error(w, err.Error(), http.StatusUnauthorized)
					return
				}

				if token == nil || !token.Valid {
					http.Error(w, "token is invalid", http.StatusUnauthorized)
					return
				}

				// Token is authenticated, pass it through
				next.ServeHTTP(w, r)
			})
		}
		r.Use(authenticator)

		r.Get("/admin", func(w http.ResponseWriter, r *http.Request) {
			_, claims, err := jwtauth.FromContext(r.Context())

			if err != nil {
				w.Write([]byte(fmt.Sprintf("error! %v", err)))
				return
			}

			w.Write([]byte(fmt.Sprintf("protected, user:%v", claims["user_id"])))
		})
	})

	// Public routes
	r.Group(func(r chi.Router) {
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("welcome"))
		})
	})

	ts := httptest.NewServer(r)
	defer ts.Close()

	// sending unauthorized requests
	if status, resp := testRequest(t, ts, "GET", "/admin", nil, nil); status != 401 || !strings.Contains(resp, "no token found") {
		t.Fatalf("Expected 401 with 'no token found', got %d: %s", status, resp)
	}

	h := http.Header{}
	h.Set("Authorization", "BEARER "+newJwtTokenHS256([]byte("wrong"), jwt.MapClaims{}))
	if status, resp := testRequest(t, ts, "GET", "/admin", h, nil); status != 401 || !strings.Contains(resp, "signature is invalid") {
		t.Fatalf("Expected 401 with 'signature is invalid', got %d: %s", status, resp)
	}

	h.Set("Authorization", "BEARER asdf")
	if status, resp := testRequest(t, ts, "GET", "/admin", h, nil); status != 401 || !strings.Contains(resp, "token is malformed") {
		t.Fatalf("Expected 401 with 'token is malformed', got %d: %s", status, resp)
	}

	// wrong alg
	h.Set("Authorization", "BEARER "+newJwtTokenHS512(TokenSecret, jwt.MapClaims{}))
	if status, resp := testRequest(t, ts, "GET", "/admin", h, nil); status != 401 || !strings.Contains(resp, "algorithm mismatch") {
		t.Fatalf("Expected 401 with 'algorithm mismatch', got %d: %s", status, resp)
	}

	// expired token
	h = newAuthHeader(jwt.MapClaims{"exp": time.Now().Unix() - 1000})
	if status, resp := testRequest(t, ts, "GET", "/admin", h, nil); status != 401 || !strings.Contains(resp, "token is expired") {
		t.Fatalf("Expected 401 with 'token is expired', got %d: %s", status, resp)
	}

	// sending authorized requests
	if status, resp := testRequest(t, ts, "GET", "/", nil, nil); status != 200 || resp != "welcome" {
		t.Fatalf("Expected 200 with 'welcome', got %d: %s", status, resp)
	}

	h = newAuthHeader(jwt.MapClaims{"user_id": 31337, "exp": time.Now().Add(5 * time.Minute).Unix()})
	if status, resp := testRequest(t, ts, "GET", "/admin", h, nil); status != 200 || !strings.Contains(resp, "protected, user:31337") {
		t.Fatalf("Expected 200 with 'protected, user:31337', got %d: %s", status, resp)
	}
}

func TestEncodeClaims(t *testing.T) {
	claims := jwt.MapClaims{
		"key1": "val1",
		"key2": 2,
		"key3": time.Now(),
		"key4": []string{"1", "2"},
		"jti":  "123",
	}

	if _, _, err := TokenAuthHS256.Encode(claims); err != nil {
		t.Fatalf("unexpected error encoding valid claims: %v", err)
	}
}

func TestContext(t *testing.T) {
	ctx := context.Background()

	// Test with nil token and error
	ctx = jwtauth.NewContext(ctx, nil, nil)
	token, claims, err := jwtauth.FromContext(ctx)
	if token != nil || claims == nil || err != nil {
		t.Errorf("Expected nil token, empty claims, nil error, got %v, %v, %v", token, claims, err)
	}

	// Test with token and error
	testErr := fmt.Errorf("test error")

	// Create a simple valid token for testing
	testToken, _, err := TokenAuthHS256.Encode(jwt.MapClaims{"test": "value"})
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	ctx = jwtauth.NewContext(ctx, testToken, testErr)
	token, claims, err = jwtauth.FromContext(ctx)
	if token != testToken || err != testErr {
		t.Errorf("Expected test token and error, got %v, %v", token, err)
	}
}

//
// Test helper functions
//

func testRequest(t *testing.T, ts *httptest.Server, method, path string, header http.Header, body io.Reader) (int, string) {
	req, err := http.NewRequest(method, ts.URL+path, body)
	if err != nil {
		t.Fatal(err)
		return 0, ""
	}

	for k, v := range header {
		req.Header.Set(k, v[0])
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
		return 0, ""
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
		return 0, ""
	}
	defer resp.Body.Close()

	return resp.StatusCode, string(respBody)
}

func newJwtTokenHS256(secret []byte, claims ...jwt.Claims) string {
	var claimsToUse jwt.Claims = jwt.MapClaims{}
	if len(claims) > 0 {
		claimsToUse = claims[0]
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claimsToUse)
	tokenString, err := token.SignedString(secret)
	if err != nil {
		log.Fatal(err)
	}
	return tokenString
}

func newJwtTokenHS512(secret []byte, claims ...jwt.Claims) string {
	var claimsToUse jwt.Claims = jwt.MapClaims{}
	if len(claims) > 0 {
		claimsToUse = claims[0]
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claimsToUse)
	tokenString, err := token.SignedString(secret)
	if err != nil {
		log.Fatal(err)
	}
	return tokenString
}

func newAuthHeader(claims ...jwt.Claims) http.Header {
	h := http.Header{}
	h.Set("Authorization", "BEARER "+newJwtTokenHS256(TokenSecret, claims...))
	return h
}
