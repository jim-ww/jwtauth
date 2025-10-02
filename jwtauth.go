package jwtauth

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type JWTAuth struct {
	Method  jwt.SigningMethod
	Key     any
	KeyFunc jwt.Keyfunc
}

var (
	TokenCtxKey = &contextKey{"Token"}
	ErrorCtxKey = &contextKey{"Error"}
)

var (
	ErrUnauthorized = errors.New("token is unauthorized")
	ErrNoTokenFound = errors.New("no token found")
	ErrAlgoInvalid  = errors.New("algorithm mismatch")
)

func New(method jwt.SigningMethod, key any) *JWTAuth {
	ja := &JWTAuth{
		Method: method,
		Key:    key,
	}

	ja.KeyFunc = func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != ja.Method.Alg() {
			return nil, ErrAlgoInvalid
		}
		return ja.Key, nil
	}

	return ja
}

func (ja *JWTAuth) Verifier() func(http.Handler) http.Handler {
	return ja.Verify(TokenFromHeader, TokenFromCookie)
}

func (ja *JWTAuth) Verify(findTokenFns ...func(r *http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		hfn := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			token, err := ja.VerifyRequest(r, findTokenFns...)
			ctx = NewContext(ctx, token, err)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(hfn)
	}
}

func (ja *JWTAuth) VerifyRequest(r *http.Request, findTokenFns ...func(r *http.Request) string) (*jwt.Token, error) {
	var tokenString string

	for _, fn := range findTokenFns {
		tokenString = fn(r)
		if tokenString != "" {
			break
		}
	}
	if tokenString == "" {
		return nil, ErrNoTokenFound
	}

	return ja.VerifyToken(tokenString)
}

func (ja *JWTAuth) VerifyToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, ja.KeyFunc)
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, ErrUnauthorized
	}

	return token, nil
}

func (ja *JWTAuth) Encode(claims jwt.Claims) (*jwt.Token, string, error) {
	t := jwt.NewWithClaims(ja.Method, claims)
	tokenString, err := t.SignedString(ja.Key)
	return t, tokenString, err
}

func (ja *JWTAuth) Authenticator() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		hfn := func(w http.ResponseWriter, r *http.Request) {
			token, _, err := FromContext(r.Context())

			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			if token == nil || !token.Valid {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(hfn)
	}
}

func NewContext(ctx context.Context, t *jwt.Token, err error) context.Context {
	ctx = context.WithValue(ctx, TokenCtxKey, t)
	ctx = context.WithValue(ctx, ErrorCtxKey, err)
	return ctx
}

func FromContext(ctx context.Context) (*jwt.Token, map[string]any, error) {
	token, _ := ctx.Value(TokenCtxKey).(*jwt.Token)
	err, _ := ctx.Value(ErrorCtxKey).(error)

	claims := make(map[string]any)
	if token != nil {
		if mapClaims, ok := token.Claims.(jwt.MapClaims); ok {
			maps.Copy(claims, mapClaims)
		}
	}

	return token, claims, err
}

func TokenFromCookie(r *http.Request) string {
	cookie, err := r.Cookie("jwt")
	if err != nil {
		return ""
	}
	return cookie.Value
}

func TokenFromHeader(r *http.Request) string {
	bearer := r.Header.Get("Authorization")
	if len(bearer) > 7 && strings.ToUpper(bearer[0:7]) == "BEARER " {
		return bearer[7:]
	}
	return ""
}

func TokenFromQuery(r *http.Request) string {
	return r.URL.Query().Get("jwt")
}

type contextKey struct {
	name string
}

func (k *contextKey) String() string {
	return "jwtauth context value " + k.name
}
