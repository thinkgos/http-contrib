package authorize

import (
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims jwt claims
type Claims[T any] struct {
	jwt.RegisteredClaims
	Meta T `json:"meta,omitempty"`
}

// Config Auth config
type Config struct {
	// Timeout token valid time
	// if timeout <= refreshTimeout, refreshTimeout = timeout + 30 * time.Minute
	Timeout time.Duration
	// RefreshTimeout refresh token valid time.
	RefreshTimeout time.Duration
	// Lookup used to extract token from the http request
	// lookup is a string in the form of "<source>:<name>[:<prefix>]" that is used
	// to extract value from the request.
	// use like "header:<name>[:<prefix>],query:<name>,cookie:<name>,param:<name>"
	// Optional, Default value "header:Authorization:Bearer" for json web token.
	// Possible values:
	// - "header:<name>:<prefix>", <prefix> is a special string in the header, Possible value is "Bearer"
	// - "query:<name>"
	// - "cookie:<name>"
	Lookup string
	// 支持签名算法: HS256, HS384, HS512, RS256, RS384, RS512, EdDSA
	// Optional, Default HS256.
	Algorithm string
	// Secret key used for signing.
	// Required, if Algorithm is one of HS256, HS384, HS512.
	Key []byte
	// Private key for asymmetric algorithms,
	// Public key for asymmetric algorithms
	// Required, if Algorithm is one of RS256, RS384, RS512, EdDSA.
	PrivKey, PubKey string
	// the issuer of the jwt
	Issuer string
}

// Auth provides a Json-Web-Token authentication implementation.
type Auth[T any] struct {
	timeout        time.Duration
	refreshTimeout time.Duration
	lookup         *Lookup
	signingMethod  jwt.SigningMethod
	encodeKey      any
	decodeKey      any
	issuer         string
}

// New auth with Config
func New[T any](c Config) (*Auth[T], error) {
	var err error

	mw := &Auth[T]{
		timeout:        c.Timeout,
		refreshTimeout: c.RefreshTimeout,
		lookup:         NewLookup(c.Lookup),
	}
	if mw.timeout <= mw.refreshTimeout {
		mw.refreshTimeout = mw.timeout + 30*time.Minute
	}
	switch c.Algorithm {
	case "ES256", "ES384", "ES512":
		mw.encodeKey, err = parseECPrivateKey(c.PrivKey)
		if err != nil {
			return nil, ErrInvalidPrivKey
		}
		mw.decodeKey, err = parseECPublicKey(c.PubKey)
		if err != nil {
			return nil, ErrInvalidPubKey
		}
	case "RS256", "RS512", "RS384":
		mw.encodeKey, err = parseRSAPrivateKey(c.PrivKey)
		if err != nil {
			return nil, ErrInvalidPrivKey
		}
		mw.decodeKey, err = parseRSAPublicKey(c.PubKey)
		if err != nil {
			return nil, ErrInvalidPubKey
		}
	case "EdDSA":
		mw.encodeKey, err = parseEdPrivateKey(c.PrivKey)
		if err != nil {
			return nil, ErrInvalidPrivKey
		}
		mw.decodeKey, err = parseEdPublicKey(c.PubKey)
		if err != nil {
			return nil, ErrInvalidPubKey
		}
	default: // "HS256", "HS512", "HS384" or empty string
		if c.Key == nil {
			return nil, ErrMissingSecretKey
		}
		if !slices.Contains([]string{"HS256", "HS512", "HS384"}, c.Algorithm) {
			c.Algorithm = "HS256"
		}
		mw.encodeKey = c.Key
		mw.decodeKey = c.Key
	}
	mw.signingMethod = jwt.GetSigningMethod(c.Algorithm)
	return mw, nil
}

// Timeout token valid time
func (a *Auth[T]) Timeout() time.Duration { return a.timeout }

// MaxTimeout refresh timeout
func (a *Auth[T]) MaxTimeout() time.Duration { return a.refreshTimeout }

// ParseToken parse token
func (a *Auth[T]) ParseToken(tokenString string) (*Claims[T], error) {
	tk, err := jwt.ParseWithClaims(tokenString, &Claims[T]{}, func(t *jwt.Token) (any, error) {
		if a.signingMethod != t.Method {
			return nil, jwt.ErrTokenSignatureInvalid
		}
		return a.decodeKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("token parser failure, %w", err)
	}
	if !tk.Valid {
		return nil, jwt.ErrTokenNotValidYet
	}
	claims, ok := tk.Claims.(*Claims[T])
	if !ok || claims == nil {
		return nil, jwt.ErrTokenInvalidClaims
	}
	if claims.Subject == "" {
		return nil, jwt.ErrTokenNotValidYet
	}
	ts := TokenSubject{}
	err = Unmarshal(claims.Subject, &ts)
	if err != nil {
		return nil, err
	}
	if ts.ConnId != claims.ID {
		return nil, jwt.ErrTokenInvalidId
	}
	claims.Subject = ts.Sub
	return claims, nil
}

// GenerateToken generate token
func (a *Auth[T]) GenerateToken(val *Claims[T]) (string, time.Time, error) {
	return a.generateToken(val, a.timeout)
}

// GenerateRefreshToken generate refresh token
func (a *Auth[T]) GenerateRefreshToken(val *Claims[T]) (string, time.Time, error) {
	return a.generateToken(val, a.refreshTimeout)
}

// ExtractToken extract token from http request
func (a *Auth[T]) ExtractToken(r *http.Request) (string, error) {
	return a.lookup.ExtractToken(r)
}

// ParseFromRequest parse token to account from http request
func (a *Auth[T]) ParseFromRequest(r *http.Request) (*Claims[T], error) {
	token, err := a.ExtractToken(r)
	if err != nil {
		return nil, err
	}
	return a.ParseToken(token)
}

func (a *Auth[T]) generateToken(val *Claims[T], timeout time.Duration) (string, time.Time, error) {
	sub, err := Marshal(&TokenSubject{
		Sub:    val.Subject,
		ConnId: val.ID,
	})
	if err != nil {
		return "", time.Time{}, err
	}
	now := time.Now()
	expiresAt := now.Add(timeout)
	val.Issuer = a.issuer
	val.ExpiresAt = jwt.NewNumericDate(expiresAt)
	val.NotBefore = jwt.NewNumericDate(now)
	val.IssuedAt = jwt.NewNumericDate(now)
	val.Subject = sub
	token, err := jwt.NewWithClaims(a.signingMethod, val).
		SignedString(a.encodeKey)
	return token, expiresAt, err
}
