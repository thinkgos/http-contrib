package authj

import (
	"net/http"

	"github.com/casbin/casbin/v3"
)

// Config for Authorizer
type Config struct {
	subject           func(*http.Request) string
	skipPermission    func(*http.Request) bool
	errFallback       func(http.ResponseWriter, *http.Request, error)
	forbiddenFallback func(http.ResponseWriter, *http.Request)
}

// Option config option
type Option func(*Config)

// WithSubject(Require) set the subject extractor of the requests.
// default: return empty subject.
func WithSubject(fn func(*http.Request) string) Option {
	return func(cfg *Config) {
		if fn != nil {
			cfg.subject = fn
		}
	}
}

// WithSkipPermission set the skip approve when it is return true.
// Default: always false
func WithSkipPermission(fn func(*http.Request) bool) Option {
	return func(cfg *Config) {
		if fn != nil {
			cfg.skipPermission = fn
		}
	}
}

// WithErrorFallback set the fallback handler when request are error happened.
// default: the 500 server error to the client
func WithErrorFallback(fn func(http.ResponseWriter, *http.Request, error)) Option {
	return func(cfg *Config) {
		if fn != nil {
			cfg.errFallback = fn
		}
	}
}

// WithForbiddenFallback set the fallback handler when request are not allow.
// default: the 403 Forbidden to the client
func WithForbiddenFallback(fn func(http.ResponseWriter, *http.Request)) Option {
	return func(cfg *Config) {
		if fn != nil {
			cfg.forbiddenFallback = fn
		}
	}
}

// Authorizer returns the authorizer
// uses a Casbin enforcer, and Subject as subject.
func Authorizer(e casbin.IEnforcer, opts ...Option) func(http.Handler) http.Handler {
	cfg := Config{
		subject:        func(r *http.Request) string { return "" },
		skipPermission: func(r *http.Request) bool { return false },
		errFallback: func(w http.ResponseWriter, r *http.Request, err error) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"code": 500, "message": "Permission validation errors occur!"}`))
		},
		forbiddenFallback: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"code": 403, "message": "Permission denied!"}`))
		},
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.skipPermission(r) {
				// checks the subject,path,method permission combination from the request.
				allowed, err := e.Enforce(cfg.subject(r), r.URL.Path, r.Method)
				if err != nil {
					cfg.errFallback(w, r, err)
					return
				}
				if !allowed {
					cfg.forbiddenFallback(w, r)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
