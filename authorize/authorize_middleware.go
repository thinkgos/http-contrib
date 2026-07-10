package authorize

import (
	"net/http"
)

// Option is Middleware option.
type Option func(*options)

// options is a Middleware option
type options struct {
	skip                 func(http.ResponseWriter, *http.Request) bool
	unauthorizedFallback func(http.ResponseWriter, *http.Request, error)
}

// WithSkip set skip func
func WithSkip(f func(http.ResponseWriter, *http.Request) bool) Option {
	return func(o *options) {
		if f != nil {
			o.skip = f
		}
	}
}

// WithUnauthorizedFallback sets the fallback handler when requests are unauthorized.
func WithUnauthorizedFallback(f func(http.ResponseWriter, *http.Request, error)) Option {
	return func(o *options) {
		if f != nil {
			o.unauthorizedFallback = f
		}
	}
}

func (a *Auth[T]) Middleware(opts ...Option) func(next http.Handler) http.Handler {
	o := &options{
		unauthorizedFallback: func(w http.ResponseWriter, r *http.Request, err error) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(err.Error()))
		},
		skip: func(http.ResponseWriter, *http.Request) bool { return false },
	}
	for _, opt := range opts {
		opt(o)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !o.skip(w, r) {
				acc, err := a.ParseFromRequest(r)
				if err != nil {
					o.unauthorizedFallback(w, r, err)
					return
				}
				r = r.WithContext(NewContext(r.Context(), acc))
			}
			next.ServeHTTP(w, r)
		})
	}
}
