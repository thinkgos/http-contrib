package authorize

import (
	"net/http"
)

// Option is Middleware option.
type Option func(*options)

// options is a Middleware option
type options struct {
	skip                  func(*http.Request) bool
	afterAuthorizeSuccess func(*http.Request) error
	unauthorizedFallback  func(http.ResponseWriter, *http.Request, error)
}

// WithSkip set skip func
func WithSkip(f func(*http.Request) bool) Option {
	return func(o *options) {
		if f != nil {
			o.skip = f
		}
	}
}

// WithAfterAuthorizeSuccess set after authorize success func
func WithAfterAuthorizeSuccess(f func(*http.Request) error) Option {
	return func(o *options) {
		if f != nil {
			o.afterAuthorizeSuccess = f
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
	opt := &options{
		skip:                  func(*http.Request) bool { return false },
		afterAuthorizeSuccess: func(*http.Request) error { return nil },
		unauthorizedFallback: func(w http.ResponseWriter, r *http.Request, err error) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(err.Error()))
		},
	}
	for _, f := range opts {
		f(opt)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !opt.skip(r) {
				acc, err := a.ParseFromRequest(r)
				if err != nil {
					opt.unauthorizedFallback(w, r, err)
					return
				}
				r = r.WithContext(NewContext(r.Context(), acc))
				err = opt.afterAuthorizeSuccess(r)
				if err != nil {
					opt.unauthorizedFallback(w, r, err)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
