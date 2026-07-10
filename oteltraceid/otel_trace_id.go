package oteltraceid

import (
	"net/http"

	"go.opentelemetry.io/otel/trace"
)

// Config defines the config for TraceId middleware
type Config struct {
	traceIdHeader string
	spanIdHeader  string
}

// Option TraceId option
type Option func(*Config)

// WithTraceIdHeader optional request id header (default "X-Trace-Id")
func WithTraceIdHeader(s string) Option {
	return func(c *Config) {
		c.traceIdHeader = s
	}
}

// WithSpanIdHeader optional request id header (default "X-Span-Id")
func WithSpanIdHeader(s string) Option {
	return func(c *Config) {
		c.spanIdHeader = s
	}
}

// TraceId is a middleware that injects a trace id into the context of each
// request. if it is empty, set to write head
//   - traceIdHeader is the name of the HTTP Header which contains the trace id.
//     Exported so that it can be changed by developers. (default "X-Trace-Id")
//   - spanIdHeader is the name of the HTTP Header which contains the span id.
//     Exported so that it can be changed by developers. (default "X-Span-Id")
func TraceId(opts ...Option) func(http.Handler) http.Handler {
	cc := &Config{
		traceIdHeader: "X-Trace-Id",
		spanIdHeader:  "X-Span-Id",
	}
	for _, opt := range opts {
		opt(cc)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sc := trace.SpanContextFromContext(r.Context())
			// set response header
			w.Header().Set(cc.traceIdHeader, sc.TraceID().String())
			w.Header().Set(cc.spanIdHeader, sc.SpanID().String())
			next.ServeHTTP(w, r)
		})
	}
}
