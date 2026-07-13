package httplog

import (
	"net/http"
	"sync/atomic"
)

// Option logger/recover option
type Option func(c *Config)

// WithSkipLogging optional custom skip logging option.
func WithSkipLogging(f func(r *http.Request) bool) Option {
	return func(c *Config) {
		if f != nil {
			c.skipLogging = f
		}
	}
}

// WithEnableLogBody optional custom enable request/response body.
func WithEnableLogBody(b bool) Option {
	return func(c *Config) {
		c.enableLogBody.Store(b)
	}
}

// WithExternalEnableLogBody optional custom enable request/response body control by external itself.
func WithExternalEnableLogBody(b *atomic.Bool) Option {
	return func(c *Config) {
		if b != nil {
			c.enableLogBody = b
		}
	}
}

// WithLogBodyLimit defines a list of body Content-Types that are safe to be logged.
// default: 4096, if <=0, mean not limit
func WithLogBodyLimit(limit int) Option {
	return func(c *Config) {
		c.logBodyLimit = limit
	}
}

// WithLogBodyContentType optional custom record body content types.
func WithLogBodyContentType(contentTypes []string) Option {
	return func(c *Config) {
		c.logBodyContentType = contentTypes
	}
}

// WithLogRequestHeaders optional custom record request headers.
func WithLogRequestHeaders(headers []string) Option {
	return func(c *Config) {
		c.logRequestHeaders = headers
	}
}

// WithLogRecordRequestBody optional custom skip request body logging option.
func WithLogRecordRequestBody(f func(r *http.Request) bool) Option {
	return func(c *Config) {
		if f != nil {
			c.logRequestBody = f
		}
	}
}

// WithLogResponseHeaders optional custom record response headers.
func WithLogResponseHeaders(headers []string) Option {
	return func(c *Config) {
		c.logResponseHeaders = headers
	}
}

// WithLogResponseBody optional custom skip response body logging option.
func WithLogResponseBody(f func(r *http.Request) bool) Option {
	return func(c *Config) {
		if f != nil {
			c.logRecordResponseBody = f
		}
	}
}
