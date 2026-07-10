package hlog

import (
	"bytes"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"github.com/thinkgos/httpcurl"
	"github.com/thinkgos/logger"
)

// Option logger/recover option
type Option func(c *Config)

// WithCustomFields optional custom field
func WithCustomFields(fields ...func(w http.ResponseWriter, r *http.Request) logger.Field) Option {
	return func(c *Config) {
		c.customFields = fields
	}
}

// WithSkipLogging optional custom skip logging option.
func WithSkipLogging(f func(w http.ResponseWriter, r *http.Request) bool) Option {
	return func(c *Config) {
		if f != nil {
			c.skipLogging = f
		}
	}
}

// WithEnableBody optional custom enable request/response body.
func WithEnableBody(b bool) Option {
	return func(c *Config) {
		c.enableBody.Store(b)
	}
}

// WithExternalEnableBody optional custom enable request/response body control by external itself.
func WithExternalEnableBody(b *atomic.Bool) Option {
	return func(c *Config) {
		if b != nil {
			c.enableBody = b
		}
	}
}

// WithBodyLimit optional custom request/response body limit.
// default: <=0, mean not limit
func WithBodyLimit(limit int) Option {
	return func(c *Config) {
		c.limit = limit
	}
}

// WithSkipRequestBody optional custom skip request body logging option.
func WithSkipRequestBody(f func(w http.ResponseWriter, r *http.Request) bool) Option {
	return func(c *Config) {
		if f != nil {
			c.skipRequestBody = f
		}
	}
}

// WithSkipResponseBody optional custom skip response body logging option.
func WithSkipResponseBody(f func(w http.ResponseWriter, r *http.Request) bool) Option {
	return func(c *Config) {
		if f != nil {
			c.skipResponseBody = f
		}
	}
}

// WithUseLoggerLevel optional use logging level.
func WithUseLoggerLevel(f func(w http.ResponseWriter, r *http.Request, statusCode int) logger.Level) Option {
	return func(c *Config) {
		if f != nil {
			c.useLoggerLevel = f
		}
	}
}

func WithEnableDebugCurl(b bool) Option {
	return func(c *Config) {
		if b {
			c.debugCurl = httpcurl.New()
		} else {
			c.debugCurl = nil
		}
	}
}

// Config logger/recover config
type Config struct {
	customFields []func(w http.ResponseWriter, r *http.Request) logger.Field
	// if returns true, it will skip logging.
	skipLogging func(w http.ResponseWriter, r *http.Request) bool
	// if returns true, it will skip request body.
	skipRequestBody func(w http.ResponseWriter, r *http.Request) bool
	// if returns true, it will skip response body.
	skipResponseBody func(w http.ResponseWriter, r *http.Request) bool
	// use logger level,
	// default:
	// 	logger.ErrorLevel: when status >= http.StatusInternalServerError && status <= http.StatusNetworkAuthenticationRequired
	// 	logger.WarnLevel: when status >= http.StatusBadRequest && status <= http.StatusUnavailableForLegalReasons
	//  logger.InfoLevel: otherwise.
	useLoggerLevel func(w http.ResponseWriter, r *http.Request, statusCode int) logger.Level
	enableBody     *atomic.Bool       // enable request/response body
	limit          int                // <=0: mean not limit
	debugCurl      *httpcurl.HttpCurl // debug curl
}

func skipRequestBody(w http.ResponseWriter, r *http.Request) bool {
	v := r.Header.Get("Content-Type")
	d, params, err := mime.ParseMediaType(v)
	if err != nil || (d != "multipart/form-data" && d != "multipart/mixed") {
		return false
	}
	_, ok := params["boundary"]
	return ok
}

func skipResponseBody(w http.ResponseWriter, r *http.Request) bool {
	// TODO: add skip response body rule
	return false
}

func useLoggerLevel(w http.ResponseWriter, r *http.Request, statusCode int) logger.Level {
	if statusCode >= http.StatusInternalServerError &&
		statusCode <= http.StatusNetworkAuthenticationRequired {
		return logger.ErrorLevel
	}
	if statusCode >= http.StatusBadRequest &&
		statusCode <= http.StatusUnavailableForLegalReasons &&
		statusCode != http.StatusUnauthorized {
		return logger.WarnLevel
	}
	return logger.InfoLevel
}

func newConfig() Config {
	return Config{
		skipLogging:      func(w http.ResponseWriter, r *http.Request) bool { return false },
		skipRequestBody:  func(w http.ResponseWriter, r *http.Request) bool { return false },
		skipResponseBody: func(w http.ResponseWriter, r *http.Request) bool { return false },
		useLoggerLevel:   useLoggerLevel,
		enableBody:       &atomic.Bool{},
		limit:            0,
	}
}

// Logging returns a gin.HandlerFunc (middleware) that logs requests using uber-go/logger.
//
// Requests with errors are logged using logger.Error().
// Requests without errors are logged using logger.Info().
func Logging(log *logger.Log, opts ...Option) func(http.Handler) http.Handler {
	log.AddCallerSkipPackage("github.com/thinkgos/gin-contrib")
	cfg := newConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.skipLogging(w, r) {
				next.ServeHTTP(w, r)
				return
			}
			respBodyBuilder := &strings.Builder{}
			reqBody := "skip request body"
			debugCurl := ""
			hasSkipRequestBody := skipRequestBody(w, r) || cfg.skipRequestBody(w, r)
			wrapWriter := &bodyWriter{ResponseWriter: w, dupBody: nil}
			w = wrapWriter

			if cfg.enableBody.Load() {
				wrapWriter.dupBody = respBodyBuilder
				if !hasSkipRequestBody {
					reqBodyBuf, err := io.ReadAll(r.Body)
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						_, _ = w.Write([]byte(err.Error()))
						return
					}
					r.Body.Close() // nolint: errcheck
					r.Body = io.NopCloser(bytes.NewBuffer(reqBodyBuf))
					if cfg.limit > 0 && len(reqBodyBuf) >= cfg.limit {
						reqBody = "larger request body"
					} else {
						reqBody = string(reqBodyBuf)
					}
				}
			}
			if !hasSkipRequestBody && cfg.debugCurl != nil {
				debugCurl, _ = cfg.debugCurl.IntoCurl(r)
			}

			start := time.Now()
			// some evil middlewares modify this values
			path := r.URL.Path
			query := r.URL.RawQuery

			defer func() {
				level := cfg.useLoggerLevel(w, r, wrapWriter.Status())
				log.OnLevelContext(r.Context(), level).
					Int("status", wrapWriter.Status()).
					String("method", r.Method).
					String("path", path).
					// String("route", c.FullPath()).
					String("query", query).
					// String("ip", c.ClientIP()).
					String("user-agent", r.UserAgent()).
					Duration("latency", time.Since(start)).
					HookFunc(func(e *logger.Event) {
						if cfg.enableBody.Load() {
							respBody := "skip response body"
							// response body must inspect here, because we know only after write response body.
							if hasSkipResponseBody := skipResponseBody(w, r) || cfg.skipResponseBody(w, r); !hasSkipResponseBody {
								if cfg.limit > 0 && respBodyBuilder.Len() >= cfg.limit {
									respBody = "larger response body"
								} else {
									respBody = respBodyBuilder.String()
								}
							}
							e.String("requestBody", reqBody).
								String("responseBody", respBody)
						}
						for _, fieldFunc := range cfg.customFields {
							e.Fields(fieldFunc(w, r))
						}
						if debugCurl != "" {
							e.String("curl", debugCurl)
						}
					}).
					Msg("logging")
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// Recovery returns a gin.HandlerFunc (middleware)
// that recovers from any panics and logs requests using uber-go/logger.
// All errors are logged using logger.Error().
// stack means whether output the stack info.
// The stack info is easy to find where the error occurs but the stack info is too large.
func Recovery(log *logger.Log, stack bool, opts ...Option) func(http.Handler) http.Handler {
	cfg := newConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					// Check for a broken connection, as it is not really a
					// condition that warrants a panic stack trace.
					var brokenPipe bool
					if ne, ok := err.(*net.OpError); ok {
						if se, ok := ne.Err.(*os.SyscallError); ok {
							if strings.Contains(strings.ToLower(se.Error()), "broken pipe") ||
								strings.Contains(strings.ToLower(se.Error()), "connection reset by peer") {
								brokenPipe = true
							}
						}
					}

					httpRequest, _ := httputil.DumpRequest(r, false)
					if brokenPipe {
						log.OnErrorContext(r.Context()).
							Any("error", err).
							ByteString("request", httpRequest).
							Msg(r.URL.Path)
						return
					}
					log.OnErrorContext(r.Context()).
						Any("error", err).
						ByteString("request", httpRequest).
						HookFunc(func(e *logger.Event) {
							for _, fieldFunc := range cfg.customFields {
								e.Fields(fieldFunc(w, r))
							}
							if stack {
								e.ByteString("stack", debug.Stack())
							}
						}).
						Msg("recovery from panic")
					w.WriteHeader(http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

type bodyWriter struct {
	http.ResponseWriter
	dupBody *strings.Builder
	code    int
}

func (w *bodyWriter) Write(b []byte) (int, error) {
	if w.dupBody != nil {
		w.dupBody.Write(b)
	}
	return w.ResponseWriter.Write(b)
}
func (w *bodyWriter) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}
func (w *bodyWriter) Status() int {
	return w.code
}
