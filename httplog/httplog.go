package httplog

import (
	"context"
	"errors"
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

	"github.com/thinkgos/logger"
)

var ErrClientAborted = errors.New("request aborted: client disconnected before response was sent")

// Config logger/recover config
type Config struct {
	// if returns true, it will skip record logging.
	skipLogging func(r *http.Request) bool
	// enable request/response body
	enableLogBody *atomic.Bool
	// defines the maximum length of the body to be logged.
	// If not provided, the default is 4096, set <=0 mean not limit
	logBodyLimit int
	// logBodyContentType defines a list of body Content-Types that are safe to be logged
	// with RequestBody or ResponseBody.
	//
	// If not provided, the default is ["application/json", "application/xml", "text/plain", "text/csv", "application/x-www-form-urlencoded"].
	logBodyContentType []string
	// logRequestHeaders is a list of headers to be logged as attributes.
	// If not provided, the default is ["Content-Type", "Origin"].
	//
	// WARNING: Do not leak any request headers with sensitive information.
	logRequestHeaders []string
	// if returns true, it will record request body.
	logRequestBody func(r *http.Request) bool
	// logResponseHeaders controls a list of headers to be logged as attributes.
	// If not provided, the default is ["Content-Type"].
	//
	// If not provided, there are no default headers.
	logResponseHeaders []string
	// if returns true, it will record response body.
	logRecordResponseBody func(r *http.Request) bool
	// only for recovery
	stack bool
}

func logRequestBody(r *http.Request) bool {
	v := r.Header.Get("Content-Type")
	d, params, err := mime.ParseMediaType(v)
	if err != nil || (d != "multipart/form-data" && d != "multipart/mixed") {
		return true
	}
	_, ok := params["boundary"]
	return !ok
}

func logResponseBody(_r *http.Request) bool {
	// add log response body rule
	return true
}

// Logging returns a gin.HandlerFunc (middleware) that logs requests using uber-go/logger.
//
// Requests with errors are logged using logger.Error().
// Requests without errors are logged using logger.Info().
func Logging(log *logger.Log, opts ...Option) func(http.Handler) http.Handler {
	log.AddCallerSkipPackage("github.com/thinkgos/http-contrib")
	cfg := Config{
		skipLogging:           func(r *http.Request) bool { return false },
		enableLogBody:         &atomic.Bool{},
		logBodyLimit:          4096,
		logBodyContentType:    []string{"application/json", "application/xml", "text/plain", "text/csv", "application/x-www-form-urlencoded"},
		logRequestHeaders:     []string{"Content-Type", "Origin"},
		logRequestBody:        func(r *http.Request) bool { return true },
		logResponseHeaders:    []string{"Content-Type"},
		logRecordResponseBody: func(r *http.Request) bool { return true },
		stack:                 false,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r = r.WithContext(context.WithValue(r.Context(), ctxKeyLogField{}, &[]logger.Field{}))
			ww := newWrapResponseWriter(w)
			respBody := &strings.Builder{}
			reqBody := &strings.Builder{}

			hasLogRequestBody := cfg.enableLogBody.Load() && logRequestBody(r) && cfg.logRequestBody(r)
			hasLogResponseBody := cfg.enableLogBody.Load() && logResponseBody(r) && cfg.logRecordResponseBody(r)
			if hasLogRequestBody {
				r.Body = io.NopCloser(io.TeeReader(r.Body, reqBody))
			}
			if hasLogResponseBody {
				ww.Tee(respBody)
			}

			start := time.Now()
			// some evil middlewares modify this values
			path := r.URL.Path
			query := r.URL.RawQuery

			defer func() {
				// recovery
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
						HookFuncIf(cfg.stack, func(e *logger.Event) {
							e.ByteString("stack", debug.Stack())
						}).
						Msg("recovery from panic")
					w.WriteHeader(http.StatusInternalServerError)
				}

				// logging
				if cfg.skipLogging(r) {
					return
				}
				statusCode := ww.Status()
				var level = logger.InfoLevel
				switch {
				case statusCode >= http.StatusInternalServerError:
					level = logger.ErrorLevel
				case statusCode == http.StatusTooManyRequests:
					level = logger.InfoLevel
				case statusCode >= http.StatusBadRequest:
					level = logger.WarnLevel
				case r.Method == "OPTIONS":
					level = logger.DebugLevel
				}

				hasLogResponseBody := cfg.enableLogBody.Load() && logResponseBody(r) && cfg.logRecordResponseBody(r)
				log.OnLevelContext(r.Context(), level).
					Int("status", ww.Status()).
					String("method", r.Method).
					String("path", path).
					String("query", query).
					String("user-agent", r.UserAgent()).
					Duration("latency", time.Since(start)).
					HookFunc(func(e *logger.Event) {
						if len(cfg.logRequestHeaders) > 0 {
							e.Dict("request.headers", extractHeaderField(r.Header, cfg.logRequestHeaders)...)
						}
						if hasLogRequestBody {
							n, _ := io.Copy(io.Discard, r.Body)
							if n > 0 {
								e.Int64("request.unread-bytes", n)
							}
							if cfg.logBodyLimit <= 0 || reqBody.Len() <= cfg.logBodyLimit {
								e.String("request.body", reqBody.String())
							} else {
								e.String("request.body", reqBody.String()[:cfg.logBodyLimit]+"... [trimmed]")
							}
						}
						if len(cfg.logResponseHeaders) > 0 {
							e.Dict("response.headers", extractHeaderField(w.Header(), cfg.logResponseHeaders)...)
						}
						if hasLogResponseBody {
							if cfg.logBodyLimit <= 0 || reqBody.Len() <= cfg.logBodyLimit {
								e.String("response.body", respBody.String())
							} else {
								e.String("response.body", respBody.String()[:cfg.logBodyLimit]+"... [trimmed]")
							}
						}
						if err := r.Context().Err(); errors.Is(err, context.Canceled) {
							e.Error(ErrClientAborted).String("error.type", "ClientAborted")
						}
					}).
					Fields(getFields(r.Context())...).
					Msg("logging")
			}()
			next.ServeHTTP(ww, r)
		})
	}
}

type bodyWriter struct {
	http.ResponseWriter
	tee    io.Writer
	status int
}

func newWrapResponseWriter(w http.ResponseWriter) *bodyWriter {
	return &bodyWriter{ResponseWriter: w, tee: nil, status: http.StatusOK}
}

func (w *bodyWriter) Tee(tee io.Writer) { w.tee = tee }

func (w *bodyWriter) Status() int { return w.status }

func (w *bodyWriter) Write(b []byte) (int, error) {
	if w.tee != nil {
		_, _ = w.tee.Write(b)
	}
	return w.ResponseWriter.Write(b)
}
func (w *bodyWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func extractHeaderField(header http.Header, headers []string) []logger.Field {
	attrs := make([]logger.Field, 0, len(headers))
	for _, h := range headers {
		vals := header.Values(h)
		if len(vals) == 1 {
			attrs = append(attrs, logger.String(h, vals[0]))
		} else if len(vals) > 1 {
			attrs = append(attrs, logger.Any(h, vals))
		}
	}
	return attrs
}
