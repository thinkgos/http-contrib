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

	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
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

// Logging returns a middleware that logs requests using zerolog.
//
// Requests with errors are logged using Error level.
// Requests without errors are logged using Info level.
//
// NOTICE: caller "file" 字段的跳过包(如本包)由调用方在 logx.CallerHook 上统一配置,
// 本函数不再修改 caller 配置.
func Logging(log zerolog.Logger, opts ...Option) func(http.Handler) http.Handler {
	opt := Config{
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
	for _, f := range opts {
		f(&opt)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			l := log.With().Logger()
			r = r.WithContext(l.WithContext(r.Context()))

			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			respBody := &strings.Builder{}
			reqBody := &strings.Builder{}

			hasLogging := !opt.skipLogging(r)
			hasLogRequestBody := hasLogging && opt.enableLogBody.Load() && logRequestBody(r) && opt.logRequestBody(r)
			hasLogResponseBody := hasLogging && opt.enableLogBody.Load() && logResponseBody(r) && opt.logRecordResponseBody(r)
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
						zerolog.Ctx(r.Context()).
							Error().
							Ctx(r.Context()).
							Func(func(e *zerolog.Event) {
								if e1, ok := err.(error); ok {
									e.AnErr("error", e1)
								} else {
									e.Interface("error", err)
								}
							}).
							Str("request", string(httpRequest)).
							Msg(r.URL.Path)
						return
					}
					zerolog.Ctx(r.Context()).
						Error().
						Ctx(r.Context()).
						Func(func(e *zerolog.Event) {
							if e1, ok := err.(error); ok {
								e.AnErr("error", e1)
							} else {
								e.Interface("error", err)
							}
							if opt.stack {
								e.Str("stack", string(debug.Stack()))
							}
						}).
						Str("request", string(httpRequest)).
						Msg("recovery from panic")
					ww.WriteHeader(http.StatusInternalServerError)
				}

				// logging
				if !hasLogging {
					return
				}
				statusCode := ww.Status()
				var level = zerolog.InfoLevel
				switch {
				case statusCode >= http.StatusInternalServerError:
					level = zerolog.ErrorLevel
				case statusCode == http.StatusTooManyRequests:
					level = zerolog.InfoLevel
				case statusCode >= http.StatusBadRequest:
					level = zerolog.WarnLevel
				case r.Method == "OPTIONS":
					level = zerolog.DebugLevel
				}

				zerolog.Ctx(r.Context()).
					WithLevel(level).
					Ctx(r.Context()).
					Int("status", ww.Status()).
					Str("method", r.Method).
					Str("path", path).
					Str("query", query).
					Str("user-agent", r.UserAgent()).
					Dur("latency", time.Since(start)).
					Func(func(e *zerolog.Event) {
						if len(opt.logRequestHeaders) > 0 {
							e.Dict("request.headers", extractHeaderField(e, r.Header, opt.logRequestHeaders))
						}
						if hasLogRequestBody {
							n, _ := io.Copy(io.Discard, r.Body)
							if n > 0 {
								e.Int64("request.unread-bytes", n)
							}
							if opt.logBodyLimit <= 0 || reqBody.Len() <= opt.logBodyLimit {
								e.Str("request.body", reqBody.String())
							} else {
								e.Str("request.body", reqBody.String()[:opt.logBodyLimit]+"... [trimmed]")
							}
						}
						if len(opt.logResponseHeaders) > 0 {
							e.Dict("response.headers", extractHeaderField(e, w.Header(), opt.logResponseHeaders))
						}
						if hasLogResponseBody {
							if opt.logBodyLimit <= 0 || ww.BytesWritten() <= opt.logBodyLimit {
								e.Str("response.body", respBody.String())
							} else {
								e.Str("response.body", respBody.String()[:opt.logBodyLimit]+"... [trimmed]")
							}
						}
						if err := r.Context().Err(); errors.Is(err, context.Canceled) {
							e.Err(ErrClientAborted).Str("error.type", "ClientAborted")
						}
					}).
					Msg("logging")
			}()
			next.ServeHTTP(ww, r)
		})
	}
}

// extractHeaderField 抽取请求/响应头为嵌套 dict 字段.
func extractHeaderField(e *zerolog.Event, header http.Header, headers []string) *zerolog.Event {
	dict := e.CreateDict()
	for _, h := range headers {
		vals := header.Values(h)
		if len(vals) == 1 {
			dict.Str(h, vals[0])
		} else if len(vals) > 1 {
			dict.Strs(h, vals)
		}
	}
	return dict
}

func Ctx(ctx context.Context) *zerolog.Logger {
	return zerolog.Ctx(ctx)
}

// AttachError attaches the error attribute on the request log.
func AttachError(ctx context.Context, err error) error {
	if err != nil {
		zerolog.Ctx(ctx).UpdateContext(func(c zerolog.Context) zerolog.Context {
			return c.AnErr("error", err)
		})
	}
	return err
}
