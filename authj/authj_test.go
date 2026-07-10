package authj

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/casbin/casbin/v3"
)

// http mux
// https://go.dev/blog/routing-enhancements

// contextKey is a value for use with context.WithValue. It's used as
// a pointer, so it fits in an interface{} without allocation.
type ctxAuthKey struct{}

// Subject returns the value associated with this context for subjectCtxKey,
func Subject(w http.ResponseWriter, r *http.Request) string {
	val, _ := r.Context().Value(ctxAuthKey{}).(string)
	return val
}

// WithValueSubject return a copy of parent in which the value associated with
// subjectCtxKey is subject.
func WithValueSubject(ctx context.Context, subject string) context.Context {
	return context.WithValue(ctx, ctxAuthKey{}, subject)
}

type Middleware func(http.Handler) http.Handler

type Pipeline struct {
	middlewares []Middleware
}

func NewPipeline(ms ...Middleware) Pipeline {
	return Pipeline{middlewares: ms}
}
func (p Pipeline) Handle(final http.Handler) http.Handler {
	if len(p.middlewares) == 0 {
		return final
	}
	handle := final
	for i := len(p.middlewares) - 1; i >= 0; i-- {
		handle = p.middlewares[i](handle)
	}
	return handle
}

func (p Pipeline) HandleFunc(final http.HandlerFunc) http.Handler {
	return p.Handle(http.HandlerFunc(final))
}

func ContextSubject(subject string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r = r.WithContext(WithValueSubject(r.Context(), subject))
			next.ServeHTTP(w, r)
		})
	}
}

func Success(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func testAuthjRequest(t *testing.T, router http.Handler, user, path, method string, code int) {
	r, _ := http.NewRequestWithContext(context.TODO(), method, path, http.NoBody)
	r.SetBasicAuth(user, "123")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	if w.Code != code {
		t.Errorf("%s, %s, %s: %d, supposed to be %d", user, path, method, w.Code, code)
	}
}

func TestBasic(t *testing.T) {
	e, _ := casbin.NewEnforcer("authj_model.conf", "authj_policy.csv")

	mux := http.NewServeMux()
	mux.Handle("/{path...}",
		NewPipeline(ContextSubject("alice"), Authorizer(e, WithSubject(Subject))).HandleFunc(Success),
	)

	testAuthjRequest(t, mux, "alice", "/dataset1/resource1", "GET", 200)
	testAuthjRequest(t, mux, "alice", "/dataset1/resource1", "POST", 200)
	testAuthjRequest(t, mux, "alice", "/dataset1/resource2", "GET", 200)
	testAuthjRequest(t, mux, "alice", "/dataset1/resource2", "POST", 403)
}

func TestPathWildcard(t *testing.T) {
	e, _ := casbin.NewEnforcer("authj_model.conf", "authj_policy.csv")

	mux := http.NewServeMux()
	mux.Handle("/{path...}",
		NewPipeline(ContextSubject("bob"), Authorizer(e, WithSubject(Subject))).HandleFunc(Success),
	)

	testAuthjRequest(t, mux, "bob", "/dataset2/resource1", "GET", 200)
	testAuthjRequest(t, mux, "bob", "/dataset2/resource1", "POST", 200)
	testAuthjRequest(t, mux, "bob", "/dataset2/resource1", "DELETE", 200)
	testAuthjRequest(t, mux, "bob", "/dataset2/resource2", "GET", 200)
	testAuthjRequest(t, mux, "bob", "/dataset2/resource2", "POST", 403)
	testAuthjRequest(t, mux, "bob", "/dataset2/resource2", "DELETE", 403)

	testAuthjRequest(t, mux, "bob", "/dataset2/folder1/item1", "GET", 403)
	testAuthjRequest(t, mux, "bob", "/dataset2/folder1/item1", "POST", 200)
	testAuthjRequest(t, mux, "bob", "/dataset2/folder1/item1", "DELETE", 403)
	testAuthjRequest(t, mux, "bob", "/dataset2/folder1/item2", "GET", 403)
	testAuthjRequest(t, mux, "bob", "/dataset2/folder1/item2", "POST", 200)
	testAuthjRequest(t, mux, "bob", "/dataset2/folder1/item2", "DELETE", 403)
}

func TestRBAC(t *testing.T) {
	e, _ := casbin.NewEnforcer("authj_model.conf", "authj_policy.csv")

	mux := http.NewServeMux()
	mux.Handle("/{path...}",
		NewPipeline(
			ContextSubject("cathy"),
			Authorizer(e,
				WithSubject(Subject),
				WithErrorFallback(func(w http.ResponseWriter, r *http.Request, err error) {

					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(`{"code": 500, "message": "Permission validation errors occur!"}`))
				}),
				WithForbiddenFallback(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusForbidden)
					w.Write([]byte(`{"code": 403, "message": "Permission denied!"}`))
				}),
			),
		).HandleFunc(Success),
	)

	// cathy can access all /dataset1/* resources via all methods because it has the dataset1_admin role.
	testAuthjRequest(t, mux, "cathy", "/dataset1/item", "GET", 200)
	testAuthjRequest(t, mux, "cathy", "/dataset1/item", "POST", 200)
	testAuthjRequest(t, mux, "cathy", "/dataset1/item", "DELETE", 200)
	testAuthjRequest(t, mux, "cathy", "/dataset2/item", "GET", 403)
	testAuthjRequest(t, mux, "cathy", "/dataset2/item", "POST", 403)
	testAuthjRequest(t, mux, "cathy", "/dataset2/item", "DELETE", 403)

	// delete all roles on user cathy, so cathy cannot access any resources now.
	_, _ = e.DeleteRolesForUser("cathy")

	testAuthjRequest(t, mux, "cathy", "/dataset1/item", "GET", 403)
	testAuthjRequest(t, mux, "cathy", "/dataset1/item", "POST", 403)
	testAuthjRequest(t, mux, "cathy", "/dataset1/item", "DELETE", 403)
	testAuthjRequest(t, mux, "cathy", "/dataset2/item", "GET", 403)
	testAuthjRequest(t, mux, "cathy", "/dataset2/item", "POST", 403)
	testAuthjRequest(t, mux, "cathy", "/dataset2/item", "DELETE", 403)
}

func TestSkipAuthentication(t *testing.T) {
	e, _ := casbin.NewEnforcer("authj_model.conf", "authj_policy.csv")

	mux := http.NewServeMux()
	mux.Handle("/{path...}",
		NewPipeline(
			ContextSubject("cathy"),
			Authorizer(e,
				WithSubject(Subject),
				WithErrorFallback(func(w http.ResponseWriter, r *http.Request, err error) {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(`{"code": 500, "message": "Permission validation errors occur!"}`))
				}),
				WithForbiddenFallback(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusForbidden)
					w.Write([]byte(`{"code": 403, "message": "Permission denied!"}`))
				}),
				WithSkipAuthentication(func(w http.ResponseWriter, r *http.Request) bool {
					return r.Method == http.MethodGet && r.URL.Path == "/skip/authentication"
				}),
			),
		).HandleFunc(Success),
	)

	// skip authentication
	testAuthjRequest(t, mux, "cathy", "/skip/authentication", "GET", 200)
	testAuthjRequest(t, mux, "cathy", "/skip/authentication", "POST", 403)

	// cathy can access all /dataset1/* resources via all methods because it has the dataset1_admin role.
	testAuthjRequest(t, mux, "cathy", "/dataset1/item", "GET", 200)
	testAuthjRequest(t, mux, "cathy", "/dataset1/item", "POST", 200)
	testAuthjRequest(t, mux, "cathy", "/dataset1/item", "DELETE", 200)
	testAuthjRequest(t, mux, "cathy", "/dataset2/item", "GET", 403)
	testAuthjRequest(t, mux, "cathy", "/dataset2/item", "POST", 403)
	testAuthjRequest(t, mux, "cathy", "/dataset2/item", "DELETE", 403)

	// delete all roles on user cathy, so cathy cannot access any resources now.
	_, _ = e.DeleteRolesForUser("cathy")

	testAuthjRequest(t, mux, "cathy", "/dataset1/item", "GET", 403)
	testAuthjRequest(t, mux, "cathy", "/dataset1/item", "POST", 403)
	testAuthjRequest(t, mux, "cathy", "/dataset1/item", "DELETE", 403)
	testAuthjRequest(t, mux, "cathy", "/dataset2/item", "GET", 403)
	testAuthjRequest(t, mux, "cathy", "/dataset2/item", "POST", 403)
	testAuthjRequest(t, mux, "cathy", "/dataset2/item", "DELETE", 403)
}
