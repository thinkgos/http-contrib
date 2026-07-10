package authorize

import (
	"context"
)

type ctxAuthKey struct{}

// NewContext put auth info into context
func NewContext[T any](ctx context.Context, claims *Claims[T]) context.Context {
	return context.WithValue(ctx, ctxAuthKey{}, claims)
}

// FromContext extract auth info from context
func FromContext[T any](ctx context.Context) (claims *Claims[T], ok bool) {
	claims, ok = ctx.Value(ctxAuthKey{}).(*Claims[T])
	return
}
