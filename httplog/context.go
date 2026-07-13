package httplog

import (
	"context"

	"github.com/thinkgos/logger"
)

type ctxKeyLogField struct{}

func (c *ctxKeyLogField) String() string {
	return "httplog attrs context"
}

// AttachFields attaches the fields on the request log.
func AttachFields(ctx context.Context, fields ...logger.Field) {
	if ptr, ok := ctx.Value(ctxKeyLogField{}).(*[]logger.Field); ok && ptr != nil {
		*ptr = append(*ptr, fields...)
	}
}

func getFields(ctx context.Context) []logger.Field {
	if ptr, ok := ctx.Value(ctxKeyLogField{}).(*[]logger.Field); ok && ptr != nil {
		return *ptr
	}
	return nil
}

// AttachError attaches the error attribute on the request log.
func AttachError(ctx context.Context, err error) error {
	if err != nil {
		AttachFields(ctx, logger.Err(err))
	}
	return err
}
