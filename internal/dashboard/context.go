package dashboard

import (
	"context"

	"github.com/go-chi/chi/v5"
)

type ctxKey int

const sessionKey ctxKey = 1

func withSession(ctx context.Context, item session) context.Context {
	return context.WithValue(ctx, sessionKey, item)
}

func sessionFrom(ctx context.Context) (session, bool) {
	item, ok := ctx.Value(sessionKey).(session)
	return item, ok
}

func contextWithRoute(ctx context.Context, rctx *chi.Context) context.Context {
	return context.WithValue(ctx, chi.RouteCtxKey, rctx)
}
