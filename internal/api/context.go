package api

import (
	"context"
	"net/http"

	"router-policy/internal/auth"
)

type requestIDKey struct{}
type sessionKey struct{}

func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

func requestIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(requestIDKey{}).(string)
	if v == "" {
		return "unknown"
	}
	return v
}

func requestIDFromAny(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return "unknown"
}

func requestID(r *http.Request) string {
	return requestIDFromContext(r.Context())
}

func withSession(ctx context.Context, session auth.Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, session)
}

func currentSession(r *http.Request) auth.Session {
	v, _ := r.Context().Value(sessionKey{}).(auth.Session)
	return v
}
