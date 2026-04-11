package logger

import (
	"context"
	"log/slog"
	"os"
)

type contextKey struct{}

// WithRequestID stores a request ID in the context.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

// RequestIDFromContext retrieves the request ID from the context.
func RequestIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(contextKey{}).(string)
	return id, ok
}

// WithRequestIDArgs prepends "request_id", id to args if a request ID is present in ctx.
func WithRequestIDArgs(ctx context.Context, args []any) []any {
	if id, ok := RequestIDFromContext(ctx); ok {
		return append([]any{"request_id", id}, args...)
	}
	return args
}

type Logger interface {
	DebugContext(ctx context.Context, msg string, args ...any)
	InfoContext(ctx context.Context, msg string, args ...any)
	WarnContext(ctx context.Context, msg string, args ...any)
	ErrorContext(ctx context.Context, msg string, args ...any)

	With(args ...any) Logger
}

type DefaultLogger struct {
	l *slog.Logger
}

func (d DefaultLogger) DebugContext(ctx context.Context, msg string, args ...any) {
	d.l.DebugContext(ctx, msg, WithRequestIDArgs(ctx, args)...)
}

func (d DefaultLogger) InfoContext(ctx context.Context, msg string, args ...any) {
	d.l.InfoContext(ctx, msg, WithRequestIDArgs(ctx, args)...)
}

func (d DefaultLogger) WarnContext(ctx context.Context, msg string, args ...any) {
	d.l.WarnContext(ctx, msg, WithRequestIDArgs(ctx, args)...)
}

func (d DefaultLogger) ErrorContext(ctx context.Context, msg string, args ...any) {
	d.l.ErrorContext(ctx, msg, WithRequestIDArgs(ctx, args)...)
}

func (d DefaultLogger) With(args ...any) Logger {
	return &DefaultLogger{d.l.With(args...)}
}

func New(debug bool) Logger {
	opts := &slog.HandlerOptions{}
	if debug {
		opts.Level = slog.LevelDebug
	}

	l := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	return &DefaultLogger{l}
}
