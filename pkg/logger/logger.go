package logger

import (
	"context"
	"log/slog"
	"os"
)

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
	d.l.DebugContext(ctx, msg, args...)
}

func (d DefaultLogger) InfoContext(ctx context.Context, msg string, args ...any) {
	d.l.InfoContext(ctx, msg, args...)
}

func (d DefaultLogger) WarnContext(ctx context.Context, msg string, args ...any) {
	d.l.WarnContext(ctx, msg, args...)
}

func (d DefaultLogger) ErrorContext(ctx context.Context, msg string, args ...any) {
	d.l.ErrorContext(ctx, msg, args...)
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
