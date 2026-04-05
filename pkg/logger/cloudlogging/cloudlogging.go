package cloudlogging

import (
	"context"
	"log/slog"
	"os"

	"github.com/yagihash/mini-gh-sts/pkg/logger"
)

type CloudLoggingLogger struct {
	l *slog.Logger
}

func (d CloudLoggingLogger) DebugContext(ctx context.Context, msg string, args ...any) {
	d.l.DebugContext(ctx, msg, args...)
}

func (d CloudLoggingLogger) InfoContext(ctx context.Context, msg string, args ...any) {
	d.l.InfoContext(ctx, msg, args...)
}

func (d CloudLoggingLogger) WarnContext(ctx context.Context, msg string, args ...any) {
	d.l.WarnContext(ctx, msg, args...)
}

func (d CloudLoggingLogger) ErrorContext(ctx context.Context, msg string, args ...any) {
	d.l.ErrorContext(ctx, msg, args...)
}

func (d CloudLoggingLogger) With(args ...any) logger.Logger {
	return &CloudLoggingLogger{d.l.With(args...)}
}

func New(debug bool) logger.Logger {
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			switch {
			case attr.Key == slog.MessageKey:
				return slog.String("message", attr.Value.String())
			case attr.Key == slog.LevelKey && attr.Value.String() == slog.LevelWarn.String():
				return slog.String("severity", "WARNING")
			case attr.Key == slog.LevelKey:
				return slog.String("severity", attr.Value.String())
			}
			return attr
		},
	}

	if debug {
		opts.Level = slog.LevelDebug
	}

	l := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	return &CloudLoggingLogger{l}
}
