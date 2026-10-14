package grpcapi

import (
	"context"
	"errors"
	"log/slog"
)

// renewLoginLock runs after a console Login refused with Throttling. Like
// STS (#44, #48), only a throttle by the user's own attempt limit renews
// the user's MFA device locks (mfa.RenewLock: only a running lock, capped
// at mfa.MaxLockout); a throttle by the source IP alone leaves them. The
// answer stays Throttling, and a failed renewal is only logged.
func (s *Server) renewLoginLock(ctx context.Context, p project, pid, user string) {
	ctx = context.WithoutCancel(ctx)
	if err := s.checkAttempts(ctx, callers{userSubject(pid, user)}); !errors.Is(err, errThrottled) {
		return
	}
	devices, err := p.mfa.List(ctx, user)
	if err != nil {
		slog.Default().LogAttrs(ctx, slog.LevelWarn, "mfa lock renewal on login throttle failed", slog.String("error", err.Error()))
		return
	}
	for _, d := range devices {
		if _, err := p.mfa.RenewLock(ctx, d.UserName, d.Name); err != nil {
			slog.Default().LogAttrs(ctx, slog.LevelWarn, "mfa lock renewal on login throttle failed", slog.String("error", err.Error()))
		}
	}
}
