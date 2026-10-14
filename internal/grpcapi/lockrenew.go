package grpcapi

import (
	"context"
	"log/slog"

	"github.com/popododo0720/vws-iam/internal/iam"
)

// renewLoginLock runs after a console Login refused with Throttling. Like
// STS (#44, #48), only a throttle by the user's own attempt limit renews
// the user's MFA device locks (mfa.RenewLock: only a running lock, capped
// at mfa.MaxLockout); a throttle by the source IP alone leaves them. The
// answer stays Throttling, and a failed renewal is only logged.
func renewLoginLock(ctx context.Context, p project, user string, err error) {
	if !throttledBy(err, iam.AttemptUser) {
		return
	}
	ctx = context.WithoutCancel(ctx)
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
