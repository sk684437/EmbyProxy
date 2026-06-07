package scheduler

import (
	"context"
	"time"

	"embyproxy/internal/logging"
	"embyproxy/internal/telegram"
)

type Scheduler struct {
	log     *logging.Logger
	tg      *telegram.Service
	cleanup func()
}

func New(log *logging.Logger, tg *telegram.Service, cleanup func()) *Scheduler {
	return &Scheduler{log: log, tg: tg, cleanup: cleanup}
}

func (s *Scheduler) Start(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	go func() {
		defer ticker.Stop()
		s.log.Info("scheduler", "started", map[string]any{"event": "schedulerStarted"})
		for {
			select {
			case <-ctx.Done():
				s.log.Info("scheduler", "stopped", map[string]any{"event": "schedulerStopped"})
				return
			case <-ticker.C:
				s.tick(ctx)
			}
		}
	}()
}

func (s *Scheduler) tick(ctx context.Context) {
	s.log.Debug("scheduler", "tick", map[string]any{"event": "schedulerTick"})
	if s.cleanup != nil {
		func() {
			defer func() {
				if recover() != nil {
					s.log.Error("scheduler", "cleanup panic", map[string]any{"event": "cleanupPanic"})
				}
			}()
			s.cleanup()
		}()
	}
	if err := s.tg.CheckAndSendReport(ctx); err != nil {
		s.log.Error("scheduler", "report error", map[string]any{"event": "reportError", "error": err.Error()})
	}
	if err := s.tg.CheckKeepaliveAndNotify(ctx); err != nil {
		s.log.Error("scheduler", "keepalive error", map[string]any{"event": "keepaliveError", "error": err.Error()})
	}
}
