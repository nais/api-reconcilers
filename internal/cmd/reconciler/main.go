package reconciler

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/nais/api-reconcilers/internal/logger"
	"github.com/sethvargo/go-envconfig"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

const (
	exitCodeSuccess = iota
	exitCodeLoggerError
	exitCodeRunError
	exitCodeConfigError
	exitCodeEnvFileError
)

const (
	reconcilerWorkers    = 10
	fullTeamSyncInterval = time.Minute * 30
)

func Run(ctx context.Context) {
	log := logrus.StandardLogger()

	if fileLoaded, err := loadEnvFile(); err != nil {
		log.WithError(err).Errorf("error when loading .env file")
		os.Exit(exitCodeEnvFileError)
	} else if fileLoaded {
		log.Infof("loaded .env file")
	}

	cfg, err := NewConfig(ctx, envconfig.OsLookuper())
	if err != nil {
		log.WithError(err).Errorf("error when processing configuration")
		os.Exit(exitCodeConfigError)
	}

	appLogger, err := logger.New(cfg.LogFormat, cfg.LogLevel)
	if err != nil {
		log.WithError(err).Errorf("error when creating application logger")
		os.Exit(exitCodeLoggerError)
	}

	err = run(ctx, cfg, appLogger)
	if err != nil {
		appLogger.WithError(err).Errorf("error in run()")
		os.Exit(exitCodeRunError)
	}

	os.Exit(exitCodeSuccess)
}

func run(ctx context.Context, cfg *Config, log logrus.FieldLogger) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ctx, signalStop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer signalStop()

	fullTeamSyncTimer := time.NewTimer(time.Second * 1)

	wg, ctx := errgroup.WithContext(ctx)

	// HTTP server
	wg.Go(func() error {
		return runHttpServer(ctx, cfg.ListenAddress, log)
	})

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-signals
		log.Infof("received signal %s, terminating...", sig)
		cancel()
	}()

	defer log.Info("main program context canceled; exiting.")

	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
			return nil

		case <-fullTeamSyncTimer.C:
			log.Infof("start full team sync")

			// correlationID := uuid.New()

			/*
				teams, err := teamSync.ScheduleAllTeams(ctx, correlationID)
				if err != nil {
					log.WithError(err).Errorf("full team sync")
					fullTeamSyncTimer.Reset(time.Second * 1)
					break
				}

			*/

			// log.Infof("%d teams scheduled for sync", len(teams))
			fullTeamSyncTimer.Reset(fullTeamSyncInterval)
		}
	}

	return nil
}

func loadEnvFile() (fileLoaded bool, err error) {
	if _, err = os.Stat(".env"); errors.Is(err, os.ErrNotExist) {
		return false, nil
	}

	if err = godotenv.Load(".env"); err != nil {
		return false, err
	}

	return true, nil
}
