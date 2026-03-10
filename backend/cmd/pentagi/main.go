package main

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"pentagi/migrations"
	"pentagi/pkg/config"
	"pentagi/pkg/controller"
	"pentagi/pkg/database"
	"pentagi/pkg/docker"
	"pentagi/pkg/graph/subscriptions"
	"pentagi/pkg/notifications"
	obs "pentagi/pkg/observability"
	"pentagi/pkg/providers"
	router "pentagi/pkg/server"
	"pentagi/pkg/server/services"
	"pentagi/pkg/version"

	_ "github.com/lib/pq"
	"github.com/pressly/goose/v3"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
)

func main() {
	ctx := context.Background()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	logrus.Infof("Starting PentAGI %s", version.GetBinaryVersion())

	cfg, err := config.NewConfig()
	if err != nil {
		log.Fatalf("Unable to load config: %v\n", err)
	}

	// Configure logrus log level based on DEBUG env variable
	if cfg.Debug {
		logrus.SetLevel(logrus.DebugLevel)
		logrus.Debug("Debug logging enabled")
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	lfclient, err := obs.NewLangfuseClient(ctx, cfg)
	if err != nil && !errors.Is(err, obs.ErrNotConfigured) {
		log.Fatalf("Unable to create langfuse client: %v\n", err)
	}

	otelclient, err := obs.NewTelemetryClient(ctx, cfg)
	if err != nil && !errors.Is(err, obs.ErrNotConfigured) {
		log.Fatalf("Unable to create telemetry client: %v\n", err)
	}

	obs.InitObserver(ctx, lfclient, otelclient, []logrus.Level{
		logrus.DebugLevel,
		logrus.InfoLevel,
		logrus.WarnLevel,
		logrus.ErrorLevel,
	})

	obs.Observer.StartProcessMetricCollect(attribute.String("component", "server"))
	obs.Observer.StartGoRuntimeMetricCollect(attribute.String("component", "server"))

	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Unable to open database: %v\n", err)
	}

	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Hour)

	queries := database.New(db)

	orm, err := database.NewGorm(cfg.DatabaseURL, "postgres")
	if err != nil {
		log.Fatalf("Unable to open database with gorm: %v\n", err)
	}

	goose.SetBaseFS(migrations.EmbedMigrations)

	if err := goose.SetDialect("postgres"); err != nil {
		log.Fatalf("Unable to set dialect: %v\n", err)
	}

	if err := goose.Up(db, "sql"); err != nil {
		log.Fatalf("Unable to run migrations: %v\n", err)
	}

	log.Println("Migrations ran successfully")

	client, err := docker.NewDockerClient(ctx, queries, cfg)
	if err != nil {
		log.Fatalf("failed to initialize Docker client: %v", err)
	}

	providers, err := providers.NewProviderController(cfg, queries, client)
	if err != nil {
		log.Fatalf("failed to initialize providers: %v", err)
	}

	// Initialize optional Telegram notifications
	var notifier *notifications.NotificationManager
	if cfg.TelegramNotify && cfg.TelegramBotToken != "" && cfg.TelegramChatID != "" {
		tg := notifications.NewTelegramNotifier(cfg.TelegramBotToken, cfg.TelegramChatID)
		notifier = notifications.NewNotificationManager(tg, true, cfg.TelegramQuietTZOffset)

		// Bridge SSE events (findings, phase changes) to Telegram notifications
		lastPhases := make(map[int64]string)
		services.RegisterFlowEventHook(func(flowID int64, event services.FlowEvent) {
			switch event.EventType {
			case services.SSEEventFinding:
				if finding, ok := event.Data.(services.FindingEvent); ok {
					notifier.Notify(notifications.NotificationEvent{
						Type:            notifications.EventFindingDiscovered,
						FlowID:          flowID,
						FindingID:       finding.ID,
						Title:           finding.Title,
						FindingSeverity: notifications.MapSeverity(finding.Severity),
						FindingTarget:   finding.Target,
						FindingVulnType: finding.VulnType,
					})
				}
			case services.SSEEventPhaseChange:
				if phase, ok := event.Data.(services.PhaseChangeEvent); ok {
					oldPhase := lastPhases[flowID]
					if oldPhase != phase.Phase && phase.Phase != "" && oldPhase != "" {
						notifier.Notify(notifications.NotificationEvent{
							Type:     notifications.EventPhaseChange,
							FlowID:   flowID,
							OldPhase: oldPhase,
							NewPhase: phase.Phase,
						})
					}
					lastPhases[flowID] = phase.Phase
				}
			}
		})

		logrus.Info("Telegram notifications enabled")
	} else {
		notifier = notifications.NewNotificationManager(nil, false, 0)
		logrus.Debug("Telegram notifications disabled")
	}

	subscriptions := subscriptions.NewSubscriptionsController()
	controller := controller.NewFlowController(queries, cfg, client, providers, subscriptions, notifier)

	if err := controller.LoadFlows(ctx); err != nil {
		log.Fatalf("failed to load flows: %v", err)
	}

	r := router.NewRouter(queries, orm, cfg, providers, controller, subscriptions)

	// Run the server in a separate goroutine
	go func() {
		listen := net.JoinHostPort(cfg.ServerHost, strconv.Itoa(cfg.ServerPort))
		if cfg.ServerUseSSL && cfg.ServerSSLCrt != "" && cfg.ServerSSLKey != "" {
			err = r.RunTLS(listen, cfg.ServerSSLCrt, cfg.ServerSSLKey)
		} else {
			err = r.Run(listen)
		}
		if err != nil {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Wait for termination signal
	<-sigChan
	log.Println("Shutting down...")

	if notifier != nil {
		notifier.Close()
	}

	log.Println("Shutdown complete")
}
