package controller

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"pentagi/pkg/config"
	"pentagi/pkg/database"
	"pentagi/pkg/docker"
	"pentagi/pkg/graph/subscriptions"
	"pentagi/pkg/masteragent"
	"pentagi/pkg/notifications"
	"pentagi/pkg/providers"
	"pentagi/pkg/providers/provider"
	"pentagi/pkg/tools"

	"github.com/sirupsen/logrus"
)

var (
	ErrFlowNotFound       = fmt.Errorf("flow not found")
	ErrFlowAlreadyStopped = fmt.Errorf("flow already stopped")
)

type FlowController interface {
	CreateFlow(
		ctx context.Context,
		userID int64,
		input string,
		prvname provider.ProviderName,
		prvtype provider.ProviderType,
		functions *tools.Functions,
	) (FlowWorker, error)
	CreateAssistant(
		ctx context.Context,
		userID int64,
		flowID int64,
		input string,
		useAgents bool,
		prvname provider.ProviderName,
		prvtype provider.ProviderType,
		functions *tools.Functions,
	) (AssistantWorker, error)
	ResumeFlow(ctx context.Context, flowID int64, input string) (FlowWorker, error)
	LoadFlows(ctx context.Context) error
	ListFlows(ctx context.Context) []FlowWorker
	GetFlow(ctx context.Context, flowID int64) (FlowWorker, error)
	StopFlow(ctx context.Context, flowID int64) error
	FinishFlow(ctx context.Context, flowID int64) error
	RenameFlow(ctx context.Context, flowID int64, title string) error
	GetFlowControlManager() FlowControlManager
	GetNotificationManager() *notifications.NotificationManager
}

type flowController struct {
	db              database.Querier
	mx              *sync.Mutex
	cfg             *config.Config
	flows           map[int64]FlowWorker
	docker          docker.DockerClient
	provs           providers.ProviderController
	subs            subscriptions.SubscriptionsController
	flowControl     FlowControlManager
	notifier        *notifications.NotificationManager
	masterSupervisor *masteragent.Supervisor
	alc             AgentLogController
	mlc             MsgLogController
	aslc            AssistantLogController
	slc             SearchLogController
	tlc             TermLogController
	vslc            VectorStoreLogController
	sc              ScreenshotController
}

func NewFlowController(
	db database.Querier,
	cfg *config.Config,
	docker docker.DockerClient,
	provs providers.ProviderController,
	subs subscriptions.SubscriptionsController,
	notifier *notifications.NotificationManager,
) FlowController {
	flowCtrl := NewFlowControlManager()

	// Initialize Master Agent supervisor if enabled
	var maSupervisor *masteragent.Supervisor
	if cfg.MasterAgentEnabled {
		maCfg := masteragent.MasterAgentConfig{
			Enabled:            true,
			Interval:           time.Duration(cfg.MasterAgentInterval) * time.Second,
			Model:              cfg.MasterAgentModel,
			AnthropicAPIKey:    cfg.AnthropicAPIKey,
			AnthropicServerURL: cfg.AnthropicServerURL,
			TelegramBotToken:   cfg.TelegramBotToken,
			TelegramChatID:     cfg.TelegramChatID,
		}
		maSupervisor = masteragent.NewSupervisor(cfg, maCfg, db, NewFlowControlMasterAgentAdapter(flowCtrl), notifier)
		logrus.WithFields(logrus.Fields{
			"interval": maCfg.Interval.String(),
			"model":    maCfg.Model,
		}).Info("master agent supervisor initialized")
	}

	return &flowController{
		db:               db,
		mx:               &sync.Mutex{},
		cfg:              cfg,
		flows:            make(map[int64]FlowWorker),
		docker:           docker,
		provs:            provs,
		subs:             subs,
		flowControl:      flowCtrl,
		notifier:         notifier,
		masterSupervisor: maSupervisor,
		alc:              NewAgentLogController(db),
		mlc:              NewMsgLogController(db),
		aslc:             NewAssistantLogController(db),
		slc:              NewSearchLogController(db),
		tlc:              NewTermLogController(db),
		vslc:             NewVectorStoreLogController(db),
		sc:               NewScreenshotController(db),
	}
}

func (fc *flowController) GetFlowControlManager() FlowControlManager {
	return fc.flowControl
}

func (fc *flowController) GetNotificationManager() *notifications.NotificationManager {
	return fc.notifier
}

func (fc *flowController) LoadFlows(ctx context.Context) error {
	flows, err := fc.db.GetFlows(ctx)
	if err != nil {
		return fmt.Errorf("failed to load flows: %w", err)
	}

	for _, flow := range flows {
		fw, err := LoadFlowWorker(ctx, flow, flowWorkerCtx{
			db:          fc.db,
			cfg:         fc.cfg,
			docker:      fc.docker,
			provs:       fc.provs,
			subs:        fc.subs,
			flowControl: fc.flowControl,
			notifier:    fc.notifier,
			flowProviderControllers: flowProviderControllers{
				mlc:  fc.mlc,
				aslc: fc.aslc,
				alc:  fc.alc,
				slc:  fc.slc,
				tlc:  fc.tlc,
				vslc: fc.vslc,
				sc:   fc.sc,
			},
		})
		if err != nil {
			if errors.Is(err, ErrNothingToLoad) {
				continue
			}

			logrus.WithContext(ctx).WithError(err).Errorf("failed to load flow %d", flow.ID)
			continue
		}

		fc.flows[flow.ID] = fw

		// Start Master Agent for running flows
		if fc.masterSupervisor != nil && (flow.Status == database.FlowStatusRunning || flow.Status == database.FlowStatusWaiting) {
			fc.masterSupervisor.StartForFlow(flow.ID)
		}
	}

	return nil
}

func (fc *flowController) CreateFlow(
	ctx context.Context,
	userID int64,
	input string,
	prvname provider.ProviderName,
	prvtype provider.ProviderType,
	functions *tools.Functions,
) (FlowWorker, error) {
	fc.mx.Lock()
	defer fc.mx.Unlock()

	fw, err := NewFlowWorker(ctx, newFlowWorkerCtx{
		userID:    userID,
		input:     input,
		prvname:   prvname,
		prvtype:   prvtype,
		functions: functions,
		flowWorkerCtx: flowWorkerCtx{
			db:          fc.db,
			cfg:         fc.cfg,
			docker:      fc.docker,
			provs:       fc.provs,
			subs:        fc.subs,
			flowControl: fc.flowControl,
			notifier:    fc.notifier,
			flowProviderControllers: flowProviderControllers{
				mlc:  fc.mlc,
				aslc: fc.aslc,
				alc:  fc.alc,
				slc:  fc.slc,
				tlc:  fc.tlc,
				vslc: fc.vslc,
				sc:   fc.sc,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create flow worker: %w", err)
	}

	fc.flows[fw.GetFlowID()] = fw

	// Start Master Agent for this flow
	if fc.masterSupervisor != nil {
		fc.masterSupervisor.StartForFlow(fw.GetFlowID())
	}

	return fw, nil
}

func (fc *flowController) CreateAssistant(
	ctx context.Context,
	userID int64,
	flowID int64,
	input string,
	useAgents bool,
	prvname provider.ProviderName,
	prvtype provider.ProviderType,
	functions *tools.Functions,
) (AssistantWorker, error) {
	fc.mx.Lock()
	defer fc.mx.Unlock()

	var (
		fw  FlowWorker
		ok  bool
		err error
	)

	flowWorkerCtx := flowWorkerCtx{
		db:          fc.db,
		cfg:         fc.cfg,
		docker:      fc.docker,
		provs:       fc.provs,
		subs:        fc.subs,
		flowControl: fc.flowControl,
		notifier:    fc.notifier,
		flowProviderControllers: flowProviderControllers{
			mlc:  fc.mlc,
			aslc: fc.aslc,
			alc:  fc.alc,
			slc:  fc.slc,
			tlc:  fc.tlc,
			vslc: fc.vslc,
			sc:   fc.sc,
		},
	}

	newFlow := func() error {
		fw, err = NewFlowWorker(ctx, newFlowWorkerCtx{
			userID:        userID,
			input:         input,
			dryRun:        true,
			prvname:       prvname,
			prvtype:       prvtype,
			functions:     functions,
			flowWorkerCtx: flowWorkerCtx,
		})
		if err != nil {
			return fmt.Errorf("failed to create flow worker: %w", err)
		}

		fc.flows[fw.GetFlowID()] = fw
		flowID = fw.GetFlowID()
		fw.SetStatus(ctx, database.FlowStatusWaiting)

		return nil
	}

	loadFlow := func() error {
		flow, err := fc.db.UpdateFlowStatus(ctx, database.UpdateFlowStatusParams{
			ID:     flowID,
			Status: database.FlowStatusWaiting,
		})
		if err != nil {
			return fmt.Errorf("failed to renew flow %d status: %w", flowID, err)
		}

		fw, err = LoadFlowWorker(ctx, flow, flowWorkerCtx)
		if err != nil {
			return fmt.Errorf("failed to load flow %d: %w", flowID, err)
		}

		fc.flows[flowID] = fw

		return nil
	}

	if flowID == 0 {
		if err := newFlow(); err != nil {
			return nil, err
		}
	} else if fw, ok = fc.flows[flowID]; ok {
		status, err := fw.GetStatus(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get flow %d status: %w", flowID, err)
		}

		switch status {
		case database.FlowStatusCreated:
			return nil, fmt.Errorf("flow %d is not completed", flowID)
		case database.FlowStatusFinished, database.FlowStatusFailed:
			if err := loadFlow(); err != nil {
				return nil, err
			}
		case database.FlowStatusRunning, database.FlowStatusWaiting:
			break
		default:
			return nil, fmt.Errorf("flow %d is in unknown status: %s", flowID, status)
		}
	} else {
		if err := loadFlow(); err != nil {
			return nil, err
		}
	}

	if fw == nil { // just double check, this should never happen
		return nil, fmt.Errorf("unexpected error: flow %d not found", flowID)
	}

	aw, err := NewAssistantWorker(ctx, newAssistantWorkerCtx{
		userID:        userID,
		flowID:        flowID,
		input:         input,
		prvname:       prvname,
		prvtype:       prvtype,
		useAgents:     useAgents,
		functions:     functions,
		flowWorkerCtx: flowWorkerCtx,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create assistant: %w", err)
	}

	if err = fw.AddAssistant(ctx, aw); err != nil {
		return nil, fmt.Errorf("failed to add assistant to flow: %w", err)
	}

	return aw, nil
}

const defaultResumeMessage = "Continue the security audit from where you left off. Review your previous findings and message history to understand current state, then proceed with the next phase."

func (fc *flowController) ResumeFlow(ctx context.Context, flowID int64, input string) (FlowWorker, error) {
	fc.mx.Lock()
	defer fc.mx.Unlock()

	flowWorkerCtx := flowWorkerCtx{
		db:          fc.db,
		cfg:         fc.cfg,
		docker:      fc.docker,
		provs:       fc.provs,
		subs:        fc.subs,
		flowControl: fc.flowControl,
		notifier:    fc.notifier,
		flowProviderControllers: flowProviderControllers{
			mlc:  fc.mlc,
			aslc: fc.aslc,
			alc:  fc.alc,
			slc:  fc.slc,
			tlc:  fc.tlc,
			vslc: fc.vslc,
			sc:   fc.sc,
		},
	}

	// Check if flow is already active in memory
	if fw, ok := fc.flows[flowID]; ok {
		status, err := fw.GetStatus(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get flow %d status: %w", flowID, err)
		}

		switch status {
		case database.FlowStatusRunning, database.FlowStatusWaiting:
			// Already alive — just send input if provided
			resumeInput := input
			if resumeInput == "" {
				resumeInput = defaultResumeMessage
			}
			if err := fw.PutInput(ctx, resumeInput); err != nil {
				return nil, fmt.Errorf("failed to put input: %w", err)
			}
			return fw, nil
		case database.FlowStatusFinished, database.FlowStatusFailed:
			// Worker exists in map but flow ended — need to reload below
			break
		default:
			return nil, fmt.Errorf("flow %d is in status %s, cannot resume", flowID, status)
		}
	}

	// Verify flow exists in DB and is in a resumable state
	flow, err := fc.db.GetFlow(ctx, flowID)
	if err != nil {
		return nil, fmt.Errorf("flow %d not found: %w", flowID, err)
	}

	if flow.Status != database.FlowStatusFinished && flow.Status != database.FlowStatusFailed {
		return nil, fmt.Errorf("flow %d is in status %s, only finished or failed flows can be resumed",
			flowID, flow.Status)
	}

	// Update status to Waiting (required by LoadFlowWorker)
	flow, err = fc.db.UpdateFlowStatus(ctx, database.UpdateFlowStatusParams{
		ID:     flowID,
		Status: database.FlowStatusWaiting,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update flow %d status: %w", flowID, err)
	}

	// Load (resurrect) the flow worker — spawns a new container, restores provider
	fw, err := LoadFlowWorker(ctx, flow, flowWorkerCtx)
	if err != nil {
		// Revert status on failure
		_, _ = fc.db.UpdateFlowStatus(ctx, database.UpdateFlowStatusParams{
			ID:     flowID,
			Status: database.FlowStatusFailed,
		})
		return nil, fmt.Errorf("failed to resume flow %d: %w", flowID, err)
	}

	fc.flows[flowID] = fw

	// Send user input (or default resume message)
	resumeInput := input
	if resumeInput == "" {
		resumeInput = defaultResumeMessage
	}
	if err := fw.PutInput(ctx, resumeInput); err != nil {
		return nil, fmt.Errorf("failed to put input to resumed flow: %w", err)
	}

	return fw, nil
}

func (fc *flowController) ListFlows(ctx context.Context) []FlowWorker {
	fc.mx.Lock()
	defer fc.mx.Unlock()

	flows := make([]FlowWorker, 0)
	for _, flow := range fc.flows {
		flows = append(flows, flow)
	}

	sort.Slice(flows, func(i, j int) bool {
		return flows[i].GetFlowID() < flows[j].GetFlowID()
	})

	return flows
}

func (fc *flowController) GetFlow(ctx context.Context, flowID int64) (FlowWorker, error) {
	fc.mx.Lock()
	defer fc.mx.Unlock()

	flow, ok := fc.flows[flowID]
	if !ok {
		return nil, ErrFlowNotFound
	}

	return flow, nil
}

func (fc *flowController) StopFlow(ctx context.Context, flowID int64) error {
	fc.mx.Lock()
	defer fc.mx.Unlock()

	flow, ok := fc.flows[flowID]
	if !ok {
		return ErrFlowNotFound
	}

	// Stop Master Agent for this flow
	if fc.masterSupervisor != nil {
		fc.masterSupervisor.StopForFlow(flowID)
	}

	err := flow.Stop(ctx)
	if err != nil {
		return fmt.Errorf("failed to stop flow %d: %w", flowID, err)
	}

	return nil
}

func (fc *flowController) FinishFlow(ctx context.Context, flowID int64) error {
	fc.mx.Lock()
	defer fc.mx.Unlock()

	flow, ok := fc.flows[flowID]
	if !ok {
		return ErrFlowNotFound
	}

	// Stop Master Agent for this flow
	if fc.masterSupervisor != nil {
		fc.masterSupervisor.StopForFlow(flowID)
	}

	err := flow.Finish(ctx)
	if err != nil {
		return fmt.Errorf("failed to finish flow %d: %w", flowID, err)
	}

	delete(fc.flows, flowID)
	fc.flowControl.Remove(flowID)

	return nil
}

func (fc *flowController) RenameFlow(ctx context.Context, flowID int64, title string) error {
	fc.mx.Lock()
	defer fc.mx.Unlock()

	flow, ok := fc.flows[flowID]
	if !ok {
		return ErrFlowNotFound
	}

	return flow.Rename(ctx, title)
}
