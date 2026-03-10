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

	"pentagi/pkg/docker"

	"github.com/docker/docker/api/types/container"
	"github.com/sirupsen/logrus"
)

const (
	defaultInteractshServer = "oast.fun"
	interactshStartTimeout  = 30 * time.Second
	interactshOutputFile    = "/work/.oob-interactions.jsonl"
	interactshPidFile       = "/work/.interactsh.pid"
	interactshExecTimeout   = 15 * time.Second
)

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
		// Try to start on-demand
		if err := ic.Start(ctx); err != nil {
			return "OOB detection is not available: interactsh-client could not be started. " +
				"You can still perform active testing without OOB callbacks.", nil
		}
	}

	ic.mu.Lock()
	ic.attacks[action.AttackID] = action.Description
	ic.mu.Unlock()

	// Generate a unique OOB URL for this attack
	sanitizedID := sanitizeAttackID(action.AttackID)
	oobURL := fmt.Sprintf("%s.%s", sanitizedID, ic.GetBaseURL())

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

		interactions = append(interactions, InteractshInteraction{
			AttackID:    attackID,
			Description: description,
			Protocol:    raw.Protocol,
			FullID:      raw.FullID,
			UniqueID:    raw.UniqueID,
			RawRequest:  raw.RawRequest,
			RawResponse: raw.RawResponse,
			RemoteAddr:  raw.RemoteAddress,
			Timestamp:   raw.Timestamp,
		})
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
