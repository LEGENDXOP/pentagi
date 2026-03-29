package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"pentagi/pkg/database"
	"pentagi/pkg/docker"

	dockercontainer "github.com/docker/docker/api/types/container"
	"github.com/sirupsen/logrus"
)

const (
	playwrightServerPort        = 9222
	playwrightDefaultTimeout    = 30 * time.Second
	playwrightStartTimeout      = 60 * time.Second
	playwrightHTTPTimeout       = 45 * time.Second
	playwrightInstallTimeout    = 180 * time.Second
	playwrightMaxResponseBody   = 128 * 1024 // 128 KB
	playwrightScreenshotDir     = "/work/evidence/screenshots"
	playwrightServerScript      = "/work/.pentagi-browser-server.js"
	playwrightPidFile           = "/work/.browser-server.pid"
	playwrightLogFile           = "/work/.browser-server.log"
	playwrightPackageJSON       = "/work/.browser-pkg/package.json"
	playwrightNodeModulesDir    = "/work/.browser-pkg/node_modules"
)

// browserPlaywright manages a Playwright-based headless browser running inside the container
type browserPlaywright struct {
	mu           sync.Mutex
	flowID       int64
	taskID       *int64
	subtaskID    *int64
	enabled      bool
	timeout      int // seconds
	containerID  int64
	containerLID string
	dockerClient docker.DockerClient
	tlp          TermLogProvider
	scp          ScreenshotProvider
	running      bool
}

// NewBrowserPlaywrightTool creates a new Playwright browser automation tool
func NewBrowserPlaywrightTool(
	flowID int64,
	taskID, subtaskID *int64,
	enabled bool,
	timeout int,
	containerID int64,
	containerLID string,
	dockerClient docker.DockerClient,
	tlp TermLogProvider,
	scp ScreenshotProvider,
) Tool {
	if timeout <= 0 || timeout > 120 {
		timeout = 30
	}
	return &browserPlaywright{
		flowID:       flowID,
		taskID:       taskID,
		subtaskID:    subtaskID,
		enabled:      enabled,
		timeout:      timeout,
		containerID:  containerID,
		containerLID: containerLID,
		dockerClient: dockerClient,
		tlp:          tlp,
		scp:          scp,
	}
}

// IsAvailable returns true if the playwright browser tool is enabled and docker is configured
func (bp *browserPlaywright) IsAvailable() bool {
	return bp.enabled && bp.dockerClient != nil
}

// Handle processes browser automation tool calls
func (bp *browserPlaywright) Handle(ctx context.Context, name string, args json.RawMessage) (string, error) {
	logger := logrus.WithContext(ctx).WithFields(enrichLogrusFields(bp.flowID, bp.taskID, bp.subtaskID, logrus.Fields{
		"tool": name,
		"args": string(args),
	}))

	switch name {
	case BrowserNavigateToolName:
		return bp.handleNavigate(ctx, logger, args)
	case BrowserClickToolName:
		return bp.handleClick(ctx, logger, args)
	case BrowserFillToolName:
		return bp.handleFill(ctx, logger, args)
	case BrowserScreenshotToolName:
		return bp.handleScreenshot(ctx, logger, args)
	case BrowserEvaluateToolName:
		return bp.handleEvaluate(ctx, logger, args)
	case BrowserCookiesToolName:
		return bp.handleCookies(ctx, logger, args)
	default:
		return "", fmt.Errorf("unknown browser playwright tool: %s", name)
	}
}

// ensureServer starts the Playwright server inside the container if not already running
func (bp *browserPlaywright) ensureServer(ctx context.Context) error {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	if bp.running {
		// Quick health check
		if bp.healthCheck(ctx) {
			return nil
		}
		bp.running = false
	}

	containerName := PrimaryTerminalName(bp.flowID)
	logger := logrus.WithFields(logrus.Fields{
		"flow_id":   bp.flowID,
		"container": containerName,
		"component": "playwright",
	})

	// Check if Node.js AND npm are available (vxcontrol/kali-linux has node but NOT npm)
	nodeCheck, err := bp.execInContainer(ctx, containerName, "which node 2>/dev/null || echo 'NOT_FOUND'", 10*time.Second)
	npmCheck, _ := bp.execInContainer(ctx, containerName, "which npm 2>/dev/null || echo 'NOT_FOUND'", 10*time.Second)

	needsInstall := err != nil || strings.Contains(nodeCheck, "NOT_FOUND") || strings.Contains(npmCheck, "NOT_FOUND")
	if needsInstall {
		var missingPkgs []string
		if err != nil || strings.Contains(nodeCheck, "NOT_FOUND") {
			missingPkgs = append(missingPkgs, "nodejs")
		}
		if strings.Contains(npmCheck, "NOT_FOUND") {
			missingPkgs = append(missingPkgs, "npm")
		}
		logger.WithField("missing", missingPkgs).Info("Installing missing packages for browser support...")
		installCmd := fmt.Sprintf("apt-get update -qq && apt-get install -y -qq %s > /dev/null 2>&1 && which node && which npm",
			strings.Join(missingPkgs, " "))
		installResult, installErr := bp.execInContainer(ctx, containerName, installCmd, playwrightInstallTimeout)
		if installErr != nil || !strings.Contains(installResult, "/node") {
			return fmt.Errorf("failed to install Node.js/npm: %v (output: %s)", installErr, installResult)
		}
		logger.Info("Node.js/npm installed successfully")
	}

	// Create package.json and install dependencies
	pkgJSON := `{"name":"pentagi-browser","version":"1.0.0","dependencies":{"playwright-extra":"^4.3.6","puppeteer-extra-plugin-stealth":"^2.11.2","playwright-core":"^1.49.0","playwright":"^1.49.0"}}`

	setupCmd := fmt.Sprintf(
		"mkdir -p /work/.browser-pkg && echo '%s' > %s && cd /work/.browser-pkg && npm install --no-audit --no-fund 2>&1 | tail -5",
		pkgJSON, playwrightPackageJSON,
	)

	// Check for pre-installed modules first (custom pentagi-kali image)
	preinstalledModules := "/opt/pentagi-browser/node_modules"
	checkPreinstalled, _ := bp.execInContainer(ctx, containerName,
		fmt.Sprintf("test -d %s/playwright-extra && echo 'EXISTS' || echo 'MISSING'", preinstalledModules), 5*time.Second)

	useNodeModulesDir := playwrightNodeModulesDir // default: /work/.browser-pkg/node_modules
	if strings.Contains(checkPreinstalled, "EXISTS") {
		logger.Info("Using pre-installed Playwright modules from image")
		useNodeModulesDir = preinstalledModules
	} else {
		// Fall back to installing in work dir
		checkModules, _ := bp.execInContainer(ctx, containerName,
			fmt.Sprintf("test -d %s/playwright-extra && echo 'EXISTS' || echo 'MISSING'", playwrightNodeModulesDir), 5*time.Second)
		if strings.Contains(checkModules, "MISSING") {
			logger.Info("Installing Playwright dependencies...")
			installResult, err := bp.execInContainer(ctx, containerName, setupCmd, playwrightInstallTimeout)
			if err != nil {
				return fmt.Errorf("failed to install Playwright dependencies: %v (output: %s)", err, installResult)
			}

			// Install Chromium browser
			chrInstall := "cd /work/.browser-pkg && npx playwright install chromium --with-deps 2>&1 | tail -5"
			chrResult, err := bp.execInContainer(ctx, containerName, chrInstall, playwrightInstallTimeout)
			if err != nil {
				return fmt.Errorf("failed to install Chromium: %v (output: %s)", err, chrResult)
			}
			logger.Info("Playwright dependencies installed successfully")
		}
	}

	// Write the browser server script into the container
	writeScriptCmd := fmt.Sprintf("cat > %s << 'SCRIPTEOF'\n%s\nSCRIPTEOF", playwrightServerScript, browserServerScript)
	if _, err := bp.execInContainer(ctx, containerName, writeScriptCmd, 10*time.Second); err != nil {
		return fmt.Errorf("failed to write browser server script: %w", err)
	}

	// Ensure screenshot dir exists
	bp.execInContainer(ctx, containerName, fmt.Sprintf("mkdir -p %s", playwrightScreenshotDir), 5*time.Second)

	// Kill any existing server
	killCmd := fmt.Sprintf("kill $(cat %s 2>/dev/null) 2>/dev/null; rm -f %s", playwrightPidFile, playwrightPidFile)
	bp.execInContainer(ctx, containerName, killCmd, 5*time.Second)

	// Start the server with the resolved NODE_PATH
	startCmd := fmt.Sprintf(
		"cd /work/.browser-pkg && BROWSER_PORT=%d BROWSER_TIMEOUT=%d NODE_PATH=%s nohup node %s > %s 2>&1 & echo $! > %s && sleep 3 && cat %s",
		playwrightServerPort, bp.timeout, useNodeModulesDir,
		playwrightServerScript, playwrightLogFile, playwrightPidFile, playwrightLogFile,
	)

	startResult, err := bp.execInContainer(ctx, containerName, startCmd, playwrightStartTimeout)
	if err != nil {
		return fmt.Errorf("failed to start browser server: %v (output: %s)", err, startResult)
	}

	// Verify server is responding
	for i := 0; i < 10; i++ {
		if bp.healthCheck(ctx) {
			bp.running = true
			logger.Info("Playwright browser server started successfully")
			return nil
		}
		time.Sleep(time.Second)
	}

	// Dump log for debugging
	logOutput, _ := bp.execInContainer(ctx, containerName, fmt.Sprintf("cat %s 2>/dev/null | tail -20", playwrightLogFile), 5*time.Second)
	return fmt.Errorf("browser server failed to start, log: %s", logOutput)
}

// healthCheck pings the browser server's health endpoint
func (bp *browserPlaywright) healthCheck(ctx context.Context) bool {
	containerName := PrimaryTerminalName(bp.flowID)
	result, err := bp.execInContainer(ctx, containerName,
		fmt.Sprintf("curl -sf http://127.0.0.1:%d/health 2>/dev/null || echo 'FAIL'", playwrightServerPort),
		5*time.Second)
	return err == nil && !strings.Contains(result, "FAIL") && strings.Contains(result, "success")
}

// callServer makes an HTTP request to the browser server inside the container
func (bp *browserPlaywright) callServer(ctx context.Context, method, endpoint string, body interface{}) (map[string]interface{}, error) {
	containerName := PrimaryTerminalName(bp.flowID)

	var curlCmd string
	if method == "GET" {
		curlCmd = fmt.Sprintf("curl -sf -X GET http://127.0.0.1:%d%s 2>&1", playwrightServerPort, endpoint)
	} else {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		// Escape single quotes in JSON for shell
		escapedBody := strings.ReplaceAll(string(jsonBody), "'", "'\"'\"'")
		curlCmd = fmt.Sprintf("curl -sf -X POST -H 'Content-Type: application/json' -d '%s' http://127.0.0.1:%d%s 2>&1",
			escapedBody, playwrightServerPort, endpoint)
	}

	result, err := bp.execInContainer(ctx, containerName, curlCmd, playwrightHTTPTimeout)
	if err != nil {
		return nil, fmt.Errorf("browser server request failed: %w", err)
	}

	// Parse JSON response
	var response map[string]interface{}
	// Find the start of JSON in the output (skip any curl noise)
	jsonStart := strings.Index(result, "{")
	if jsonStart < 0 {
		return nil, fmt.Errorf("no JSON in response: %s", truncateStr(result, 500))
	}
	if err := json.Unmarshal([]byte(result[jsonStart:]), &response); err != nil {
		return nil, fmt.Errorf("failed to parse server response: %w (raw: %s)", err, truncateStr(result, 500))
	}

	// Check for error
	if errMsg, ok := response["error"]; ok {
		return response, fmt.Errorf("browser server error: %v", errMsg)
	}

	return response, nil
}

func (bp *browserPlaywright) handleNavigate(ctx context.Context, logger *logrus.Entry, args json.RawMessage) (string, error) {
	var action BrowserNavigateAction
	if err := json.Unmarshal(args, &action); err != nil {
		return "", fmt.Errorf("failed to unmarshal browser_navigate action: %w", err)
	}

	if strings.TrimSpace(action.URL) == "" {
		return "error: url is required", nil
	}

	bp.logToTerminal(ctx, fmt.Sprintf("browser_navigate: %s", action.URL))

	if err := bp.ensureServer(ctx); err != nil {
		return fmt.Sprintf("[ERROR] Failed to start browser server: %v", err), nil
	}

	resp, err := bp.callServer(ctx, "POST", "/navigate", map[string]interface{}{
		"url":       action.URL,
		"waitUntil": action.WaitUntil,
		"timeout":   bp.timeout * 1000,
	})
	if err != nil {
		bp.running = false // Server might have crashed
		return fmt.Sprintf("[ERROR] Navigation failed: %v", err), nil
	}

	var sb strings.Builder
	sb.WriteString("## Browser Navigation Result\n\n")
	sb.WriteString(fmt.Sprintf("**URL:** `%v`\n", resp["url"]))
	sb.WriteString(fmt.Sprintf("**Title:** %v\n", resp["title"]))
	sb.WriteString(fmt.Sprintf("**Status:** %v\n", resp["status"]))
	if headers, ok := resp["headers"].(map[string]interface{}); ok {
		if ct := headers["content-type"]; ct != nil && ct != "" {
			sb.WriteString(fmt.Sprintf("**Content-Type:** %v\n", ct))
		}
		if srv := headers["server"]; srv != nil && srv != "" {
			sb.WriteString(fmt.Sprintf("**Server:** %v\n", srv))
		}
	}
	sb.WriteString(fmt.Sprintf("\n### Page Content\n\n```\n%v\n```\n", resp["content"]))

	result := sb.String()
	bp.logToTerminalOutput(ctx, truncateStr(result, 4096))

	logger.WithField("url", action.URL).Info("browser navigation completed")
	return result, nil
}

func (bp *browserPlaywright) handleClick(ctx context.Context, logger *logrus.Entry, args json.RawMessage) (string, error) {
	var action BrowserClickAction
	if err := json.Unmarshal(args, &action); err != nil {
		return "", fmt.Errorf("failed to unmarshal browser_click action: %w", err)
	}

	if strings.TrimSpace(action.Selector) == "" {
		return "error: selector is required", nil
	}

	bp.logToTerminal(ctx, fmt.Sprintf("browser_click: %s", action.Selector))

	if err := bp.ensureServer(ctx); err != nil {
		return fmt.Sprintf("[ERROR] Failed to start browser server: %v", err), nil
	}

	resp, err := bp.callServer(ctx, "POST", "/click", map[string]interface{}{
		"selector": action.Selector,
		"timeout":  bp.timeout * 1000,
	})
	if err != nil {
		return fmt.Sprintf("[ERROR] Click failed: %v", err), nil
	}

	result := fmt.Sprintf("## Browser Click Result\n\n**Clicked:** `%s`\n**Current URL:** `%v`\n**Title:** %v\n",
		action.Selector, resp["url"], resp["title"])

	bp.logToTerminalOutput(ctx, result)
	logger.WithField("selector", action.Selector).Info("browser click completed")
	return result, nil
}

func (bp *browserPlaywright) handleFill(ctx context.Context, logger *logrus.Entry, args json.RawMessage) (string, error) {
	var action BrowserFillAction
	if err := json.Unmarshal(args, &action); err != nil {
		return "", fmt.Errorf("failed to unmarshal browser_fill action: %w", err)
	}

	if strings.TrimSpace(action.Selector) == "" {
		return "error: selector is required", nil
	}

	bp.logToTerminal(ctx, fmt.Sprintf("browser_fill: %s = [%d chars]", action.Selector, len(action.Value)))

	if err := bp.ensureServer(ctx); err != nil {
		return fmt.Sprintf("[ERROR] Failed to start browser server: %v", err), nil
	}

	resp, err := bp.callServer(ctx, "POST", "/fill", map[string]interface{}{
		"selector": action.Selector,
		"value":    action.Value,
		"timeout":  bp.timeout * 1000,
	})
	if err != nil {
		return fmt.Sprintf("[ERROR] Fill failed: %v", err), nil
	}

	result := fmt.Sprintf("## Browser Fill Result\n\n%v\n", resp["message"])
	bp.logToTerminalOutput(ctx, result)
	logger.WithField("selector", action.Selector).Info("browser fill completed")
	return result, nil
}

func (bp *browserPlaywright) handleScreenshot(ctx context.Context, logger *logrus.Entry, args json.RawMessage) (string, error) {
	var action BrowserScreenshotAction
	if err := json.Unmarshal(args, &action); err != nil {
		return "", fmt.Errorf("failed to unmarshal browser_screenshot action: %w", err)
	}

	bp.logToTerminal(ctx, "browser_screenshot")

	if err := bp.ensureServer(ctx); err != nil {
		return fmt.Sprintf("[ERROR] Failed to start browser server: %v", err), nil
	}

	resp, err := bp.callServer(ctx, "POST", "/screenshot", map[string]interface{}{
		"fullPage": action.FullPage.Bool(),
	})
	if err != nil {
		return fmt.Sprintf("[ERROR] Screenshot failed: %v", err), nil
	}

	screenshotPath := fmt.Sprintf("%v", resp["path"])
	filename := fmt.Sprintf("%v", resp["filename"])

	// Register screenshot with the screenshot provider
	if bp.scp != nil {
		url := fmt.Sprintf("%v", resp["url"])
		_, _ = bp.scp.PutScreenshot(ctx, filename, url, bp.taskID, bp.subtaskID)
	}

	result := fmt.Sprintf("## Browser Screenshot\n\n**File:** `%s`\n**URL:** `%v`\n**Title:** %v\n**Size:** %v bytes\n",
		screenshotPath, resp["url"], resp["title"], resp["size"])

	bp.logToTerminalOutput(ctx, result)
	logger.WithField("path", screenshotPath).Info("browser screenshot captured")
	return result, nil
}

func (bp *browserPlaywright) handleEvaluate(ctx context.Context, logger *logrus.Entry, args json.RawMessage) (string, error) {
	var action BrowserEvaluateAction
	if err := json.Unmarshal(args, &action); err != nil {
		return "", fmt.Errorf("failed to unmarshal browser_evaluate action: %w", err)
	}

	if strings.TrimSpace(action.Expression) == "" {
		return "error: expression is required", nil
	}

	bp.logToTerminal(ctx, fmt.Sprintf("browser_evaluate: %s", truncateStr(action.Expression, 100)))

	if err := bp.ensureServer(ctx); err != nil {
		return fmt.Sprintf("[ERROR] Failed to start browser server: %v", err), nil
	}

	resp, err := bp.callServer(ctx, "POST", "/evaluate", map[string]interface{}{
		"expression": action.Expression,
	})
	if err != nil {
		return fmt.Sprintf("[ERROR] Evaluate failed: %v", err), nil
	}

	result := fmt.Sprintf("## Browser Evaluate Result\n\n**Type:** %v\n\n```json\n%v\n```\n",
		resp["type"], resp["result"])

	bp.logToTerminalOutput(ctx, truncateStr(result, 4096))
	logger.Info("browser evaluate completed")
	return result, nil
}

func (bp *browserPlaywright) handleCookies(ctx context.Context, logger *logrus.Entry, args json.RawMessage) (string, error) {
	var action BrowserCookiesAction
	if err := json.Unmarshal(args, &action); err != nil {
		return "", fmt.Errorf("failed to unmarshal browser_cookies action: %w", err)
	}

	bp.logToTerminal(ctx, "browser_cookies")

	if err := bp.ensureServer(ctx); err != nil {
		return fmt.Sprintf("[ERROR] Failed to start browser server: %v", err), nil
	}

	resp, err := bp.callServer(ctx, "GET", "/cookies", nil)
	if err != nil {
		return fmt.Sprintf("[ERROR] Get cookies failed: %v", err), nil
	}

	var sb strings.Builder
	sb.WriteString("## Browser Cookies\n\n")
	sb.WriteString(fmt.Sprintf("**URL:** `%v`\n", resp["url"]))
	sb.WriteString(fmt.Sprintf("**Count:** %v\n\n", resp["count"]))

	if cookies, ok := resp["cookies"].([]interface{}); ok {
		for i, c := range cookies {
			if cookie, ok := c.(map[string]interface{}); ok {
				sb.WriteString(fmt.Sprintf("### Cookie %d: `%v`\n", i+1, cookie["name"]))
				sb.WriteString(fmt.Sprintf("- **Value:** `%v`\n", cookie["value"]))
				sb.WriteString(fmt.Sprintf("- **Domain:** `%v`\n", cookie["domain"]))
				sb.WriteString(fmt.Sprintf("- **Path:** `%v`\n", cookie["path"]))
				sb.WriteString(fmt.Sprintf("- **Secure:** %v\n", cookie["secure"]))
				sb.WriteString(fmt.Sprintf("- **HttpOnly:** %v\n", cookie["httpOnly"]))
				sb.WriteString(fmt.Sprintf("- **SameSite:** %v\n\n", cookie["sameSite"]))
			}
		}
	}

	result := sb.String()
	bp.logToTerminalOutput(ctx, truncateStr(result, 4096))
	logger.Info("browser cookies retrieved")
	return result, nil
}

// execInContainer runs a command inside the primary container
func (bp *browserPlaywright) execInContainer(ctx context.Context, containerName, command string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	createResp, err := bp.dockerClient.ContainerExecCreate(execCtx, containerName, dockercontainer.ExecOptions{
		Cmd:          []string{"sh", "-c", command},
		AttachStdout: true,
		AttachStderr: true,
		WorkingDir:   docker.WorkFolderPathInContainer,
	})
	if err != nil {
		return "", fmt.Errorf("failed to create exec: %w", err)
	}

	resp, err := bp.dockerClient.ContainerExecAttach(execCtx, createResp.ID, dockercontainer.ExecAttachOptions{
		Tty: true,
	})
	if err != nil {
		return "", fmt.Errorf("failed to attach to exec: %w", err)
	}
	defer resp.Close()

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, io.LimitReader(resp.Reader, playwrightMaxResponseBody))

	return buf.String(), nil
}

// logToTerminal logs a command to the terminal log provider
func (bp *browserPlaywright) logToTerminal(ctx context.Context, msg string) {
	if bp.tlp == nil {
		return
	}
	formatted := FormatTerminalInput(docker.WorkFolderPathInContainer, msg)
	_, _ = bp.tlp.PutMsg(ctx, database.TermlogTypeStdin, formatted, bp.containerID, bp.taskID, bp.subtaskID)
}

// logToTerminalOutput logs output to the terminal log provider
func (bp *browserPlaywright) logToTerminalOutput(ctx context.Context, msg string) {
	if bp.tlp == nil {
		return
	}
	formatted := FormatTerminalSystemOutput(msg)
	_, _ = bp.tlp.PutMsg(ctx, database.TermlogTypeStdout, formatted, bp.containerID, bp.taskID, bp.subtaskID)
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "... [truncated]"
}

// Unused import guard for net/http — used in the write file above for type references only.
// The actual HTTP calls go through curl inside the container to avoid network routing issues.
var _ = http.StatusOK
var _ bytes.Buffer
