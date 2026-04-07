package tools

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"pentagi/pkg/database"
	"pentagi/pkg/docker"

	"github.com/docker/docker/api/types/container"
	"github.com/sirupsen/logrus"
)

const (
	nucleiDefaultRateLimit   = 100
	nucleiMinRateLimit       = 10
	nucleiMaxRateLimit       = 500
	nucleiDefaultSeverity    = "medium,high,critical"
	nucleiDefaultTimeout     = 10 * time.Minute
	nucleiExtraTimeout       = 30 * time.Second
	nucleiOutputPath         = "/tmp/nuclei-results.jsonl"
	nucleiMaxFindings        = 100
	nucleiMaxOutputSize      = 128 * 1024 // 128 KB
	nucleiMaxFindingDescSize = 2048
	nucleiMaxCurlCommandSize = 1024
)

// nucleiTool implements the nuclei vulnerability scanner integration
type nucleiTool struct {
	flowID        int64
	taskID        *int64
	subtaskID     *int64
	enabled       bool
	rateLimit     int
	templatesPath string
	containerID   int64
	containerLID  string
	dockerClient  docker.DockerClient
	tlp           TermLogProvider
}

// NewNucleiTool creates a new Nuclei scanner tool instance
func NewNucleiTool(
	flowID int64,
	taskID, subtaskID *int64,
	enabled bool,
	rateLimit int,
	templatesPath string,
	containerID int64,
	containerLID string,
	dockerClient docker.DockerClient,
	tlp TermLogProvider,
) Tool {
	if rateLimit < nucleiMinRateLimit || rateLimit > nucleiMaxRateLimit {
		rateLimit = nucleiDefaultRateLimit
	}
	return &nucleiTool{
		flowID:        flowID,
		taskID:        taskID,
		subtaskID:     subtaskID,
		enabled:       enabled,
		rateLimit:     rateLimit,
		templatesPath: templatesPath,
		containerID:   containerID,
		containerLID:  containerLID,
		dockerClient:  dockerClient,
		tlp:           tlp,
	}
}

// IsAvailable returns true if the nuclei tool is enabled and docker is configured
func (n *nucleiTool) IsAvailable() bool {
	return n.enabled && n.dockerClient != nil && n.tlp != nil
}

// Handle processes a nuclei scan request from the pentester agent
func (n *nucleiTool) Handle(ctx context.Context, name string, args json.RawMessage) (string, error) {
	var action NucleiScanAction
	logger := logrus.WithContext(ctx).WithFields(enrichLogrusFields(n.flowID, n.taskID, n.subtaskID, logrus.Fields{
		"tool": name,
		"args": string(args),
	}))

	if err := json.Unmarshal(args, &action); err != nil {
		logger.WithError(err).Error("failed to unmarshal nuclei scan action")
		return "", fmt.Errorf("failed to unmarshal nuclei scan action arguments: %w", err)
	}

	target := strings.TrimSpace(action.Target)
	if target == "" {
		return "error: target URL or host is required", nil
	}

	// Build nuclei command
	cmd := n.buildCommand(action)
	logger = logger.WithField("command", cmd)

	// Log the command to terminal log
	containerName := PrimaryTerminalName(n.flowID)

	// Validate nuclei setup: check templates are available
	if ok, diagMsg := n.validateNucleiSetup(ctx, containerName, logger); !ok {
		// Attempt auto-fix: download templates
		logger.Warn("nuclei validation failed, attempting template download: " + diagMsg)
		fixCmd := "nuclei -update-templates 2>&1 | tail -5"
		fixCtx, fixCancel := context.WithTimeout(ctx, 3*time.Minute)
		defer fixCancel()
		fixOutput, fixErr := n.execInContainer(fixCtx, containerName, fixCmd)
		if fixErr != nil {
			errMsg := fmt.Sprintf("[ERROR] nuclei is not properly configured: %s\nAuto-fix failed: %v\nFix output: %s",
				diagMsg, fixErr, fixOutput)
			formattedOutput := FormatTerminalSystemOutput(errMsg)
			n.tlp.PutMsg(ctx, database.TermlogTypeStdout, formattedOutput, n.containerID, n.taskID, n.subtaskID)
			return errMsg, nil
		}
		// Re-validate after fix
		if ok2, diagMsg2 := n.validateNucleiSetup(ctx, containerName, logger); !ok2 {
			errMsg := fmt.Sprintf("[ERROR] nuclei setup still invalid after template download: %s", diagMsg2)
			formattedOutput := FormatTerminalSystemOutput(errMsg)
			n.tlp.PutMsg(ctx, database.TermlogTypeStdout, formattedOutput, n.containerID, n.taskID, n.subtaskID)
			return errMsg, nil
		}
		logger.Info("nuclei templates downloaded successfully, proceeding with scan")
	}
	formattedCmd := FormatTerminalInput(docker.WorkFolderPathInContainer, cmd)
	if _, err := n.tlp.PutMsg(ctx, database.TermlogTypeStdin, formattedCmd, n.containerID, n.taskID, n.subtaskID); err != nil {
		logger.WithError(err).Warn("failed to put terminal log for nuclei command")
	}

	// Execute nuclei in the container
	scanStartTime := time.Now()
	output, err := n.execInContainer(ctx, containerName, cmd)
	scanDuration := time.Since(scanStartTime)
	if err != nil {
		errMsg := fmt.Sprintf("[ERROR] nuclei scan failed: %v", err)
		if output != "" {
			partial := output
			if len(partial) > 4096 {
				partial = partial[:4096]
			}
			errMsg += fmt.Sprintf("\nPartial output:\n%s", partial)
		}

		// Log output even on error
		formattedOutput := FormatTerminalSystemOutput(errMsg)
		if _, logErr := n.tlp.PutMsg(ctx, database.TermlogTypeStdout, formattedOutput, n.containerID, n.taskID, n.subtaskID); logErr != nil {
			logger.WithError(logErr).Warn("failed to put terminal log for nuclei error output")
		}

		return errMsg, nil
	}

	// Viability check: if scan completed in <5 seconds, something is likely wrong
	if scanDuration < 5*time.Second {
		logger.WithField("scan_duration", scanDuration).Warn("nuclei scan completed suspiciously fast — possible misconfiguration")
		diagCmd := fmt.Sprintf("ls -la %s 2>/dev/null && wc -l %s 2>/dev/null || echo 'results file not found'",
			nucleiOutputPath, nucleiOutputPath)
		diagOutput, _ := n.execInContainer(ctx, containerName, diagCmd)
		output += fmt.Sprintf("\n[DIAGNOSTIC] Scan completed in %v (expected >30s for real scan).\n"+
			"This usually means nuclei has no templates loaded or the target is unreachable.\n"+
			"Results file check: %s\n"+
			"Stdout output length: %d bytes",
			scanDuration, strings.TrimSpace(diagOutput), len(output))
	}

	// Read results file from container
	resultsOutput, readErr := n.readResultsFile(ctx, containerName)
	if readErr != nil {
		logger.WithError(readErr).Warn("failed to read nuclei results file, falling back to stdout parsing")
		// Fall back to parsing stdout
		resultsOutput = output
	}

	// Parse and format findings
	findings := parseNucleiFindings(resultsOutput)
	result := formatNucleiResults(target, action, findings)

	// v7: Write findings to the work directory so the agent can find them if it
	// tries to read from disk (common LLM behavior — it ignores inline results).
	if len(findings) > 0 {
		evidenceDir := docker.WorkFolderPathInContainer + "/evidence"
		mkdirCmd := fmt.Sprintf("mkdir -p %s", evidenceDir)
		mkCtx, mkCancel := context.WithTimeout(ctx, 10*time.Second)
		n.execInContainer(mkCtx, containerName, mkdirCmd)
		mkCancel()

		// Write the formatted markdown for the agent's convenience
		writeCmd := fmt.Sprintf("echo '%s' | base64 -d > %s/nuclei_results.md",
			base64EncodeResult(result), evidenceDir)
		writeCtx, writeCancel := context.WithTimeout(ctx, 15*time.Second)
		_, writeErr := n.execInContainer(writeCtx, containerName, writeCmd)
		writeCancel()
		if writeErr != nil {
			logger.WithError(writeErr).Debug("failed to write nuclei results to evidence dir (non-fatal)")
		}

		// Also copy the raw JSONL
		copyCmd := fmt.Sprintf("cp %s %s/nuclei_results.jsonl 2>/dev/null || true", nucleiOutputPath, evidenceDir)
		copyCtx, copyCancel := context.WithTimeout(ctx, 10*time.Second)
		n.execInContainer(copyCtx, containerName, copyCmd)
		copyCancel()
	}

	// Log results to terminal
	formattedResult := FormatTerminalSystemOutput(result)
	if _, logErr := n.tlp.PutMsg(ctx, database.TermlogTypeStdout, formattedResult, n.containerID, n.taskID, n.subtaskID); logErr != nil {
		logger.WithError(logErr).Warn("failed to put terminal log for nuclei results")
	}

	logger.WithField("findings_count", len(findings)).Info("nuclei scan completed")

	return result, nil
}

// buildCommand constructs the nuclei CLI command from action parameters
func (n *nucleiTool) buildCommand(action NucleiScanAction) string {
	target := strings.TrimSpace(action.Target)
	var parts []string
	parts = append(parts, "nuclei")
	parts = append(parts, "-u", shellQuote(target))

	// Template tags filter
	tags := strings.TrimSpace(action.Tags)
	if tags != "" {
		// Sanitize: only allow alphanumeric, commas, hyphens, underscores
		sanitized := sanitizeCSV(tags)
		if sanitized != "" {
			parts = append(parts, "-tags", sanitized)
		}
	}

	// Severity filter
	severity := strings.TrimSpace(action.Severity)
	if severity != "" {
		sanitized := sanitizeCSV(severity)
		if sanitized != "" {
			parts = append(parts, "-severity", sanitized)
		}
	} else {
		parts = append(parts, "-severity", nucleiDefaultSeverity)
	}

	// Rate limit
	rateLimit := action.RateLimit.Int()
	if rateLimit < nucleiMinRateLimit {
		rateLimit = n.rateLimit
	}
	if rateLimit > nucleiMaxRateLimit {
		rateLimit = nucleiMaxRateLimit
	}
	parts = append(parts, "-rate-limit", fmt.Sprintf("%d", rateLimit))

	// JSON Lines output for structured parsing
	parts = append(parts, "-jsonl")
	parts = append(parts, "-o", nucleiOutputPath)

	// Templates path if configured
	if n.templatesPath != "" {
		parts = append(parts, "-t", n.templatesPath)
	}

	// Disable update checks (running in container, templates pre-installed)
	parts = append(parts, "-duc")

	// Use -no-color to keep output parseable but don't suppress it entirely.
	// -silent was previously used but it suppresses ALL output including error
	// diagnostics, making it impossible to debug scan failures.
	parts = append(parts, "-no-color")
	parts = append(parts, "-stats")
	parts = append(parts, "-stats-interval", "10")

	return strings.Join(parts, " ")
}

// execInContainer runs a command inside the primary container and returns stdout.
// Fix Issue-4: Added context-aware timeout alignment and process kill on cancellation.
// The scanner.Scan() loop can block indefinitely because Docker exec attach readers
// don't respect Go context cancellation. We use a goroutine + select pattern to
// unblock on timeout, and explicitly kill the nuclei process inside the container.
func (n *nucleiTool) execInContainer(ctx context.Context, containerName, command string) (string, error) {
	isRunning, err := n.dockerClient.IsContainerRunning(ctx, n.containerLID)
	if err != nil {
		return "", fmt.Errorf("failed to inspect container: %w", err)
	}
	if !isRunning {
		return "", fmt.Errorf("container is not running")
	}

	// Fix Issue-4: Respect parent context deadline. If the parent (executor tool timeout)
	// has a shorter deadline than nuclei's internal timeout, use the parent's with a
	// 30-second cleanup buffer. Minimum viable scan time is 2 minutes.
	timeout := nucleiDefaultTimeout + nucleiExtraTimeout
	if deadline, ok := ctx.Deadline(); ok {
		parentRemaining := time.Until(deadline)
		if parentRemaining < timeout {
			timeout = parentRemaining - 30*time.Second // leave 30s for cleanup
			if timeout < 2*time.Minute {
				timeout = 2 * time.Minute // minimum viable scan time
			}
		}
	}
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := []string{"sh", "-c", command}

	createResp, err := n.dockerClient.ContainerExecCreate(execCtx, containerName, container.ExecOptions{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
		WorkingDir:   docker.WorkFolderPathInContainer,
		Tty:          true,
	})
	if err != nil {
		return "", fmt.Errorf("failed to create exec process for nuclei: %w", err)
	}

	resp, err := n.dockerClient.ContainerExecAttach(execCtx, createResp.ID, container.ExecAttachOptions{
		Tty: true,
	})
	if err != nil {
		return "", fmt.Errorf("failed to attach to nuclei exec process: %w", err)
	}

	// Fix Issue-4: Start a goroutine that kills the nuclei process when context is cancelled.
	// Docker exec attach readers don't respect context cancellation, so scanner.Scan()
	// would block indefinitely without this. We use pkill to kill the process inside
	// the container (NOT ContainerExecResize which only resizes the TTY).
	go func() {
		<-execCtx.Done()
		// Kill the nuclei process by name inside the container
		killCtx, killCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer killCancel()
		killCmd := []string{"sh", "-c", "pkill -9 -f nuclei 2>/dev/null || true"}
		killExec, killErr := n.dockerClient.ContainerExecCreate(killCtx, containerName, container.ExecOptions{
			Cmd:          killCmd,
			AttachStdout: true,
			AttachStderr: true,
		})
		if killErr == nil {
			// Use Attach to start the exec (Start is not in the DockerClient interface)
			killResp, attachErr := n.dockerClient.ContainerExecAttach(killCtx, killExec.ID, container.ExecAttachOptions{})
			if attachErr == nil {
				killResp.Close()
			}
		}
		// Close the reader to unblock scanner.Scan()
		resp.Close()
	}()

	// Fix Issue-4: Run scanner in a goroutine with select to unblock on context cancellation.
	var buf strings.Builder
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		scanner := bufio.NewScanner(resp.Reader)
		scanner.Buffer(make([]byte, 64*1024), nucleiMaxOutputSize)
		for scanner.Scan() {
			if buf.Len() > nucleiMaxOutputSize {
				buf.WriteString("\n[OUTPUT TRUNCATED: exceeded size limit]")
				break
			}
			buf.WriteString(scanner.Text())
			buf.WriteString("\n")
		}
	}()

	select {
	case <-doneCh:
		// Scanner finished normally
	case <-execCtx.Done():
		// Context expired — the kill goroutine will close resp, unblocking scanner
		<-doneCh // Wait for scanner goroutine to finish after reader closes
		logrus.WithContext(ctx).Warn("nuclei exec timed out, process killed")
		return buf.String(), fmt.Errorf("nuclei execution timed out after %v: %w", timeout, context.DeadlineExceeded)
	}

	// Check exec exit code
	inspectResp, inspectErr := n.dockerClient.ContainerExecInspect(execCtx, createResp.ID)
	if inspectErr != nil {
		return buf.String(), fmt.Errorf("failed to inspect nuclei exec: %w", inspectErr)
	}
	// nuclei returns exit code 0 on success, 1 when it finds vulns — both are fine
	if inspectResp.ExitCode > 1 {
		return buf.String(), fmt.Errorf("nuclei exited with code %d", inspectResp.ExitCode)
	}

	return buf.String(), nil
}

// readResultsFile reads the nuclei JSONL output file from the container
func (n *nucleiTool) readResultsFile(ctx context.Context, containerName string) (string, error) {
	readCmd := fmt.Sprintf("cat %s 2>/dev/null || echo ''", nucleiOutputPath)
	cmd := []string{"sh", "-c", readCmd}

	readCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	createResp, err := n.dockerClient.ContainerExecCreate(readCtx, containerName, container.ExecOptions{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
		WorkingDir:   docker.WorkFolderPathInContainer,
		Tty:          true,
	})
	if err != nil {
		return "", fmt.Errorf("failed to create exec for reading results: %w", err)
	}

	resp, err := n.dockerClient.ContainerExecAttach(readCtx, createResp.ID, container.ExecAttachOptions{
		Tty: true,
	})
	if err != nil {
		return "", fmt.Errorf("failed to attach to results read: %w", err)
	}
	defer resp.Close()

	var buf strings.Builder
	scanner := bufio.NewScanner(resp.Reader)
	scanner.Buffer(make([]byte, 64*1024), nucleiMaxOutputSize)
	for scanner.Scan() {
		buf.WriteString(scanner.Text())
		buf.WriteString("\n")
	}

	return buf.String(), nil
}

// nucleiFinding represents a parsed nuclei result
type nucleiFinding struct {
	TemplateID       string     `json:"template-id"`
	TemplatePath     string     `json:"template-path,omitempty"`
	Info             nucleiInfo `json:"info"`
	MatchedAt        string     `json:"matched-at"`
	MatcherName      string     `json:"matcher-name,omitempty"`
	ExtractedResults []string   `json:"extracted-results,omitempty"`
	CurlCommand      string     `json:"curl-command,omitempty"`
	Host             string     `json:"host,omitempty"`
	IP               string     `json:"ip,omitempty"`
	Timestamp        string     `json:"timestamp,omitempty"`
	Type             string     `json:"type,omitempty"`
}

type nucleiInfo struct {
	Name           string               `json:"name"`
	Severity       string               `json:"severity"`
	Description    string               `json:"description,omitempty"`
	Tags           []string             `json:"tags"`
	Reference      []string             `json:"reference,omitempty"`
	Classification nucleiClassification `json:"classification,omitempty"`
	Author         []string             `json:"author,omitempty"`
}

type nucleiClassification struct {
	CVSSMetrics string   `json:"cvss-metrics,omitempty"`
	CVSSScore   float64  `json:"cvss-score,omitempty"`
	CVEID       []string `json:"cve-id,omitempty"`
	CWEID       []string `json:"cwe-id,omitempty"`
}

// parseNucleiFindings parses JSONL nuclei output into structured findings
func parseNucleiFindings(output string) []nucleiFinding {
	var findings []nucleiFinding
	seen := make(map[string]struct{})

	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 64*1024), nucleiMaxOutputSize)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		var finding nucleiFinding
		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			continue
		}

		// Skip empty findings
		if finding.TemplateID == "" || finding.MatchedAt == "" {
			continue
		}

		// Deduplicate: same template-id + same normalized endpoint = same finding
		dedupKey := finding.TemplateID + "|" + normalizeEndpoint(finding.MatchedAt)
		if _, exists := seen[dedupKey]; exists {
			continue
		}
		seen[dedupKey] = struct{}{}

		findings = append(findings, finding)
		if len(findings) >= nucleiMaxFindings {
			break
		}
	}

	return findings
}

// normalizeEndpoint strips numeric IDs, UUIDs, and query params for dedup comparison
func normalizeEndpoint(url string) string {
	// Strip query parameters
	if idx := strings.Index(url, "?"); idx != -1 {
		url = url[:idx]
	}
	// Strip trailing slash
	url = strings.TrimRight(url, "/")
	return url
}

// mapNucleiSeverity maps nuclei severity strings to a standardized format
func mapNucleiSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	case "info", "informational":
		return "Info"
	default:
		return "Unknown"
	}
}

// mapNucleiTagToVulnType maps nuclei template tags to PentAGI's [VULN_TYPE] tags
func mapNucleiTagToVulnType(tags []string, templateID string) string {
	// Priority order: check specific tags first
	tagSet := make(map[string]struct{})
	for _, t := range tags {
		tagSet[strings.ToLower(strings.TrimSpace(t))] = struct{}{}
	}

	// Direct mapping from nuclei tags to PentAGI VULN_TYPE
	mappings := []struct {
		nucleiTag string
		vulnType  string
	}{
		{"sqli", "sqli"},
		{"sql-injection", "sqli"},
		{"xss", "xss_reflected"},
		{"stored-xss", "xss_stored"},
		{"dom-xss", "xss_dom"},
		{"ssrf", "ssrf"},
		{"ssti", "ssti"},
		{"lfi", "path_traversal"},
		{"rfi", "path_traversal"},
		{"path-traversal", "path_traversal"},
		{"rce", "command_injection"},
		{"command-injection", "command_injection"},
		{"idor", "idor"},
		{"csrf", "csrf"},
		{"open-redirect", "open_redirect"},
		{"redirect", "open_redirect"},
		{"xxe", "xxe"},
		{"deserialization", "deserialization"},
		{"file-upload", "file_upload"},
		{"fileupload", "file_upload"},
		{"auth-bypass", "auth_bypass"},
		{"authentication-bypass", "auth_bypass"},
		{"default-login", "broken_auth"},
		{"default-credential", "broken_auth"},
		{"weak-password", "broken_auth"},
		{"misconfig", "security_misconfiguration"},
		{"misconfiguration", "security_misconfiguration"},
		{"exposure", "information_disclosure"},
		{"disclosure", "information_disclosure"},
		{"info-disclosure", "information_disclosure"},
		{"token", "sensitive_data_exposure"},
		{"token-exposure", "sensitive_data_exposure"},
		{"api-key", "sensitive_data_exposure"},
		{"cors", "cors_misconfiguration"},
		{"cve", "vulnerable_component"},
	}

	for _, m := range mappings {
		if _, ok := tagSet[m.nucleiTag]; ok {
			return m.vulnType
		}
	}

	// Check template ID for CVE pattern
	templateLower := strings.ToLower(templateID)
	if strings.HasPrefix(templateLower, "cve-") || strings.Contains(templateLower, "cve-") {
		return "vulnerable_component"
	}

	// Fallback: check for partial matches in tags
	for _, tag := range tags {
		tagLower := strings.ToLower(tag)
		if strings.Contains(tagLower, "sql") {
			return "sqli"
		}
		if strings.Contains(tagLower, "xss") {
			return "xss_reflected"
		}
		if strings.Contains(tagLower, "inject") {
			return "command_injection"
		}
	}

	return "security_misconfiguration"
}


// base64EncodeResult encodes a string to base64 for safe shell transport.
func base64EncodeResult(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// formatNucleiResults produces a human-readable markdown report from parsed findings
func formatNucleiResults(target string, action NucleiScanAction, findings []nucleiFinding) string {
	var sb strings.Builder

	sb.WriteString("⚠️ ALL RESULTS ARE BELOW — do NOT try to read any file from disk. These results are COMPLETE and INLINE.\n\n")
	sb.WriteString("# Nuclei Scan Results\n\n")
	sb.WriteString(fmt.Sprintf("**Target:** `%s`\n", target))
	if action.Tags != "" {
		sb.WriteString(fmt.Sprintf("**Tags:** %s\n", action.Tags))
	}
	if action.Severity != "" {
		sb.WriteString(fmt.Sprintf("**Severity Filter:** %s\n", action.Severity))
	}
	sb.WriteString(fmt.Sprintf("**Total Unique Findings:** %d\n\n", len(findings)))
	sb.WriteString("---\n\n")

	if len(findings) == 0 {
		sb.WriteString("No vulnerabilities were detected by nuclei for the given target and configuration.\n")
		sb.WriteString("\nConsider:\n")
		sb.WriteString("- Broadening template tags or removing the tag filter\n")
		sb.WriteString("- Lowering the severity filter to include 'low' or 'info'\n")
		sb.WriteString("- Verifying the target is reachable from the container\n")
		return sb.String()
	}

	// Group findings by severity for summary
	severityCounts := map[string]int{}
	for _, f := range findings {
		sev := mapNucleiSeverity(f.Info.Severity)
		severityCounts[sev]++
	}

	sb.WriteString("## Summary by Severity\n\n")
	for _, sev := range []string{"Critical", "High", "Medium", "Low", "Info"} {
		if count, ok := severityCounts[sev]; ok {
			sb.WriteString(fmt.Sprintf("- **%s:** %d\n", sev, count))
		}
	}
	sb.WriteString("\n---\n\n")

	// Detail each finding
	sb.WriteString("## Detailed Findings\n\n")
	for i, f := range findings {
		if i >= 50 { // Hard limit on detailed output
			sb.WriteString(fmt.Sprintf("\n**... and %d more findings (truncated for readability)**\n", len(findings)-50))
			break
		}

		vulnType := mapNucleiTagToVulnType(f.Info.Tags, f.TemplateID)
		severity := mapNucleiSeverity(f.Info.Severity)

		sb.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, f.Info.Name))
		sb.WriteString(fmt.Sprintf("- **Template:** `%s`\n", f.TemplateID))
		sb.WriteString(fmt.Sprintf("- **Severity:** %s\n", severity))
		sb.WriteString(fmt.Sprintf("- **Matched At:** `%s`\n", f.MatchedAt))
		sb.WriteString(fmt.Sprintf("- [VULN_TYPE: %s]\n", vulnType))

		if len(f.Info.Tags) > 0 {
			sb.WriteString(fmt.Sprintf("- **Tags:** %s\n", strings.Join(f.Info.Tags, ", ")))
		}

		if f.Info.Description != "" {
			desc := f.Info.Description
			if len(desc) > nucleiMaxFindingDescSize {
				desc = desc[:nucleiMaxFindingDescSize] + "... [truncated]"
			}
			sb.WriteString(fmt.Sprintf("- **Description:** %s\n", desc))
		}

		// Classification info (CVE, CWE, CVSS)
		if len(f.Info.Classification.CVEID) > 0 {
			sb.WriteString(fmt.Sprintf("- **CVE:** %s\n", strings.Join(f.Info.Classification.CVEID, ", ")))
		}
		if len(f.Info.Classification.CWEID) > 0 {
			sb.WriteString(fmt.Sprintf("- **CWE:** %s\n", strings.Join(f.Info.Classification.CWEID, ", ")))
		}
		if f.Info.Classification.CVSSScore > 0 {
			sb.WriteString(fmt.Sprintf("- **CVSS Score:** %.1f\n", f.Info.Classification.CVSSScore))
		}

		// References
		if len(f.Info.Reference) > 0 {
			sb.WriteString("- **References:**\n")
			for _, ref := range f.Info.Reference {
				if ref != "" {
					sb.WriteString(fmt.Sprintf("  - %s\n", ref))
				}
			}
		}

		// Curl command for reproduction
		if f.CurlCommand != "" {
			curlCmd := f.CurlCommand
			if len(curlCmd) > nucleiMaxCurlCommandSize {
				curlCmd = curlCmd[:nucleiMaxCurlCommandSize] + "... [truncated]"
			}
			sb.WriteString(fmt.Sprintf("- **Reproduction:** `%s`\n", curlCmd))
		}

		// Extracted results
		if len(f.ExtractedResults) > 0 {
			sb.WriteString("- **Extracted Data:**\n")
			for _, r := range f.ExtractedResults {
				if len(r) > 256 {
					r = r[:256] + "..."
				}
				sb.WriteString(fmt.Sprintf("  - `%s`\n", r))
			}
		}

		sb.WriteString("\n---\n\n")
	}

	if len(findings) >= nucleiMaxFindings {
		sb.WriteString(fmt.Sprintf("\n**⚠️ Note:** Output limited to %d findings. Consider narrowing your scan with more specific tags or higher severity filter.\n", nucleiMaxFindings))
	}

	return sb.String()
}

// Helper: sanitize a CSV string to only allow safe characters
func sanitizeCSV(input string) string {
	var parts []string
	for _, part := range strings.Split(input, ",") {
		cleaned := strings.TrimSpace(part)
		// Only allow alphanumeric, hyphens, underscores
		safe := true
		for _, c := range cleaned {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
				safe = false
				break
			}
		}
		if safe && cleaned != "" {
			parts = append(parts, cleaned)
		}
	}
	return strings.Join(parts, ",")
}

// Helper: simple shell quoting (single quotes with escaping)
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

// validateNucleiSetup checks that nuclei has templates available.
// Returns (ok, diagnosticMessage). If !ok, the caller should attempt template download.
func (n *nucleiTool) validateNucleiSetup(ctx context.Context, containerName string, logger *logrus.Entry) (bool, string) {
	checkCmd := "nuclei -tl 2>/dev/null | wc -l"

	checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	output, err := n.execInContainer(checkCtx, containerName, checkCmd)
	if err != nil {
		return false, fmt.Sprintf("failed to check nuclei templates: %v", err)
	}

	countStr := strings.TrimSpace(output)
	count := 0
	fmt.Sscanf(countStr, "%d", &count)

	if count == 0 {
		return false, fmt.Sprintf(
			"nuclei has 0 templates loaded. Templates path '%s' may be empty or missing. "+
				"Run 'nuclei -update-templates' in the container first.",
			n.templatesPath,
		)
	}

	logger.WithField("template_count", count).Debug("nuclei template validation passed")
	return true, ""
}
