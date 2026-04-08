package tools

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"pentagi/pkg/database"
	"pentagi/pkg/docker"
	"pentagi/pkg/evidence"
	obs "pentagi/pkg/observability"
	"pentagi/pkg/observability/langfuse"

	"github.com/docker/docker/api/types/container"
	"github.com/sirupsen/logrus"
)

// blockedCommandPatterns prevents obviously dangerous commands from executing.
// Note: for a pentesting tool, some dangerous commands are legitimate against targets,
// so this blocklist focuses on host/container-destructive patterns only.
var blockedCommandPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(curl|wget).*\|\s*(ba)?sh`),  // pipe-to-shell
	regexp.MustCompile(`(?i)rm\s+-[a-z]*r[a-z]*f[a-z]*\s+/\s*$`), // rm -rf /
	regexp.MustCompile(`(?i)rm\s+-[a-z]*f[a-z]*r[a-z]*\s+/\s*$`), // rm -fr /
	regexp.MustCompile(`(?i)mkfs\s+/dev/`),                // format disks
	regexp.MustCompile(`(?i):\(\)\{\s*:\|:&\s*\};:`),      // fork bomb
	regexp.MustCompile(`(?i)>\s*/dev/sd[a-z]`),            // overwrite disk devices
	regexp.MustCompile(`(?i)(shutdown|reboot|halt|poweroff)\b`), // system shutdown/reboot
}

func validateCommand(command string) error {
	for _, pattern := range blockedCommandPatterns {
		if pattern.MatchString(command) {
			return fmt.Errorf("command blocked by security policy: matches dangerous pattern %q", pattern.String())
		}
	}
	return nil
}

const (
	defaultExecCommandTimeout = 5 * time.Minute
	defaultExtraExecTimeout   = 5 * time.Second
	defaultQuickCheckTimeout  = 500 * time.Millisecond
)

type execResult struct {
	output string
	err    error
}

type terminal struct {
	mu            sync.Mutex // enforce serial command execution (Fix 13)
	flowID        int64
	taskID        *int64
	subtaskID     *int64
	containerID   int64
	containerLID  string
	dockerClient  docker.DockerClient
	tlp           TermLogProvider
	evidenceStore *evidence.EvidenceStore // Feature 3.5: transparent evidence capture
}

func NewTerminalTool(flowID int64, taskID, subtaskID *int64,
	containerID int64, containerLID string,
	dockerClient docker.DockerClient, tlp TermLogProvider,
) Tool {
	return &terminal{
		flowID:        flowID,
		taskID:        taskID,
		subtaskID:     subtaskID,
		containerID:   containerID,
		containerLID:  containerLID,
		dockerClient:  dockerClient,
		tlp:           tlp,
		evidenceStore: evidence.NewEvidenceStore(),
	}
}

// NewTerminalToolWithEvidence creates a terminal tool with an external EvidenceStore,
// allowing evidence to be shared across tools or retrieved for reporting.
func NewTerminalToolWithEvidence(flowID int64, taskID, subtaskID *int64,
	containerID int64, containerLID string,
	dockerClient docker.DockerClient, tlp TermLogProvider,
	es *evidence.EvidenceStore,
) Tool {
	if es == nil {
		es = evidence.NewEvidenceStore()
	}
	return &terminal{
		flowID:        flowID,
		taskID:        taskID,
		subtaskID:     subtaskID,
		containerID:   containerID,
		containerLID:  containerLID,
		dockerClient:  dockerClient,
		tlp:           tlp,
		evidenceStore: es,
	}
}

// GetEvidenceStore returns the evidence store for this terminal tool,
// allowing callers to retrieve captured evidence for reporting.
func (t *terminal) GetEvidenceStore() *evidence.EvidenceStore {
	return t.evidenceStore
}

func (t *terminal) wrapCommandResult(ctx context.Context, args json.RawMessage, name, result string, err error) (string, error) {
	ctx, observation := obs.Observer.NewObservation(ctx)
	if err != nil {
		observation.Event(
			langfuse.WithEventName("terminal tool error"),
			langfuse.WithEventInput(args),
			langfuse.WithEventStatus(err.Error()),
			langfuse.WithEventLevel(langfuse.ObservationLevelWarning),
			langfuse.WithEventMetadata(langfuse.Metadata{
				"tool_name": name,
				"error":     err.Error(),
			}),
		)

		logrus.WithContext(ctx).WithError(err).WithFields(logrus.Fields{
			"tool":   name,
			"result": result[:min(len(result), 1000)],
		}).Error("terminal tool failed")

		// Prefix with [ERROR] so the system can detect and track tool failures
		// instead of silently converting errors to success strings (Fix 30)
		errMsg := fmt.Sprintf("[ERROR] terminal tool '%s' failed: %v", name, err)
		if result != "" {
			partial := result
			if len(partial) > 4096 {
				partial = partial[:4096]
			}
			errMsg += fmt.Sprintf("\nPartial output:\n%s", partial)
		}
		return errMsg, nil
	}
	return result, nil
}

func (t *terminal) Handle(ctx context.Context, name string, args json.RawMessage) (string, error) {
	logger := logrus.WithContext(ctx).WithFields(enrichLogrusFields(t.flowID, t.taskID, t.subtaskID, logrus.Fields{
		"tool": name,
		"args": string(args),
	}))

	switch name {
	case TerminalToolName:
		var action TerminalAction
		if err := json.Unmarshal(args, &action); err != nil {
			logger.WithError(err).Error("failed to unmarshal terminal action")
			return "", fmt.Errorf("failed to unmarshal terminal action: %w", err)
		}
		timeout := time.Duration(action.Timeout)*time.Second + defaultExtraExecTimeout
		result, err := t.ExecCommand(ctx, action.Cwd, action.Input, action.Detach.Bool(), timeout)
		return t.wrapCommandResult(ctx, args, name, result, err)
	case FileToolName:
		var action FileAction
		if err := json.Unmarshal(args, &action); err != nil {
			logger.WithError(err).Error("failed to unmarshal file action")
			return "", fmt.Errorf("failed to unmarshal file action: %w", err)
		}

		logger = logger.WithFields(logrus.Fields{
			"action": action.Action,
			"path":   action.Path,
		})

		switch action.Action {
		case ReadFile:
			result, err := t.ReadFile(ctx, t.flowID, action.Path)
			return t.wrapCommandResult(ctx, args, name, result, err)
		case UpdateFile:
			if len(action.Content) == 0 {
				return t.wrapCommandResult(ctx, args, name, "",
					fmt.Errorf("file write refused: content is empty. Provide non-empty content for update_file action on path %s", action.Path))
			}
			result, err := t.WriteFile(ctx, t.flowID, action.Content, action.Path)
			return t.wrapCommandResult(ctx, args, name, result, err)
		default:
			logger.Error("unknown file action")
			return "", fmt.Errorf("unknown file action: %s", action.Action)
		}
	default:
		return "", fmt.Errorf("unknown tool: %s", name)
	}
}

func (t *terminal) ExecCommand(
	ctx context.Context,
	cwd, command string,
	detach bool,
	timeout time.Duration,
) (string, error) {
	// Fix 13: enforce serial execution — only one command at a time
	t.mu.Lock()
	defer t.mu.Unlock()

	// Fix 10: validate command against blocklist
	if err := validateCommand(command); err != nil {
		return "", err
	}

	containerName := PrimaryTerminalName(t.flowID)

	// create options for starting the exec process
	cmd := []string{
		"sh",
		"-c",
		command,
	}

	// check if container is running
	isRunning, err := t.dockerClient.IsContainerRunning(ctx, t.containerLID)
	if err != nil {
		return "", fmt.Errorf("failed to inspect container: %w", err)
	}
	if !isRunning {
		return "", fmt.Errorf("container is not running")
	}

	if cwd == "" {
		cwd = docker.WorkFolderPathInContainer
	}

	formattedCommand := FormatTerminalInput(cwd, command)
	_, err = t.tlp.PutMsg(ctx, database.TermlogTypeStdin, formattedCommand, t.containerID, t.taskID, t.subtaskID)
	if err != nil {
		return "", fmt.Errorf("failed to put terminal log (stdin): %w", err)
	}

	maxExecTimeout := 20 * time.Minute
	if timeout <= 0 {
		timeout = defaultExecCommandTimeout
	} else if timeout > maxExecTimeout {
		timeout = maxExecTimeout
	}

	createResp, err := t.dockerClient.ContainerExecCreate(ctx, containerName, container.ExecOptions{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
		WorkingDir:   cwd,
		Tty:          true,
	})
	if err != nil {
		return "", fmt.Errorf("failed to create exec process: %w", err)
	}

	if detach {
		resultChan := make(chan execResult, 1)

		go func() {
			output, err := t.getExecResult(ctx, createResp.ID, timeout)
			resultChan <- execResult{output: output, err: err}
		}()

		select {
		case result := <-resultChan:
			if result.err != nil {
				return "", fmt.Errorf("command failed: %w: %s", result.err, result.output)
			}
			// Feature 3.5: capture evidence transparently for detached commands
			t.captureEvidence(command, result.output)
			if result.output == "" {
				return "Command completed in background with exit code 0", nil
			}
			return result.output, nil
		case <-time.After(defaultQuickCheckTimeout):
			return fmt.Sprintf("Command started in background with timeout %s (still running)", timeout), nil
		}
	}

	output, err := t.getExecResult(ctx, createResp.ID, timeout)
	if err == nil {
		// Feature 3.5: capture evidence transparently — don't modify the returned output
		t.captureEvidence(command, output)
	}
	return output, err
}

// captureEvidence attempts to parse HTTP evidence from a command's output
// and stores it in the evidence store. This is completely transparent —
// it never modifies the output or causes errors visible to the agent.
func (t *terminal) captureEvidence(command, output string) {
	if t.evidenceStore == nil || output == "" {
		return
	}

	// Attempt to detect and parse HTTP evidence from the command/output
	ev := evidence.DetectAndParseHTTP(command, output)
	if ev == nil {
		return
	}

	// Store the evidence — the finding ID will be "_unassigned" initially
	// and can be associated with a finding later during reporting
	t.evidenceStore.Add(*ev)

	logrus.WithFields(logrus.Fields{
		"flow_id": t.flowID,
		"command": command[:min(len(command), 100)],
		"type":    ev.Type,
	}).Debug("evidence captured from terminal output")
}

func (t *terminal) getExecResult(ctx context.Context, id string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// attach to the exec process
	resp, err := t.dockerClient.ContainerExecAttach(ctx, id, container.ExecAttachOptions{
		Tty: true,
	})
	if err != nil {
		return "", fmt.Errorf("failed to attach to exec process: %w", err)
	}
	defer resp.Close()

	const maxOutputSize = 512 * 1024 // 512 KB limit (Fix 11)
	dst := bytes.Buffer{}
	errChan := make(chan error, 1)

	go func() {
		limitedReader := io.LimitReader(resp.Reader, int64(maxOutputSize)+1)
		_, copyErr := io.Copy(&dst, limitedReader)
		errChan <- copyErr
	}()

	select {
	case err := <-errChan:
		if err != nil && err != io.EOF {
			return "", fmt.Errorf("failed to copy output: %w", err)
		}
	case <-ctx.Done():
		// Close the response to unblock io.Copy
		resp.Close()

		// Wait for the copy goroutine to finish
		<-errChan

		result := fmt.Sprintf("temporary output: %s", dst.String())
		return "", fmt.Errorf("timeout value is too low, use greater value if you need so: %w: %s", ctx.Err(), result)
	}

	// wait for the exec process to finish
	_, err = t.dockerClient.ContainerExecInspect(ctx, id)
	if err != nil {
		return "", fmt.Errorf("failed to inspect exec process: %w", err)
	}

	results := dst.String()
	// Fix 11: truncate oversized output
	if len(results) > maxOutputSize {
		results = results[:maxOutputSize] + "\n\n[OUTPUT TRUNCATED: exceeded 512KB limit]"
	}

	formattedResults := FormatTerminalSystemOutput(results)
	_, err = t.tlp.PutMsg(ctx, database.TermlogTypeStdout, formattedResults, t.containerID, t.taskID, t.subtaskID)
	if err != nil {
		return "", fmt.Errorf("failed to put terminal log (stdout): %w", err)
	}

	if results == "" {
		results = "Command completed successfully with exit code 0. No output produced (silent success)"
	}

	return results, nil
}

func (t *terminal) ReadFile(ctx context.Context, flowID int64, path string) (string, error) {
	// Acquire mutex to prevent race conditions with concurrent writes
	t.mu.Lock()
	defer t.mu.Unlock()

	containerName := PrimaryTerminalName(flowID)

	isRunning, err := t.dockerClient.IsContainerRunning(ctx, t.containerLID)
	if err != nil {
		return "", fmt.Errorf("failed to inspect container: %w", err)
	}
	if !isRunning {
		return "", fmt.Errorf("container is not running")
	}

	cwd := docker.WorkFolderPathInContainer
	escapedPath := strings.ReplaceAll(path, "'", "'\"'\"'")
	formattedCommand := FormatTerminalInput(cwd, fmt.Sprintf("cat '%s'", escapedPath))
	_, err = t.tlp.PutMsg(ctx, database.TermlogTypeStdin, formattedCommand, t.containerID, t.taskID, t.subtaskID)
	if err != nil {
		return "", fmt.Errorf("failed to put terminal log (read file cmd): %w", err)
	}

	reader, stats, err := t.dockerClient.CopyFromContainer(ctx, containerName, path)
	if err != nil {
		return "", fmt.Errorf("failed to copy file: %w", err)
	}
	defer reader.Close()

	var buffer strings.Builder
	tarReader := tar.NewReader(reader)
	for {
		tarHeader, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("failed to read tar header: %w", err)
		}

		if tarHeader.FileInfo().IsDir() {
			continue
		}

		if stats.Mode.IsDir() {
			buffer.WriteString("--------------------------------------------------\n")
			buffer.WriteString(
				fmt.Sprintf("'%s' file content (with size %d bytes) keeps bellow:\n",
					tarHeader.Name, tarHeader.Size,
				),
			)
		}

		const maxReadFileSize int64 = 1 * 1024 * 1024 // 1 MB limit (Fix 31: reduced from 100MB)
		if tarHeader.Size > maxReadFileSize {
			return "", fmt.Errorf("file '%s' size %d exceeds maximum allowed size %d (1MB limit for LLM consumption)", tarHeader.Name, tarHeader.Size, maxReadFileSize)
		}
		if tarHeader.Size < 0 {
			return "", fmt.Errorf("file '%s' has invalid size %d", tarHeader.Name, tarHeader.Size)
		}

		var fileContent = make([]byte, tarHeader.Size)
		_, err = tarReader.Read(fileContent)
		if err != nil && err != io.EOF {
			return "", fmt.Errorf("failed to read file '%s' content: %w", tarHeader.Name, err)
		}

		// Fix 31: detect binary files — check first 512 bytes for null bytes
		checkLen := min(len(fileContent), 512)
		for _, b := range fileContent[:checkLen] {
			if b == 0 {
				return fmt.Sprintf("file '%s' appears to be binary (%d bytes), cannot display as text",
					tarHeader.Name, tarHeader.Size), nil
			}
		}

		buffer.Write(fileContent)

		if stats.Mode.IsDir() {
			buffer.WriteString("\n\n")
		}
	}

	content := buffer.String()
	formattedContent := FormatTerminalSystemOutput(content)
	_, err = t.tlp.PutMsg(ctx, database.TermlogTypeStdout, formattedContent, t.containerID, t.taskID, t.subtaskID)
	if err != nil {
		return "", fmt.Errorf("failed to put terminal log (read file content): %w", err)
	}

	return content, nil
}

func (t *terminal) WriteFile(ctx context.Context, flowID int64, content string, path string) (string, error) {
	// Fix 12: restrict write paths to working directory and /tmp/
	cleanPath := filepath.Clean(path)
	if !strings.HasPrefix(cleanPath, docker.WorkFolderPathInContainer) && !strings.HasPrefix(cleanPath, "/tmp/") {
		return "", fmt.Errorf("write path must be within %s or /tmp/, got: %s", docker.WorkFolderPathInContainer, path)
	}
	// Block known sensitive directories even within allowed prefixes
	for _, blocked := range []string{"/etc/", "/proc/", "/sys/", "/root/", "/dev/"} {
		if strings.HasPrefix(cleanPath, blocked) {
			return "", fmt.Errorf("write to sensitive path %q is blocked by security policy", path)
		}
	}

	// Acquire mutex to prevent race conditions with concurrent terminal commands
	t.mu.Lock()
	defer t.mu.Unlock()

	containerName := PrimaryTerminalName(flowID)

	isRunning, err := t.dockerClient.IsContainerRunning(ctx, t.containerLID)
	if err != nil {
		return "", fmt.Errorf("failed to inspect container: %w", err)
	}
	if !isRunning {
		return "", fmt.Errorf("container is not running")
	}

	// put content into a tar archive
	archive := &bytes.Buffer{}
	tarWriter := tar.NewWriter(archive)
	defer tarWriter.Close()

	filename := filepath.Base(path)
	tarHeader := &tar.Header{
		Name:    filename,
		Mode:    0600,
		Size:    int64(len(content)),
		ModTime: time.Now(),
	}
	err = tarWriter.WriteHeader(tarHeader)
	if err != nil {
		return "", fmt.Errorf("failed to write tar header: %w", err)
	}

	_, err = tarWriter.Write([]byte(content))
	if err != nil {
		return "", fmt.Errorf("failed to write tar content: %w", err)
	}

	err = tarWriter.Close()
	if err != nil {
		return "", fmt.Errorf("failed to close tar writer: %w", err)
	}

	dir := filepath.Dir(path)
	err = t.dockerClient.CopyToContainer(ctx, containerName, dir, archive, container.CopyToContainerOptions{
		AllowOverwriteDirWithFile: true,
	})
	if err != nil {
		return "", fmt.Errorf("failed to write file: %w", err)
	}

	// Post-write verification: confirm file exists with expected size
	expectedSize := int64(len(content))
	verifyCmd := fmt.Sprintf("stat -c '%%s' '%s' 2>/dev/null || echo 'FILE_NOT_FOUND'",
		strings.ReplaceAll(path, "'", "'\"'\"'"))
	verifyExec, verifyErr := t.dockerClient.ContainerExecCreate(ctx, containerName, container.ExecOptions{
		Cmd:          []string{"sh", "-c", verifyCmd},
		AttachStdout: true,
		AttachStderr: true,
	})
	if verifyErr == nil {
		verifyCtx, verifyCancel := context.WithTimeout(ctx, 5*time.Second)
		defer verifyCancel()
		verifyResp, attachErr := t.dockerClient.ContainerExecAttach(verifyCtx, verifyExec.ID, container.ExecAttachOptions{})
		if attachErr == nil {
			var verifyBuf bytes.Buffer
			_, _ = io.Copy(&verifyBuf, verifyResp.Reader)
			verifyResp.Close()
			verifyOutput := strings.TrimSpace(verifyBuf.String())

			if verifyOutput == "FILE_NOT_FOUND" || verifyOutput == "" {
				return "", fmt.Errorf("file write verification failed: file not found at %s after write. Use terminal heredoc instead: cat > %s << 'EOF'\n...\nEOF", path, path)
			}

			var actualSize int64
			if _, scanErr := fmt.Sscanf(verifyOutput, "%d", &actualSize); scanErr == nil {
				if actualSize == 0 && expectedSize > 0 {
					return "", fmt.Errorf("[ERROR] file write produced 0-byte file at %s (expected %s). Use terminal heredoc instead: cat > %s << 'EOF'\n...\nEOF",
						path, formatByteSize(expectedSize), path)
				}
				logrus.WithFields(logrus.Fields{
					"flow_id":       t.flowID,
					"path":          path,
					"expected_size": expectedSize,
					"actual_size":   actualSize,
				}).Debug("file write verification passed")
			}
		}
	}

	formattedCommand := FormatTerminalSystemOutput(fmt.Sprintf("Wrote to %s (%s)", path, formatByteSize(expectedSize)))
	_, err = t.tlp.PutMsg(ctx, database.TermlogTypeStdin, formattedCommand, t.containerID, t.taskID, t.subtaskID)
	if err != nil {
		return "", fmt.Errorf("failed to put terminal log (write file cmd): %w", err)
	}

	return fmt.Sprintf("File written: %s (%s)", path, formatByteSize(expectedSize)), nil
}

func PrimaryTerminalName(flowID int64) string {
	return fmt.Sprintf("pentagi-terminal-%d", flowID)
}

func FormatTerminalInput(cwd, text string) string {
	yellow := "\033[33m" // ANSI escape code for yellow color
	reset := "\033[0m"   // ANSI escape code to reset color
	return fmt.Sprintf("%s $ %s%s%s\r\n", cwd, yellow, text, reset)
}

func FormatTerminalSystemOutput(text string) string {
	blue := "\033[34m" // ANSI escape code for blue color
	reset := "\033[0m" // ANSI escape code to reset color
	return fmt.Sprintf("%s%s%s\r\n", blue, text, reset)
}

// formatByteSize returns a human-readable byte size string.
func formatByteSize(size int64) string {
	if size < 1024 {
		return fmt.Sprintf("%d bytes", size)
	} else if size < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(size)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(size)/(1024*1024))
}

func (t *terminal) IsAvailable() bool {
	return t.dockerClient != nil
}

// FileInfo describes a file found in the workspace container directory.
type FileInfo struct {
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	Modified string `json:"modified"`
}

// ListWorkspaceFiles lists files in the container's working directory (up to maxdepth 2).
// It executes `find` inside the container and parses the output into FileInfo structs.
func ListWorkspaceFiles(
	ctx context.Context,
	dockerClient docker.DockerClient,
	containerName string,
	containerLID string,
	workdir string,
) ([]FileInfo, error) {
	if workdir == "" {
		workdir = docker.WorkFolderPathInContainer
	}

	// Check if container is running
	isRunning, err := dockerClient.IsContainerRunning(ctx, containerLID)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container: %w", err)
	}
	if !isRunning {
		return nil, fmt.Errorf("container is not running")
	}

	// Use find with -printf to get path, size, and modification time in one shot
	// Format: size_in_bytes\tmodified_time\tpath\n
	cmd := []string{
		"sh", "-c",
		fmt.Sprintf(`find '%s' -maxdepth 2 -type f -printf '%%s\t%%TY-%%Tm-%%Td %%TH:%%TM\t%%p\n' 2>/dev/null | head -100`,
			strings.ReplaceAll(workdir, "'", "'\\''")),
	}

	createResp, err := dockerClient.ContainerExecCreate(ctx, containerName, container.ExecOptions{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
		WorkingDir:   workdir,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create exec for file listing: %w", err)
	}

	execCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resp, err := dockerClient.ContainerExecAttach(execCtx, createResp.ID, container.ExecAttachOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to attach to exec for file listing: %w", err)
	}
	defer resp.Close()

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, resp.Reader)

	output := buf.String()
	if output == "" {
		return nil, nil // empty workspace
	}

	var files []FileInfo
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "\t", 3)
		if len(parts) != 3 {
			continue
		}

		var size int64
		if _, err := fmt.Sscanf(parts[0], "%d", &size); err != nil {
			size = 0
		}

		files = append(files, FileInfo{
			Path:     parts[2],
			Size:     size,
			Modified: parts[1],
		})
	}

	return files, nil
}

// RescuedFile represents a file rescued from a container before it's destroyed.
type RescuedFile struct {
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	Content string `json:"content"`
}

// RescueContainerFiles rescues evidence files from a container's filesystem.
// It scans /work/, /tmp/, and /root/ for files matching evidence patterns
// (*.md, *.txt, *.json, *.html, *.xml, *.csv) and reads their contents.
// This is called during subtask expiration to preserve work products before
// the container is destroyed. Callers must provide a properly-timed context
// (e.g., context.WithTimeout(context.Background(), 30*time.Second)) since
// the parent subtask context is typically already expired.
func RescueContainerFiles(
	ctx context.Context,
	dockerClient docker.DockerClient,
	containerName string,
	containerLID string,
) ([]RescuedFile, error) {
	// Use the caller-provided context directly — callers are responsible for
	// setting an appropriate timeout (typically 30s via context.WithTimeout).
	rescueCtx := ctx

	// Check if container is still running
	isRunning, err := dockerClient.IsContainerRunning(rescueCtx, containerLID)
	if err != nil || !isRunning {
		return nil, fmt.Errorf("container not available for rescue: running=%v, err=%v", isRunning, err)
	}

	// Find evidence files across all key directories
	// Extensions that typically contain evidence/results
	cmd := []string{
		"sh", "-c",
		`find /work/ /tmp/ /root/ -maxdepth 3 -type f \( ` +
			`-name '*.md' -o -name '*.txt' -o -name '*.json' -o ` +
			`-name '*.html' -o -name '*.xml' -o -name '*.csv' -o ` +
			`-name '*.log' -o -name 'FINDINGS*' -o -name 'RESULTS*' -o ` +
			`-name 'attack_results*' -o -name 'evidence*' -o -name 'report*' ` +
			`\) -printf '%s\t%p\n' 2>/dev/null | head -50`,
	}

	createResp, err := dockerClient.ContainerExecCreate(rescueCtx, containerName, container.ExecOptions{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create exec for file rescue: %w", err)
	}

	resp, err := dockerClient.ContainerExecAttach(rescueCtx, createResp.ID, container.ExecAttachOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to attach to exec for file rescue: %w", err)
	}
	defer resp.Close()

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, resp.Reader)

	output := buf.String()
	if output == "" {
		return nil, nil // no evidence files found
	}

	// Parse the file listing
	type fileEntry struct {
		path string
		size int64
	}
	var entries []fileEntry
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		var size int64
		if _, err := fmt.Sscanf(parts[0], "%d", &size); err != nil {
			size = 0
		}
		// Skip files that are too large (>256KB) or empty
		if size == 0 || size > 256*1024 {
			continue
		}
		entries = append(entries, fileEntry{path: parts[1], size: size})
	}

	if len(entries) == 0 {
		return nil, nil
	}

	// Read each file's content using CopyFromContainer
	var rescued []RescuedFile
	const maxTotalSize = 512 * 1024 // 512KB total budget for all rescued files
	totalSize := int64(0)

	for _, entry := range entries {
		if totalSize+entry.size > maxTotalSize {
			break // budget exhausted
		}

		reader, _, err := dockerClient.CopyFromContainer(rescueCtx, containerName, entry.path)
		if err != nil {
			logrus.WithError(err).WithField("path", entry.path).
				Debug("rescue: failed to copy file from container")
			continue
		}

		// Read tar content
		tarReader := tar.NewReader(reader)
		var content string
		for {
			tarHeader, err := tarReader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				break
			}
			if tarHeader.FileInfo().IsDir() {
				continue
			}

			fileContent := make([]byte, tarHeader.Size)
			_, err = io.ReadFull(tarReader, fileContent)
			if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
				break
			}

			// Check for binary content
			checkLen := min(len(fileContent), 512)
			isBinary := false
			for _, b := range fileContent[:checkLen] {
				if b == 0 {
					isBinary = true
					break
				}
			}
			if isBinary {
				break
			}

			content = string(fileContent)
			break // only read first file in tar
		}
		reader.Close()

		if content == "" {
			continue
		}

		rescued = append(rescued, RescuedFile{
			Path:    entry.path,
			Size:    entry.size,
			Content: content,
		})
		totalSize += entry.size
	}

	return rescued, nil
}
