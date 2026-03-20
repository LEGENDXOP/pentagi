package tools

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"pentagi/pkg/database"
	"pentagi/pkg/docker"

	"github.com/docker/docker/api/types/container"
	"github.com/sirupsen/logrus"
)

const (
	raceConditionDefaultConcurrency = 10
	raceConditionMinConcurrency     = 2
	raceConditionMaxConcurrency     = 50
	raceConditionDefaultRounds      = 3
	raceConditionMinRounds          = 1
	raceConditionMaxRounds          = 10
	raceConditionExecTimeout        = 120 * time.Second
	raceConditionScriptPath         = "/work/.race_condition_test.py"
)

// raceConditionPythonScript is embedded in Go so it can be deployed to the container on first use.
// It uses asyncio + aiohttp to fire concurrent HTTP requests and analyse responses for race conditions.
const raceConditionPythonScript = `#!/usr/bin/env python3
"""Race condition / TOCTOU tester — fires concurrent HTTP requests and analyses responses."""

import argparse
import asyncio
import json
import sys
import time

try:
    import aiohttp
except ImportError:
    print("NEED_AIOHTTP", flush=True)
    sys.exit(99)


async def send_request(session, url, method, headers, body, req_id):
    """Send a single request and capture timing + response details."""
    start = time.monotonic()
    try:
        async with session.request(
            method, url, headers=headers, data=body, ssl=False, timeout=aiohttp.ClientTimeout(total=15)
        ) as resp:
            elapsed = time.monotonic() - start
            resp_body = await resp.text()
            return {
                "id": req_id,
                "status": resp.status,
                "elapsed_ms": round(elapsed * 1000, 2),
                "body_length": len(resp_body),
                "body_snippet": resp_body[:500] if resp_body else "",
                "headers": dict(resp.headers),
            }
    except Exception as exc:
        elapsed = time.monotonic() - start
        return {
            "id": req_id,
            "status": -1,
            "elapsed_ms": round(elapsed * 1000, 2),
            "error": str(exc),
            "body_length": 0,
            "body_snippet": "",
            "headers": {},
        }


async def run_round(url, method, headers, body, concurrency, round_num):
    """Run one round of concurrent requests."""
    connector = aiohttp.TCPConnector(limit=0, force_close=True)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            send_request(session, url, method, headers, body, f"r{round_num}_req{i}")
            for i in range(concurrency)
        ]
        results = await asyncio.gather(*tasks)
    return list(results)


def analyse_results(all_rounds):
    """Analyse responses across rounds for race condition indicators."""
    analysis = {
        "total_requests": 0,
        "status_distribution": {},
        "timing_stats": {"min_ms": float("inf"), "max_ms": 0, "avg_ms": 0},
        "unique_body_lengths": set(),
        "unique_status_codes": set(),
        "error_count": 0,
        "anomalies": [],
    }

    all_timings = []
    body_snippets = []

    for round_results in all_rounds:
        for r in round_results:
            analysis["total_requests"] += 1
            code = r.get("status", -1)
            analysis["unique_status_codes"].add(code)
            analysis["status_distribution"][str(code)] = (
                analysis["status_distribution"].get(str(code), 0) + 1
            )
            elapsed = r.get("elapsed_ms", 0)
            all_timings.append(elapsed)
            analysis["unique_body_lengths"].add(r.get("body_length", 0))
            if r.get("error"):
                analysis["error_count"] += 1
            body_snippets.append(r.get("body_snippet", ""))

    if all_timings:
        analysis["timing_stats"]["min_ms"] = round(min(all_timings), 2)
        analysis["timing_stats"]["max_ms"] = round(max(all_timings), 2)
        analysis["timing_stats"]["avg_ms"] = round(sum(all_timings) / len(all_timings), 2)

    # Detect anomalies
    if len(analysis["unique_status_codes"]) > 1:
        analysis["anomalies"].append(
            f"Multiple status codes observed: {sorted(analysis['unique_status_codes'])} — possible race condition"
        )
    if len(analysis["unique_body_lengths"]) > 2:
        analysis["anomalies"].append(
            f"Response body length varies ({len(analysis['unique_body_lengths'])} distinct sizes) — possible state inconsistency"
        )
    if all_timings:
        spread = max(all_timings) - min(all_timings)
        if spread > 500:
            analysis["anomalies"].append(
                f"High timing spread ({round(spread, 1)}ms) — some requests may have been serialised by a lock"
            )

    # Check for duplicate resource creation (same 201 Created responses)
    created_count = analysis["status_distribution"].get("201", 0)
    if created_count > 1:
        analysis["anomalies"].append(
            f"{created_count} requests returned 201 Created — possible duplicate resource creation (TOCTOU)"
        )

    # Check for mixed success/failure that hints at single-use tokens or balances
    ok_count = analysis["status_distribution"].get("200", 0)
    fail_count = sum(
        v for k, v in analysis["status_distribution"].items() if k.startswith("4")
    )
    if ok_count >= 1 and fail_count >= 1 and analysis["total_requests"] > 2:
        analysis["anomalies"].append(
            f"{ok_count} succeeded vs {fail_count} client errors — may indicate a one-time-use resource was consumed by multiple concurrent requests"
        )

    # Convert sets to lists for JSON
    analysis["unique_body_lengths"] = sorted(analysis["unique_body_lengths"])
    analysis["unique_status_codes"] = sorted(analysis["unique_status_codes"])

    return analysis


async def main():
    parser = argparse.ArgumentParser(description="Race condition tester")
    parser.add_argument("--url", required=True)
    parser.add_argument("--method", default="POST")
    parser.add_argument("--headers", default="{}")
    parser.add_argument("--body", default="")
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--rounds", type=int, default=3)
    args = parser.parse_args()

    headers = json.loads(args.headers) if args.headers else {}

    all_rounds = []
    for rnd in range(1, args.rounds + 1):
        results = await run_round(
            args.url, args.method, headers, args.body, args.concurrency, rnd
        )
        all_rounds.append(results)

    analysis = analyse_results(all_rounds)

    output = {
        "target": args.url,
        "method": args.method,
        "concurrency": args.concurrency,
        "rounds": args.rounds,
        "analysis": analysis,
        "rounds_detail": [
            [
                {
                    "id": r["id"],
                    "status": r["status"],
                    "elapsed_ms": r["elapsed_ms"],
                    "body_length": r["body_length"],
                    "body_snippet": r.get("body_snippet", "")[:200],
                    "error": r.get("error", ""),
                }
                for r in rnd
            ]
            for rnd in all_rounds
        ],
    }

    print("RACE_RESULT_JSON:" + json.dumps(output))


if __name__ == "__main__":
    asyncio.run(main())
`

// raceConditionTool implements the race condition / TOCTOU testing tool.
type raceConditionTool struct {
	flowID       int64
	taskID       *int64
	subtaskID    *int64
	containerID  int64
	containerLID string
	dockerClient docker.DockerClient
	tlp          TermLogProvider
}

// NewRaceConditionTool creates a new race condition testing tool instance.
func NewRaceConditionTool(
	flowID int64,
	taskID, subtaskID *int64,
	containerID int64,
	containerLID string,
	dockerClient docker.DockerClient,
	tlp TermLogProvider,
) Tool {
	return &raceConditionTool{
		flowID:       flowID,
		taskID:       taskID,
		subtaskID:    subtaskID,
		containerID:  containerID,
		containerLID: containerLID,
		dockerClient: dockerClient,
		tlp:          tlp,
	}
}

// IsAvailable returns true if Docker is available for running the test.
func (rc *raceConditionTool) IsAvailable() bool {
	return rc.dockerClient != nil
}

// Handle processes a race_condition_test tool call.
func (rc *raceConditionTool) Handle(ctx context.Context, name string, args json.RawMessage) (string, error) {
	var action RaceConditionAction
	logger := logrus.WithContext(ctx).WithFields(enrichLogrusFields(rc.flowID, rc.taskID, rc.subtaskID, logrus.Fields{
		"tool": name,
		"args": string(args),
	}))

	if err := json.Unmarshal(args, &action); err != nil {
		logger.WithError(err).Error("failed to unmarshal race_condition_test action")
		return "", fmt.Errorf("failed to unmarshal race_condition_test action arguments: %w", err)
	}

	targetURL := strings.TrimSpace(action.TargetURL)
	if targetURL == "" {
		return "error: target_url is required", nil
	}

	method := strings.TrimSpace(action.Method)
	if method == "" {
		method = "POST"
	}
	method = strings.ToUpper(method)

	concurrency := action.ConcurrentRequests.Int()
	if concurrency < raceConditionMinConcurrency {
		concurrency = raceConditionDefaultConcurrency
	}
	if concurrency > raceConditionMaxConcurrency {
		concurrency = raceConditionMaxConcurrency
	}

	rounds := action.Rounds.Int()
	if rounds < raceConditionMinRounds {
		rounds = raceConditionDefaultRounds
	}
	if rounds > raceConditionMaxRounds {
		rounds = raceConditionMaxRounds
	}

	headers := strings.TrimSpace(action.Headers)
	if headers == "" {
		headers = "{}"
	}

	body := action.Body

	containerName := PrimaryTerminalName(rc.flowID)

	// Log the action to terminal
	cmdSummary := fmt.Sprintf("race_condition_test: %s %s (concurrency=%d, rounds=%d)", method, targetURL, concurrency, rounds)
	formattedCmd := FormatTerminalInput(docker.WorkFolderPathInContainer, cmdSummary)
	if _, err := rc.tlp.PutMsg(ctx, database.TermlogTypeStdin, formattedCmd, rc.containerID, rc.taskID, rc.subtaskID); err != nil {
		logger.WithError(err).Warn("failed to put terminal log for race condition command")
	}

	// Step 1: Deploy the Python script to the container if not already present
	if err := rc.deployScript(ctx, containerName, logger); err != nil {
		errMsg := fmt.Sprintf("[ERROR] Failed to deploy race condition test script: %v", err)
		rc.logOutput(ctx, errMsg)
		return errMsg, nil
	}

	// Step 2: Ensure aiohttp is installed
	if err := rc.ensureAiohttp(ctx, containerName, logger); err != nil {
		errMsg := fmt.Sprintf("[ERROR] Failed to install aiohttp: %v.\n\nFallback: you can run a basic race test with:\n"+
			"  for i in $(seq 1 %d); do curl -s -o /dev/null -w '%%{http_code} %%{time_total}\\n' -X %s '%s' & done; wait",
			concurrency, method, targetURL)
		rc.logOutput(ctx, errMsg)
		return errMsg, nil
	}

	// Step 3: Execute the race condition test
	escapedURL := shellQuote(targetURL)
	escapedHeaders := shellQuote(headers)
	escapedBody := shellQuote(body)
	runCmd := fmt.Sprintf(
		"python3 %s --url %s --method %s --headers %s --body %s --concurrency %d --rounds %d 2>&1",
		raceConditionScriptPath, escapedURL, method, escapedHeaders, escapedBody, concurrency, rounds,
	)

	output, err := rc.execInContainer(ctx, containerName, runCmd, raceConditionExecTimeout)
	if err != nil {
		errMsg := fmt.Sprintf("[ERROR] Race condition test execution failed: %v\nOutput: %s", err, truncate(output, 2048))
		rc.logOutput(ctx, errMsg)
		return errMsg, nil
	}

	// Step 4: Parse results
	result := rc.parseAndFormatResults(output, targetURL, method, concurrency, rounds)

	// Log results to terminal
	rc.logOutput(ctx, result)

	logger.WithFields(logrus.Fields{
		"target":      targetURL,
		"method":      method,
		"concurrency": concurrency,
		"rounds":      rounds,
	}).Info("race condition test completed")

	return result, nil
}

// deployScript writes the embedded Python script into the container.
func (rc *raceConditionTool) deployScript(ctx context.Context, containerName string, logger *logrus.Entry) error {
	// Check if script already exists and is the same size (fast path)
	checkCmd := fmt.Sprintf("test -f %s && echo EXISTS || echo MISSING", raceConditionScriptPath)
	checkOutput, _ := rc.execInContainer(ctx, containerName, checkCmd, 5*time.Second)
	if strings.Contains(checkOutput, "EXISTS") {
		return nil
	}

	// Write the script using heredoc via sh -c
	// We base64-encode to avoid shell escaping issues with the Python source
	writeCmd := fmt.Sprintf("cat > %s << 'RACESCRIPT_EOF'\n%s\nRACESCRIPT_EOF\nchmod +x %s",
		raceConditionScriptPath, raceConditionPythonScript, raceConditionScriptPath)
	_, err := rc.execInContainer(ctx, containerName, writeCmd, 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to write script to container: %w", err)
	}

	logger.Info("deployed race condition test script to container")
	return nil
}

// ensureAiohttp checks that aiohttp is available and installs it if needed.
func (rc *raceConditionTool) ensureAiohttp(ctx context.Context, containerName string, logger *logrus.Entry) error {
	// Quick check: try importing aiohttp
	checkCmd := "python3 -c 'import aiohttp' 2>&1 && echo AIOHTTP_OK || echo AIOHTTP_MISSING"
	output, err := rc.execInContainer(ctx, containerName, checkCmd, 10*time.Second)
	if err == nil && strings.Contains(output, "AIOHTTP_OK") {
		return nil
	}

	logger.Info("aiohttp not found, installing via pip3")
	installCmd := "pip3 install --quiet --disable-pip-version-check aiohttp 2>&1 && python3 -c 'import aiohttp' && echo INSTALL_OK || echo INSTALL_FAILED"
	installOutput, installErr := rc.execInContainer(ctx, containerName, installCmd, 60*time.Second)
	if installErr != nil || strings.Contains(installOutput, "INSTALL_FAILED") {
		return fmt.Errorf("aiohttp installation failed: %s", truncate(installOutput, 500))
	}

	logger.Info("aiohttp installed successfully")
	return nil
}

// execInContainer runs a command in the container and returns stdout+stderr.
func (rc *raceConditionTool) execInContainer(ctx context.Context, containerName, command string, timeout time.Duration) (string, error) {
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	createResp, err := rc.dockerClient.ContainerExecCreate(execCtx, containerName, container.ExecOptions{
		Cmd:          []string{"sh", "-c", command},
		AttachStdout: true,
		AttachStderr: true,
		WorkingDir:   docker.WorkFolderPathInContainer,
	})
	if err != nil {
		return "", fmt.Errorf("failed to create exec: %w", err)
	}

	resp, err := rc.dockerClient.ContainerExecAttach(execCtx, createResp.ID, container.ExecAttachOptions{
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

// logOutput writes a message to the terminal log provider.
func (rc *raceConditionTool) logOutput(ctx context.Context, msg string) {
	if rc.tlp == nil {
		return
	}
	formatted := FormatTerminalSystemOutput(msg)
	_, _ = rc.tlp.PutMsg(ctx, database.TermlogTypeStdout, formatted, rc.containerID, rc.taskID, rc.subtaskID)
}

// parseAndFormatResults parses the JSON output from the Python script and formats it as markdown.
func (rc *raceConditionTool) parseAndFormatResults(output, targetURL, method string, concurrency, rounds int) string {
	// Find the JSON result line
	var resultJSON string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "RACE_RESULT_JSON:") {
			resultJSON = strings.TrimPrefix(line, "RACE_RESULT_JSON:")
			break
		}
	}

	if resultJSON == "" {
		// No structured output — return raw output with context
		return fmt.Sprintf("# Race Condition Test Results\n\n"+
			"**Target:** `%s`\n"+
			"**Method:** %s\n"+
			"**Concurrency:** %d\n"+
			"**Rounds:** %d\n\n"+
			"## Raw Output\n\n"+
			"The test script did not produce structured output. Raw output:\n\n```\n%s\n```\n\n"+
			"This may indicate the script failed to execute. Check that the target is reachable.",
			targetURL, method, concurrency, rounds, truncate(output, 4096))
	}

	// Parse structured results
	var result struct {
		Target      string `json:"target"`
		Method      string `json:"method"`
		Concurrency int    `json:"concurrency"`
		Rounds      int    `json:"rounds"`
		Analysis    struct {
			TotalRequests    int               `json:"total_requests"`
			StatusDist       map[string]int    `json:"status_distribution"`
			TimingStats      map[string]float64 `json:"timing_stats"`
			UniqueBodyLens   []int             `json:"unique_body_lengths"`
			UniqueStatusCodes []int            `json:"unique_status_codes"`
			ErrorCount       int               `json:"error_count"`
			Anomalies        []string          `json:"anomalies"`
		} `json:"analysis"`
		RoundsDetail [][]struct {
			ID          string  `json:"id"`
			Status      int     `json:"status"`
			ElapsedMs   float64 `json:"elapsed_ms"`
			BodyLength  int     `json:"body_length"`
			BodySnippet string  `json:"body_snippet"`
			Error       string  `json:"error"`
		} `json:"rounds_detail"`
	}

	if err := json.Unmarshal([]byte(resultJSON), &result); err != nil {
		return fmt.Sprintf("# Race Condition Test Results\n\n"+
			"**Target:** `%s`\n\n"+
			"⚠ Failed to parse structured results: %v\n\nRaw: ```\n%s\n```",
			targetURL, err, truncate(resultJSON, 2048))
	}

	var sb strings.Builder
	a := result.Analysis

	sb.WriteString("# Race Condition Test Results\n\n")
	sb.WriteString(fmt.Sprintf("**Target:** `%s`\n", result.Target))
	sb.WriteString(fmt.Sprintf("**Method:** %s\n", result.Method))
	sb.WriteString(fmt.Sprintf("**Concurrency:** %d requests per round\n", result.Concurrency))
	sb.WriteString(fmt.Sprintf("**Rounds:** %d\n", result.Rounds))
	sb.WriteString(fmt.Sprintf("**Total Requests Sent:** %d\n\n", a.TotalRequests))

	// Anomalies (most important section)
	if len(a.Anomalies) > 0 {
		sb.WriteString("## 🚨 Anomalies Detected\n\n")
		for _, anomaly := range a.Anomalies {
			sb.WriteString(fmt.Sprintf("- **%s**\n", anomaly))
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("## ✅ No Obvious Race Condition Indicators\n\n")
		sb.WriteString("All responses were consistent across concurrent requests. ")
		sb.WriteString("This does not definitively rule out race conditions — consider testing with different payloads or endpoints.\n\n")
	}

	// Status distribution
	sb.WriteString("## Response Status Distribution\n\n")
	for code, count := range a.StatusDist {
		sb.WriteString(fmt.Sprintf("- **HTTP %s:** %d responses\n", code, count))
	}
	sb.WriteString("\n")

	// Timing analysis
	sb.WriteString("## Timing Analysis\n\n")
	sb.WriteString(fmt.Sprintf("- **Fastest:** %.2f ms\n", a.TimingStats["min_ms"]))
	sb.WriteString(fmt.Sprintf("- **Slowest:** %.2f ms\n", a.TimingStats["max_ms"]))
	sb.WriteString(fmt.Sprintf("- **Average:** %.2f ms\n", a.TimingStats["avg_ms"]))
	spread := a.TimingStats["max_ms"] - a.TimingStats["min_ms"]
	sb.WriteString(fmt.Sprintf("- **Spread:** %.2f ms\n\n", spread))

	// Error count
	if a.ErrorCount > 0 {
		sb.WriteString(fmt.Sprintf("## ⚠ Errors: %d/%d requests failed\n\n", a.ErrorCount, a.TotalRequests))
	}

	// Response body length variation
	if len(a.UniqueBodyLens) > 1 {
		sb.WriteString("## Response Body Length Variation\n\n")
		sb.WriteString(fmt.Sprintf("Distinct body sizes: %v\n\n", a.UniqueBodyLens))
	}

	// Round details (condensed)
	sb.WriteString("## Round-by-Round Summary\n\n")
	for ri, rnd := range result.RoundsDetail {
		sb.WriteString(fmt.Sprintf("### Round %d\n\n", ri+1))
		sb.WriteString("| Request | Status | Time (ms) | Body Len |\n")
		sb.WriteString("|---------|--------|-----------|----------|\n")
		for _, r := range rnd {
			status := fmt.Sprintf("%d", r.Status)
			if r.Error != "" {
				status = "ERR"
			}
			sb.WriteString(fmt.Sprintf("| %s | %s | %.1f | %d |\n", r.ID, status, r.ElapsedMs, r.BodyLength))
		}
		sb.WriteString("\n")
	}

	// Sample response bodies (first different ones)
	sb.WriteString("## Sample Response Bodies\n\n")
	seenSnippets := make(map[string]bool)
	snippetCount := 0
	for _, rnd := range result.RoundsDetail {
		for _, r := range rnd {
			snippet := r.BodySnippet
			if snippet == "" || seenSnippets[snippet] {
				continue
			}
			seenSnippets[snippet] = true
			snippetCount++
			if snippetCount > 3 {
				break
			}
			sb.WriteString(fmt.Sprintf("**%s (HTTP %d):**\n```\n%s\n```\n\n", r.ID, r.Status, truncate(snippet, 300)))
		}
		if snippetCount > 3 {
			break
		}
	}

	return sb.String()
}

// truncate shortens a string to maxLen, appending "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
