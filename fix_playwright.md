# Fix: playwright-extra Missing in Kali Container

## Root Cause

The `ensureServer()` method in `browser_playwright.go` tries to install playwright dependencies at runtime using `npm install`. However, the `vxcontrol/kali-linux` Docker image has Node.js v22 but **no npm**. Without npm, the entire dependency installation chain fails silently, and the browser server never starts.

Additionally, `browser_install_blocker.go` blocks the AI agent from running `npm install playwright` or `apt install chromium` commands — but this blocker only affects commands the **AI agent** sends via the terminal tool. The blocker does **not** affect `ensureServer()` (which runs via `execInContainer` directly). So the blocker is not the direct cause, but it prevents the agent from self-recovering.

## Chain of Failure

```
ensureServer() → "which node" → OK (v22 found)
              → skip apt install nodejs npm (node found)
              → "test -d /work/.browser-pkg/node_modules" → MISSING
              → "npm install --no-audit ..." → FAILS (npm: command not found)
              → returns error → browser tool reports [ERROR]
```

The key bug: `ensureServer()` checks for `node` but never checks for `npm`. Node exists, so it skips the `apt-get install nodejs npm` step. Then `npm install` fails because npm isn't there.

## Fix Strategy: Multi-Layered (Recommended)

### Fix 1: Custom Docker Image (PRIMARY FIX — Most Reliable)

Create a custom image `pentagi-kali` that extends `vxcontrol/kali-linux` with all browser deps pre-installed. This eliminates runtime installation entirely.

**File: `docker/Dockerfile.kali`**
```dockerfile
FROM vxcontrol/kali-linux

# Install npm (missing from base image) and browser dependencies
RUN apt-get update -qq && \
    apt-get install -y -qq npm curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Pre-install playwright and stealth plugin globally
RUN mkdir -p /opt/pentagi-browser && \
    cd /opt/pentagi-browser && \
    echo '{"name":"pentagi-browser","version":"1.0.0","dependencies":{"playwright-extra":"^4.3.6","puppeteer-extra-plugin-stealth":"^2.11.2","playwright-core":"^1.49.0","playwright":"^1.49.0"}}' > package.json && \
    npm install --no-audit --no-fund && \
    npx playwright install chromium --with-deps && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /root/.cache

# Set NODE_PATH so scripts can find pre-installed modules
ENV NODE_PATH=/opt/pentagi-browser/node_modules
```

**Build & Push:**
```bash
cd /home/legendx/Coding/pentagi
docker build -f docker/Dockerfile.kali -t pentagi-kali:latest .

# Optionally push to Docker Hub for multi-host setups:
# docker tag pentagi-kali:latest vxcontrol/pentagi-kali:latest
# docker push vxcontrol/pentagi-kali:latest
```

**Config change (`.env`):**
```env
# Before:
DOCKER_DEFAULT_IMAGE_FOR_PENTEST=vxcontrol/kali-linux

# After:
DOCKER_DEFAULT_IMAGE_FOR_PENTEST=pentagi-kali:latest
```

That's it for the simplest path. But the Go code also needs hardening so it doesn't break if someone uses a different base image.

---

### Fix 2: Go Code — Fix `ensureServer()` to Check for npm (REQUIRED)

The current code checks for `node` but not `npm`. If node is found, it skips installation entirely. Fix: also check for npm, and install it if missing.

**File: `backend/pkg/tools/browser_playwright.go`**

Replace the Node.js check block in `ensureServer()`:

```go
// CURRENT CODE (BROKEN):
	// Check if Node.js is available
	nodeCheck, err := bp.execInContainer(ctx, containerName, "which node 2>/dev/null || echo 'NOT_FOUND'", 10*time.Second)
	if err != nil || strings.Contains(nodeCheck, "NOT_FOUND") {
		logger.Info("Node.js not found, installing...")
		installCmd := "apt-get update -qq && apt-get install -y -qq nodejs npm > /dev/null 2>&1 && which node"
		installResult, installErr := bp.execInContainer(ctx, containerName, installCmd, playwrightInstallTimeout)
		if installErr != nil || !strings.Contains(installResult, "/node") {
			return fmt.Errorf("failed to install Node.js: %v (output: %s)", installErr, installResult)
		}
		logger.Info("Node.js installed successfully")
	}
```

```go
// FIXED CODE:
	// Check if Node.js AND npm are available (kali-linux has node but not npm)
	nodeCheck, err := bp.execInContainer(ctx, containerName, "which node 2>/dev/null || echo 'NOT_FOUND'", 10*time.Second)
	npmCheck, _ := bp.execInContainer(ctx, containerName, "which npm 2>/dev/null || echo 'NOT_FOUND'", 10*time.Second)
	
	needsInstall := err != nil || strings.Contains(nodeCheck, "NOT_FOUND") || strings.Contains(npmCheck, "NOT_FOUND")
	if needsInstall {
		var missingPkgs []string
		if strings.Contains(nodeCheck, "NOT_FOUND") {
			missingPkgs = append(missingPkgs, "nodejs")
		}
		if strings.Contains(npmCheck, "NOT_FOUND") {
			missingPkgs = append(missingPkgs, "npm")
		}
		logger.WithField("missing", missingPkgs).Info("Installing missing packages...")
		installCmd := fmt.Sprintf("apt-get update -qq && apt-get install -y -qq %s > /dev/null 2>&1 && which node && which npm",
			strings.Join(missingPkgs, " "))
		installResult, installErr := bp.execInContainer(ctx, containerName, installCmd, playwrightInstallTimeout)
		if installErr != nil || !strings.Contains(installResult, "/node") {
			return fmt.Errorf("failed to install Node.js/npm: %v (output: %s)", installErr, installResult)
		}
		logger.Info("Node.js/npm installed successfully")
	}
```

### Fix 3: Go Code — Use Pre-installed Modules When Available (REQUIRED)

When using the custom image with pre-installed modules at `/opt/pentagi-browser/node_modules`, skip the npm install step entirely.

Add this check **before** the "Check if node_modules already exists" block:

```go
// CURRENT CODE:
	// Check if node_modules already exists
	checkModules, _ := bp.execInContainer(ctx, containerName, fmt.Sprintf("test -d %s && echo 'EXISTS' || echo 'MISSING'", playwrightNodeModulesDir), 5*time.Second)
	if strings.Contains(checkModules, "MISSING") {
		// ... npm install ...
	}
```

```go
// FIXED CODE:
	// Check for pre-installed modules first (custom pentagi-kali image),
	// then fall back to /work/.browser-pkg/node_modules
	preinstalledModules := "/opt/pentagi-browser/node_modules"
	checkPreinstalled, _ := bp.execInContainer(ctx, containerName,
		fmt.Sprintf("test -d %s && echo 'EXISTS' || echo 'MISSING'", preinstalledModules), 5*time.Second)

	useNodeModulesDir := playwrightNodeModulesDir // default: /work/.browser-pkg/node_modules
	if strings.Contains(checkPreinstalled, "EXISTS") {
		logger.Info("Using pre-installed Playwright modules from image")
		useNodeModulesDir = preinstalledModules
	} else {
		// Check if node_modules already exists at work dir
		checkModules, _ := bp.execInContainer(ctx, containerName,
			fmt.Sprintf("test -d %s && echo 'EXISTS' || echo 'MISSING'", playwrightNodeModulesDir), 5*time.Second)
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
```

Then update the server start command to use `useNodeModulesDir`:

```go
	// Start the server — use the resolved node_modules path
	startCmd := fmt.Sprintf(
		"cd /work/.browser-pkg && BROWSER_PORT=%d BROWSER_TIMEOUT=%d NODE_PATH=%s nohup node %s > %s 2>&1 & echo $! > %s && sleep 3 && cat %s",
		playwrightServerPort, bp.timeout, useNodeModulesDir,
		playwrightServerScript, playwrightLogFile, playwrightPidFile, playwrightLogFile,
	)
```

---

### Fix 4: browser_install_blocker.go — No Changes Needed

The blocker is working as designed. It blocks the **AI agent** from wasting time trying to install browser packages via the terminal tool. The blocker message correctly tells the agent to use the built-in browser tools instead.

The blocker does NOT affect `ensureServer()` since that uses `execInContainer` directly (not the terminal tool handler where the blocker runs).

**No changes needed to `browser_install_blocker.go`.**

---

## Complete Patched `ensureServer()` Method

Here's the full replacement for the `ensureServer` method in `browser_playwright.go`:

```go
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

	// Check if Node.js AND npm are available
	// (vxcontrol/kali-linux has node v22 but NOT npm)
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

	// Create package.json for dependencies
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
		"mkdir -p /work/.browser-pkg && BROWSER_PORT=%d BROWSER_TIMEOUT=%d NODE_PATH=%s nohup node %s > %s 2>&1 & echo $! > %s && sleep 3 && cat %s",
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
```

---

## Implementation Steps

### Quick Fix (Just Go code — works with existing image):

1. **Edit** `backend/pkg/tools/browser_playwright.go` — replace `ensureServer()` with the patched version above
2. **Rebuild** PentAGI: `cd /home/legendx/Coding/pentagi && docker compose build backend`
3. **Restart**: `docker compose down && docker compose up -d`
4. **Test**: Run a flow that uses browser tools

This works because the patched code will detect npm is missing, install it, then proceed normally. ~3 min overhead on first browser use per container.

### Permanent Fix (Custom image — zero runtime overhead):

1. Create `docker/Dockerfile.kali` as shown above
2. Build: `docker build -f docker/Dockerfile.kali -t pentagi-kali:latest .`
3. Update `.env`: `DOCKER_DEFAULT_IMAGE_FOR_PENTEST=pentagi-kali:latest`
4. Apply the Go code fix too (for graceful fallback if someone uses a different image)
5. Rebuild + restart PentAGI

### Git Changes Summary

```
Modified:
  backend/pkg/tools/browser_playwright.go  (ensureServer method)

Added:
  docker/Dockerfile.kali                   (custom Kali image with deps)

Config:
  .env → DOCKER_DEFAULT_IMAGE_FOR_PENTEST=pentagi-kali:latest
```

---

## Why This Fixes All 6 Flows (14-19)

Every flow failed at the same point: `ensureServer()` → npm not found → browser server never starts → all browser tool calls return `[ERROR] Failed to start browser server`.

With either fix:
- **Quick fix**: npm gets installed at runtime, then playwright-extra installs, Chromium installs, server starts. ~3-5 min delay on first browser use.
- **Permanent fix**: Everything pre-installed in image. Server starts in <5 seconds. Zero runtime installation needed.

Both fixes are backwards-compatible. The Go code checks for pre-installed modules first, falls back to runtime installation, and the npm check ensures it doesn't skip installation when npm is missing.
