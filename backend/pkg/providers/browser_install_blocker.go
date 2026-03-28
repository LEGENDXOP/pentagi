package providers

import (
	"strings"
)

// blockedBrowserInstallMessage is returned when the agent tries to install browser
// automation packages that are unnecessary because browser tools are already available.
const blockedBrowserInstallMessage = `BLOCKED: Browser automation packages are NOT needed.

The browser_navigate tool IS Playwright — it's already running in your container.
Use browser_navigate, browser_click, browser_fill, browser_screenshot directly as tools.
No installation required.

Do NOT attempt to install playwright, puppeteer, chromium, or any browser automation package.
They are already provided as built-in tools.`

// browserInstallPatterns contains command prefixes/substrings that indicate an attempt
// to install browser automation packages. Each entry is checked as a substring match
// against the normalized (lowercased, whitespace-collapsed) command.
var browserInstallPatterns = []string{
	"npm install playwright",
	"npm i playwright",
	"npm install puppeteer",
	"npm i puppeteer",
	"npm install --save playwright",
	"npm install --save puppeteer",
	"npm install -g playwright",
	"npm install -g puppeteer",
	"npm i -g playwright",
	"npm i -g puppeteer",
	"yarn add playwright",
	"yarn add puppeteer",
	"pnpm add playwright",
	"pnpm add puppeteer",
	"pnpm install playwright",
	"pnpm install puppeteer",
	"pip install playwright",
	"pip3 install playwright",
	"pip install pyppeteer",
	"pip3 install pyppeteer",
	"apt install chromium",
	"apt-get install chromium",
	"apt install google-chrome",
	"apt-get install google-chrome",
	"apt install firefox",
	"apt-get install firefox",
	"npx playwright install",
	"playwright install",
}

// isBrowserAutomationInstall checks if a shell command is attempting to install
// browser automation packages (playwright, puppeteer, chromium, etc.).
// These packages are unnecessary because browser tools are already provided as
// built-in agent tools.
func isBrowserAutomationInstall(cmd string) bool {
	// Normalize: lowercase and collapse whitespace for reliable matching.
	normalized := collapseWhitespace(strings.ToLower(strings.TrimSpace(cmd)))

	for _, pattern := range browserInstallPatterns {
		if strings.Contains(normalized, pattern) {
			return true
		}
	}

	return false
}

// collapseWhitespace replaces runs of whitespace with a single space.
func collapseWhitespace(s string) string {
	fields := strings.Fields(s)
	return strings.Join(fields, " ")
}
