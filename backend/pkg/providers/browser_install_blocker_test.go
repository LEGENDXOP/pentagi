package providers

import "testing"

func TestIsBrowserAutomationInstall(t *testing.T) {
	tests := []struct {
		name    string
		cmd     string
		blocked bool
	}{
		// Should block
		{"npm install playwright", "npm install playwright", true},
		{"npm install playwright-extra", "npm install playwright-extra", true},
		{"npm i playwright", "npm i playwright", true},
		{"npm install puppeteer", "npm install puppeteer", true},
		{"npm install puppeteer-extra", "npm install puppeteer-extra", true},
		{"npm i puppeteer", "npm i puppeteer", true},
		{"npm install with extra spaces", "npm  install   playwright", true},
		{"pip install playwright", "pip install playwright", true},
		{"pip3 install playwright", "pip3 install playwright", true},
		{"apt install chromium", "apt install chromium", true},
		{"apt-get install chromium", "apt-get install chromium", true},
		{"apt install chromium-browser", "apt install chromium-browser", true},
		{"apt-get install chromium-browser", "sudo apt-get install chromium-browser", true},
		{"npx playwright install", "npx playwright install", true},
		{"npx playwright install chromium", "npx playwright install chromium", true},
		{"yarn add playwright", "yarn add playwright", true},
		{"pnpm add puppeteer", "pnpm add puppeteer", true},
		{"uppercase npm", "NPM INSTALL PLAYWRIGHT", true},
		{"mixed case", "Npm Install Playwright-Extra", true},
		{"sudo prefix", "sudo npm install playwright", true},
		{"with version", "npm install playwright@1.40.0", true},
		{"global install", "npm install -g playwright", true},
		{"pip install pyppeteer", "pip install pyppeteer", true},
		{"apt install google-chrome-stable", "apt install google-chrome-stable", true},

		// Should NOT block
		{"regular npm install", "npm install express", false},
		{"pip install requests", "pip install requests", false},
		{"apt install curl", "apt install curl", false},
		{"ls command", "ls -la", false},
		{"node script", "node index.js", false},
		{"empty string", "", false},
		{"just npm", "npm", false},
		{"playwright in path", "cat /usr/lib/playwright/README.md", false},
		{"grep for playwright", "grep -r playwright package.json", false},
		{"npm list playwright", "npm list playwright", false},
		{"npm uninstall playwright", "npm uninstall playwright", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isBrowserAutomationInstall(tt.cmd)
			if got != tt.blocked {
				t.Errorf("isBrowserAutomationInstall(%q) = %v, want %v", tt.cmd, got, tt.blocked)
			}
		})
	}
}

func TestCollapseWhitespace(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello  world", "hello world"},
		{"  npm   install    playwright  ", "npm install playwright"},
		{"no-extra-spaces", "no-extra-spaces"},
		{"", ""},
		{"  ", ""},
		{"a\t\tb\nc", "a b c"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := collapseWhitespace(tt.input)
			if got != tt.expected {
				t.Errorf("collapseWhitespace(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
