package masteragent

import "time"

// MasterAgentConfig holds configuration for the Master Agent supervisor.
type MasterAgentConfig struct {
	Enabled  bool
	Interval time.Duration
	Model    string

	// Anthropic API credentials (from main config)
	AnthropicAPIKey    string
	AnthropicServerURL string

	// Telegram notifications (optional)
	TelegramBotToken string
	TelegramChatID   string
}
