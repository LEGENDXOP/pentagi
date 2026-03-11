package notifications

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	telegramAPIBase    = "https://api.telegram.org/bot"
	telegramRateLimit  = 3 * time.Second
	telegramQueueSize  = 100
	telegramMaxMsgLen  = 4096
	telegramHTTPTimout = 10 * time.Second
)

// telegramSendRequest represents the JSON body for Telegram sendMessage API.
type telegramSendRequest struct {
	ChatID    string `json:"chat_id"`
	Text      string `json:"text"`
	ParseMode string `json:"parse_mode,omitempty"`
}

// telegramResponse represents a minimal Telegram API response.
type telegramResponse struct {
	OK          bool   `json:"ok"`
	Description string `json:"description,omitempty"`
}

// TelegramNotifier sends messages via Telegram Bot API.
// It uses a buffered channel queue and rate-limits outgoing messages.
type TelegramNotifier struct {
	token  string
	chatID string
	client *http.Client
	queue  chan string
	done   chan struct{}
	wg     sync.WaitGroup
}

// NewTelegramNotifier creates and starts a TelegramNotifier.
// Messages are queued and sent asynchronously with rate limiting.
func NewTelegramNotifier(token, chatID string) *TelegramNotifier {
	t := &TelegramNotifier{
		token:  token,
		chatID: chatID,
		client: &http.Client{Timeout: telegramHTTPTimout},
		queue:  make(chan string, telegramQueueSize),
		done:   make(chan struct{}),
	}

	t.wg.Add(1)
	go t.worker()

	return t
}

// Send enqueues a message for delivery. Non-blocking: drops if queue is full.
func (t *TelegramNotifier) Send(message string) {
	if message == "" {
		logrus.Debug("telegram Send called with empty message, skipping")
		return
	}

	// Truncate if too long for Telegram
	if len(message) > telegramMaxMsgLen {
		message = message[:telegramMaxMsgLen-20] + "\n\n... (truncated)"
	}

	select {
	case t.queue <- message:
		logrus.WithField("queue_len", len(t.queue)).Debug("telegram message enqueued")
	default:
		logrus.WithField("queue_cap", cap(t.queue)).Warn("telegram notification queue full, dropping message")
	}
}

// Close stops the worker and waits for pending messages to drain.
func (t *TelegramNotifier) Close() {
	close(t.done)
	t.wg.Wait()
}

// worker processes queued messages with rate limiting.
func (t *TelegramNotifier) worker() {
	defer t.wg.Done()

	ticker := time.NewTicker(telegramRateLimit)
	defer ticker.Stop()

	for {
		select {
		case <-t.done:
			// Drain remaining messages
			t.drainQueue()
			return
		case msg := <-t.queue:
			t.sendMessage(msg)
			// Wait for rate limit before processing next message
			select {
			case <-ticker.C:
			case <-t.done:
				t.drainQueue()
				return
			}
		}
	}
}

// drainQueue attempts to send remaining queued messages on shutdown.
func (t *TelegramNotifier) drainQueue() {
	for {
		select {
		case msg := <-t.queue:
			t.sendMessage(msg)
		default:
			return
		}
	}
}

// sendMessage makes the HTTP POST to Telegram sendMessage API.
func (t *TelegramNotifier) sendMessage(text string) {
	logrus.WithField("chat_id", t.chatID).Debug("sending telegram message")
	url := fmt.Sprintf("%s%s/sendMessage", telegramAPIBase, t.token)

	body := telegramSendRequest{
		ChatID:    t.chatID,
		Text:      text,
		ParseMode: "HTML",
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		logrus.WithError(err).Error("failed to marshal telegram message")
		return
	}

	resp, err := t.client.Post(url, "application/json", bytes.NewReader(jsonBody))
	if err != nil {
		logrus.WithError(err).Error("failed to send telegram message")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		var tgResp telegramResponse
		if json.Unmarshal(respBody, &tgResp) == nil {
			logrus.WithFields(logrus.Fields{
				"status":      resp.StatusCode,
				"description": tgResp.Description,
			}).Error("telegram API error")
		} else {
			logrus.WithFields(logrus.Fields{
				"status": resp.StatusCode,
				"body":   string(respBody),
			}).Error("telegram API error")
		}

		return
	}

	logrus.Debug("telegram notification sent successfully")
}
