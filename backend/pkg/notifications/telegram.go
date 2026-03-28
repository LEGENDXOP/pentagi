package notifications

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	telegramAPIBase     = "https://api.telegram.org/bot"
	telegramRateLimit   = 3 * time.Second
	telegramQueueSize   = 100
	telegramMaxMsgLen   = 4096
	telegramHTTPTimeout = 10 * time.Second
	telegramMaxRetries  = 2
	telegramDrainDelay  = 500 * time.Millisecond // delay between messages during drain
	telegramMaxDrain    = 20                      // max messages to send during drain
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
		client: &http.Client{Timeout: telegramHTTPTimeout},
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
			// Drain remaining messages with rate limiting
			t.drainQueue()
			return
		case msg := <-t.queue:
			t.sendMessageWithRetry(msg)
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

// drainQueue attempts to send remaining queued messages on shutdown with rate limiting.
func (t *TelegramNotifier) drainQueue() {
	sent := 0
	for {
		if sent >= telegramMaxDrain {
			// Drop remaining messages to avoid long shutdown
			remaining := len(t.queue)
			if remaining > 0 {
				logrus.WithField("dropped", remaining).Warn("telegram drain limit reached, dropping remaining messages")
			}
			return
		}
		select {
		case msg := <-t.queue:
			t.sendMessageWithRetry(msg)
			sent++
			if sent < telegramMaxDrain {
				time.Sleep(telegramDrainDelay)
			}
		default:
			return
		}
	}
}

// sendMessageWithRetry sends a message with retry logic for transient errors.
func (t *TelegramNotifier) sendMessageWithRetry(text string) {
	backoff := 1 * time.Second

	for attempt := 0; attempt <= telegramMaxRetries; attempt++ {
		retryAfter, err := t.sendMessage(text)
		if err == nil {
			return // success
		}

		if attempt >= telegramMaxRetries {
			logrus.WithError(err).WithField("attempts", attempt+1).Error("telegram message failed after retries")
			return
		}

		// Use Retry-After header value if provided (429), otherwise use exponential backoff
		wait := backoff
		if retryAfter > 0 {
			wait = retryAfter
		}

		logrus.WithFields(logrus.Fields{
			"attempt": attempt + 1,
			"wait":    wait,
		}).Warn("retrying telegram message")

		time.Sleep(wait)
		backoff *= 2
	}
}

// sendMessage makes the HTTP POST to Telegram sendMessage API.
// Returns the Retry-After duration (if any) and an error for retryable failures.
func (t *TelegramNotifier) sendMessage(text string) (time.Duration, error) {
	url := fmt.Sprintf("%s%s/sendMessage", telegramAPIBase, t.token)
	return t.sendMessageURL(url, text)
}

// sendMessageURL makes the HTTP POST to a given URL (allows test injection).
func (t *TelegramNotifier) sendMessageURL(url, text string) (time.Duration, error) {
	logrus.WithField("chat_id", t.chatID).Debug("sending telegram message")

	body := telegramSendRequest{
		ChatID:    t.chatID,
		Text:      text,
		ParseMode: "HTML",
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		logrus.WithError(err).Error("failed to marshal telegram message")
		return 0, nil // non-retryable
	}

	resp, err := t.client.Post(url, "application/json", bytes.NewReader(jsonBody))
	if err != nil {
		logrus.WithError(err).Error("failed to send telegram message")
		return 0, fmt.Errorf("http error: %w", err) // retryable
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		logrus.Debug("telegram notification sent successfully")
		return 0, nil
	}

	respBody, _ := io.ReadAll(resp.Body)

	// Parse Retry-After header for 429 responses
	var retryAfter time.Duration
	if resp.StatusCode == http.StatusTooManyRequests {
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if seconds, parseErr := strconv.Atoi(ra); parseErr == nil {
				retryAfter = time.Duration(seconds) * time.Second
			}
		}
		if retryAfter == 0 {
			retryAfter = 5 * time.Second // default for 429
		}
	}

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

	// Retryable: 429, 5xx
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return retryAfter, fmt.Errorf("telegram API error: status %d", resp.StatusCode)
	}

	return 0, nil // non-retryable (4xx client errors)
}
