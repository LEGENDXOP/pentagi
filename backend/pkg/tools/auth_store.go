package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Tool name constants for auth store tools
const (
	AuthLoginToolName   = "auth_login"
	AuthStatusToolName  = "auth_status"
	AuthInjectToolName  = "auth_inject"
	AuthRefreshToolName = "auth_refresh"
	AuthLogoutToolName  = "auth_logout"
)

// ──────────────────── Action schemas ────────────────────

// AuthLoginAction is the argument schema for the auth_login tool
type AuthLoginAction struct {
	FlowType    string `json:"flow_type" jsonschema:"required,enum=form-login,enum=oauth2-cc,enum=api-key,enum=custom" jsonschema_description:"Type of authentication flow to execute. 'form-login' posts credentials to a login form. 'oauth2-cc' uses OAuth2 client_credentials grant. 'api-key' stores a static API key for injection. 'custom' executes a custom shell command to obtain tokens."`
	FlowID      string `json:"flow_id" jsonschema:"required" jsonschema_description:"Unique identifier for this auth session (e.g., 'webapp-admin', 'api-service'). Used to reference this session in auth_inject and auth_status calls."`
	LoginURL    string `json:"login_url,omitempty" jsonschema_description:"URL to POST credentials to (required for form-login and oauth2-cc). For oauth2-cc this is the token endpoint."`
	Username    string `json:"username,omitempty" jsonschema_description:"Username for form-login authentication"`
	Password    string `json:"password,omitempty" jsonschema_description:"Password for form-login authentication"`
	ClientID    string `json:"client_id,omitempty" jsonschema_description:"Client ID for oauth2-cc flow"`
	ClientSecret string `json:"client_secret,omitempty" jsonschema_description:"Client secret for oauth2-cc flow"`
	Scope       string `json:"scope,omitempty" jsonschema_description:"OAuth2 scope (optional, for oauth2-cc flow)"`
	APIKey      string `json:"api_key,omitempty" jsonschema_description:"API key value (required for api-key flow)"`
	APIKeyHeader string `json:"api_key_header,omitempty" jsonschema_description:"Header name for API key injection (default: 'X-API-Key'). Set to 'Authorization' for Bearer-style keys. Set to '?param_name' for query parameter injection."`
	CustomCmd   string `json:"custom_cmd,omitempty" jsonschema_description:"Shell command that outputs a JSON object with 'access_token' and optionally 'refresh_token', 'expires_in', 'cookies' fields. Used only for custom flow type."`
	ExtraHeaders map[string]string `json:"extra_headers,omitempty" jsonschema_description:"Additional headers to send during login (e.g., Content-Type overrides, CSRF tokens)"`
	FormFields  map[string]string `json:"form_fields,omitempty" jsonschema_description:"Additional form fields for form-login (e.g., CSRF tokens, remember-me flags). Username and password fields default to 'username' and 'password' but can be overridden here."`
	UsernameField string `json:"username_field,omitempty" jsonschema_description:"Form field name for username (default: 'username'). Set this if the login form uses a different name like 'email' or 'login'."`
	PasswordField string `json:"password_field,omitempty" jsonschema_description:"Form field name for password (default: 'password'). Set this if the login form uses a different name like 'passwd' or 'pass'."`
	Message     string `json:"message" jsonschema:"required,title=Auth login message" jsonschema_description:"Short message explaining the authentication action to send to the user in English"`
}

// AuthStatusAction is the argument schema for the auth_status tool
type AuthStatusAction struct {
	FlowID  string `json:"flow_id,omitempty" jsonschema_description:"Specific flow ID to check status for. Leave empty to see all active sessions."`
	Message string `json:"message" jsonschema:"required,title=Auth status message" jsonschema_description:"Short message explaining why you're checking auth status, to send to the user in English"`
}

// AuthInjectAction is the argument schema for the auth_inject tool
type AuthInjectAction struct {
	FlowID  string `json:"flow_id" jsonschema:"required" jsonschema_description:"Flow ID to get authentication context for"`
	Message string `json:"message" jsonschema:"required,title=Auth inject message" jsonschema_description:"Short message explaining what authenticated request you want to make, to send to the user in English"`
}

// AuthRefreshAction is the argument schema for the auth_refresh tool
type AuthRefreshAction struct {
	FlowID  string `json:"flow_id" jsonschema:"required" jsonschema_description:"Flow ID to force token refresh for"`
	Message string `json:"message" jsonschema:"required,title=Auth refresh message" jsonschema_description:"Short message explaining why you need to refresh the token, to send to the user in English"`
}

// AuthLogoutAction is the argument schema for the auth_logout tool
type AuthLogoutAction struct {
	FlowID  string `json:"flow_id" jsonschema:"required" jsonschema_description:"Flow ID to clear. All cookies, tokens, and session state for this flow will be removed."`
	Message string `json:"message" jsonschema:"required,title=Auth logout message" jsonschema_description:"Short message explaining why you're clearing this session, to send to the user in English"`
}

// ──────────────────── Auth State ────────────────────

// AuthState holds all authentication state for a single flow/session
type AuthState struct {
	mu           sync.RWMutex
	FlowID       string            `json:"flow_id"`
	FlowType     string            `json:"flow_type"`
	LoginURL     string            `json:"login_url,omitempty"`
	AccessToken  string            `json:"access_token,omitempty"`
	RefreshToken string            `json:"refresh_token,omitempty"`
	TokenType    string            `json:"token_type,omitempty"`
	ExpiresAt    time.Time         `json:"expires_at,omitempty"`
	IssuedAt     time.Time         `json:"issued_at"`
	Cookies      []*http.Cookie    `json:"cookies,omitempty"`
	CSRFToken    string            `json:"csrf_token,omitempty"`
	APIKey       string            `json:"api_key,omitempty"`
	APIKeyHeader string            `json:"api_key_header,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`

	// For oauth2-cc refresh
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// NeedsRefresh returns true if token is within 20% of its lifetime from expiry.
// Thread-safe: acquires RLock.
func (as *AuthState) NeedsRefresh() bool {
	as.mu.RLock()
	defer as.mu.RUnlock()
	return as.needsRefreshLocked()
}

// needsRefreshLocked is the lock-free version for use when caller already holds the lock.
func (as *AuthState) needsRefreshLocked() bool {
	if as.ExpiresAt.IsZero() {
		return false // no expiry set, no refresh needed
	}

	now := time.Now()
	if now.After(as.ExpiresAt) {
		return true // already expired
	}

	totalLifetime := as.ExpiresAt.Sub(as.IssuedAt)
	if totalLifetime <= 0 {
		return false
	}

	// Refresh when within 20% of the expiry
	threshold := time.Duration(float64(totalLifetime) * 0.2)
	return now.After(as.ExpiresAt.Add(-threshold))
}

// IsExpired returns true if the token has expired.
// Thread-safe: acquires RLock.
func (as *AuthState) IsExpired() bool {
	as.mu.RLock()
	defer as.mu.RUnlock()
	return as.isExpiredLocked()
}

// isExpiredLocked is the lock-free version for use when caller already holds the lock.
func (as *AuthState) isExpiredLocked() bool {
	if as.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(as.ExpiresAt)
}

// CookiesNetscape returns cookies in Netscape format compatible with curl -b
func (as *AuthState) CookiesNetscape() string {
	as.mu.RLock()
	defer as.mu.RUnlock()

	if len(as.Cookies) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("# Netscape HTTP Cookie File\n")
	sb.WriteString("# Generated by PentAGI auth_store\n\n")

	for _, c := range as.Cookies {
		domain := c.Domain
		if domain == "" {
			domain = "."
		}
		includeSubdomains := "TRUE"
		if !strings.HasPrefix(domain, ".") {
			includeSubdomains = "FALSE"
		}
		path := c.Path
		if path == "" {
			path = "/"
		}
		secure := "FALSE"
		if c.Secure {
			secure = "TRUE"
		}
		expires := "0"
		if !c.Expires.IsZero() {
			expires = fmt.Sprintf("%d", c.Expires.Unix())
		}
		sb.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			domain, includeSubdomains, path, secure, expires, c.Name, c.Value))
	}

	return sb.String()
}

// ──────────────────── Auth Store Tool ────────────────────

// authStore manages all authentication sessions for a flow
type authStore struct {
	mu        sync.RWMutex
	flowID    int64
	taskID    *int64
	subtaskID *int64
	sessions  map[string]*AuthState
	enabled   bool
}

// NewAuthStoreTool creates a new auth store tool instance
func NewAuthStoreTool(
	flowID int64,
	taskID, subtaskID *int64,
	enabled bool,
) *authStore {
	return &authStore{
		flowID:    flowID,
		taskID:    taskID,
		subtaskID: subtaskID,
		sessions:  make(map[string]*AuthState),
		enabled:   enabled,
	}
}

// IsAvailable returns true if the auth store tool is enabled
func (as *authStore) IsAvailable() bool {
	return as.enabled
}

// Handle processes tool calls for all auth store tools
func (as *authStore) Handle(ctx context.Context, name string, args json.RawMessage) (string, error) {
	logger := logrus.WithContext(ctx).WithFields(enrichLogrusFields(as.flowID, as.taskID, as.subtaskID, logrus.Fields{
		"tool": name,
		"args": string(args),
	}))

	switch name {
	case AuthLoginToolName:
		return as.handleLogin(ctx, logger, args)
	case AuthStatusToolName:
		return as.handleStatus(ctx, logger, args)
	case AuthInjectToolName:
		return as.handleInject(ctx, logger, args)
	case AuthRefreshToolName:
		return as.handleRefresh(ctx, logger, args)
	case AuthLogoutToolName:
		return as.handleLogout(ctx, logger, args)
	default:
		return "", fmt.Errorf("unknown auth store tool: %s", name)
	}
}

func (as *authStore) handleLogin(ctx context.Context, logger *logrus.Entry, args json.RawMessage) (string, error) {
	var action AuthLoginAction
	if err := json.Unmarshal(args, &action); err != nil {
		logger.WithError(err).Error("failed to unmarshal auth_login action")
		return "", fmt.Errorf("failed to unmarshal auth_login action: %w", err)
	}

	if action.FlowID == "" {
		return "Error: flow_id is required", nil
	}

	var state *AuthState
	var err error

	switch action.FlowType {
	case "form-login":
		state, err = executeFormLogin(ctx, &action)
	case "oauth2-cc":
		state, err = executeOAuth2CC(ctx, &action)
	case "api-key":
		state, err = executeAPIKey(ctx, &action)
	case "custom":
		state, err = executeCustomFlow(ctx, &action)
	default:
		return fmt.Sprintf("Error: unknown flow_type '%s'. Must be one of: form-login, oauth2-cc, api-key, custom", action.FlowType), nil
	}

	if err != nil {
		logger.WithError(err).WithField("flow_type", action.FlowType).Warn("auth login flow failed")
		return fmt.Sprintf("## Authentication Failed\n\n**Flow:** `%s` (type: %s)\n**Error:** %s\n\n"+
			"Check credentials, URL, and network connectivity. Use `auth_status` to review current sessions.",
			action.FlowID, action.FlowType, err.Error()), nil
	}

	// Store the session
	as.mu.Lock()
	as.sessions[action.FlowID] = state
	as.mu.Unlock()

	logger.WithFields(logrus.Fields{
		"flow_id":   action.FlowID,
		"flow_type": action.FlowType,
		"has_token": state.AccessToken != "",
		"cookies":   len(state.Cookies),
	}).Info("auth login successful")

	return as.formatLoginSuccess(state), nil
}

func (as *authStore) formatLoginSuccess(state *AuthState) string {
	var sb strings.Builder
	sb.WriteString("## Authentication Successful\n\n")
	sb.WriteString(fmt.Sprintf("**Flow ID:** `%s`\n", state.FlowID))
	sb.WriteString(fmt.Sprintf("**Flow Type:** %s\n", state.FlowType))

	if state.AccessToken != "" {
		tokenPreview := state.AccessToken
		if len(tokenPreview) > 20 {
			tokenPreview = tokenPreview[:10] + "..." + tokenPreview[len(tokenPreview)-10:]
		}
		sb.WriteString(fmt.Sprintf("**Access Token:** `%s`\n", tokenPreview))
		if !state.ExpiresAt.IsZero() {
			remaining := time.Until(state.ExpiresAt).Round(time.Second)
			sb.WriteString(fmt.Sprintf("**Expires In:** %s\n", remaining))
		}
	}

	if state.RefreshToken != "" {
		sb.WriteString("**Refresh Token:** ✅ available\n")
	}

	if len(state.Cookies) > 0 {
		sb.WriteString(fmt.Sprintf("**Cookies:** %d stored\n", len(state.Cookies)))
		for _, c := range state.Cookies {
			sb.WriteString(fmt.Sprintf("  - `%s` (domain: %s)\n", c.Name, c.Domain))
		}
	}

	if state.CSRFToken != "" {
		sb.WriteString("**CSRF Token:** ✅ tracked\n")
	}

	if state.APIKey != "" {
		sb.WriteString(fmt.Sprintf("**API Key:** stored (header: `%s`)\n", state.APIKeyHeader))
	}

	sb.WriteString("\n**Next step:** Use `auth_inject` with this flow_id to get curl flags for authenticated requests.")

	return sb.String()
}

func (as *authStore) handleStatus(ctx context.Context, logger *logrus.Entry, args json.RawMessage) (string, error) {
	var action AuthStatusAction
	if err := json.Unmarshal(args, &action); err != nil {
		logger.WithError(err).Error("failed to unmarshal auth_status action")
		return "", fmt.Errorf("failed to unmarshal auth_status action: %w", err)
	}

	as.mu.RLock()
	defer as.mu.RUnlock()

	if action.FlowID != "" {
		state, ok := as.sessions[action.FlowID]
		if !ok {
			return fmt.Sprintf("No active session found for flow_id `%s`.\n\nUse `auth_login` to create a new session.", action.FlowID), nil
		}
		return as.formatSessionStatus(state), nil
	}

	if len(as.sessions) == 0 {
		return "## Auth Store Status\n\n**No active sessions.**\n\nUse `auth_login` to create an authenticated session.", nil
	}

	var sb strings.Builder
	sb.WriteString("## Auth Store Status\n\n")
	sb.WriteString(fmt.Sprintf("**Active Sessions:** %d\n\n", len(as.sessions)))

	for _, state := range as.sessions {
		sb.WriteString(as.formatSessionStatus(state))
		sb.WriteString("\n---\n\n")
	}

	return sb.String(), nil
}

func (as *authStore) formatSessionStatus(state *AuthState) string {
	state.mu.RLock()
	defer state.mu.RUnlock()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("### Session: `%s` (type: %s)\n\n", state.FlowID, state.FlowType))

	// Token status (use lock-free versions since we already hold state.mu.RLock)
	if state.AccessToken != "" {
		if state.isExpiredLocked() {
			sb.WriteString("**Token Status:** ❌ EXPIRED\n")
		} else if state.needsRefreshLocked() {
			sb.WriteString("**Token Status:** ⚠️ NEEDS REFRESH (within 20% of expiry)\n")
		} else {
			sb.WriteString("**Token Status:** ✅ ACTIVE\n")
		}

		if !state.ExpiresAt.IsZero() {
			remaining := time.Until(state.ExpiresAt).Round(time.Second)
			if remaining > 0 {
				sb.WriteString(fmt.Sprintf("**Expires In:** %s\n", remaining))
			} else {
				sb.WriteString(fmt.Sprintf("**Expired:** %s ago\n", (-remaining)))
			}
		} else {
			sb.WriteString("**Expires:** no expiry set\n")
		}

		sb.WriteString(fmt.Sprintf("**Refresh Token:** %s\n",
			boolEmoji(state.RefreshToken != "")))
	}

	// Cookie status
	if len(state.Cookies) > 0 {
		sb.WriteString(fmt.Sprintf("**Cookies:** %d stored\n", len(state.Cookies)))
	}

	// API key status
	if state.APIKey != "" {
		sb.WriteString(fmt.Sprintf("**API Key:** stored (inject via `%s`)\n", state.APIKeyHeader))
	}

	// CSRF
	if state.CSRFToken != "" {
		sb.WriteString("**CSRF Token:** tracked\n")
	}

	return sb.String()
}

func (as *authStore) handleInject(ctx context.Context, logger *logrus.Entry, args json.RawMessage) (string, error) {
	var action AuthInjectAction
	if err := json.Unmarshal(args, &action); err != nil {
		logger.WithError(err).Error("failed to unmarshal auth_inject action")
		return "", fmt.Errorf("failed to unmarshal auth_inject action: %w", err)
	}

	as.mu.RLock()
	state, ok := as.sessions[action.FlowID]
	as.mu.RUnlock()

	if !ok {
		return fmt.Sprintf("No active session found for flow_id `%s`.\n\nUse `auth_login` first.", action.FlowID), nil
	}

	// Auto-refresh if needed
	if state.NeedsRefresh() && state.RefreshToken != "" {
		logger.WithField("flow_id", action.FlowID).Info("auto-refreshing token before injection")
		if err := as.refreshSession(ctx, state); err != nil {
			logger.WithError(err).Warn("auto-refresh failed, using existing token")
		}
	}

	return as.buildCurlFlags(state), nil
}

func (as *authStore) buildCurlFlags(state *AuthState) string {
	state.mu.RLock()
	defer state.mu.RUnlock()

	var flags []string
	var sb strings.Builder

	sb.WriteString("## Curl Authentication Flags\n\n")
	sb.WriteString(fmt.Sprintf("**Session:** `%s` (type: %s)\n\n", state.FlowID, state.FlowType))

	// Bearer token
	if state.AccessToken != "" {
		tokenType := state.TokenType
		if tokenType == "" {
			tokenType = "Bearer"
		}
		flag := fmt.Sprintf(`-H "Authorization: %s %s"`, tokenType, state.AccessToken)
		flags = append(flags, flag)
	}

	// Cookies — inline format for curl -b
	if len(state.Cookies) > 0 {
		var cookieParts []string
		for _, c := range state.Cookies {
			cookieParts = append(cookieParts, fmt.Sprintf("%s=%s", c.Name, c.Value))
		}
		flag := fmt.Sprintf(`-b "%s"`, strings.Join(cookieParts, "; "))
		flags = append(flags, flag)
	}

	// CSRF token
	if state.CSRFToken != "" {
		flag := fmt.Sprintf(`-H "X-CSRF-Token: %s"`, state.CSRFToken)
		flags = append(flags, flag)
	}

	// API key
	if state.APIKey != "" {
		header := state.APIKeyHeader
		if header == "" {
			header = "X-API-Key"
		}
		if strings.HasPrefix(header, "?") {
			// Query parameter injection — just note it
			paramName := strings.TrimPrefix(header, "?")
			sb.WriteString(fmt.Sprintf("**Query Parameter:** Append `?%s=%s` to URL\n\n", paramName, state.APIKey))
		} else {
			flag := fmt.Sprintf(`-H "%s: %s"`, header, state.APIKey)
			flags = append(flags, flag)
		}
	}

	// Extra headers
	for k, v := range state.Headers {
		flag := fmt.Sprintf(`-H "%s: %s"`, k, v)
		flags = append(flags, flag)
	}

	if len(flags) == 0 {
		sb.WriteString("**No authentication flags to inject.** Session has no tokens, cookies, or API keys.\n")
		return sb.String()
	}

	sb.WriteString("```\n")
	sb.WriteString(strings.Join(flags, " \\\n  "))
	sb.WriteString("\n```\n\n")

	sb.WriteString("**Usage example:**\n```bash\n")
	sb.WriteString(fmt.Sprintf("curl -v -k %s \"https://target/api/endpoint\"\n",
		strings.Join(flags, " ")))
	sb.WriteString("```\n")

	// Token expiry warning (use lock-free version since we already hold state.mu.RLock)
	if !state.ExpiresAt.IsZero() {
		remaining := time.Until(state.ExpiresAt).Round(time.Second)
		if remaining <= 0 {
			sb.WriteString("\n⚠️ **Token is EXPIRED.** Use `auth_refresh` to obtain a new token.\n")
		} else if state.needsRefreshLocked() {
			sb.WriteString(fmt.Sprintf("\n⚠️ **Token expires in %s.** Consider `auth_refresh` soon.\n", remaining))
		}
	}

	return sb.String()
}

func (as *authStore) handleRefresh(ctx context.Context, logger *logrus.Entry, args json.RawMessage) (string, error) {
	var action AuthRefreshAction
	if err := json.Unmarshal(args, &action); err != nil {
		logger.WithError(err).Error("failed to unmarshal auth_refresh action")
		return "", fmt.Errorf("failed to unmarshal auth_refresh action: %w", err)
	}

	as.mu.RLock()
	state, ok := as.sessions[action.FlowID]
	as.mu.RUnlock()

	if !ok {
		return fmt.Sprintf("No active session found for flow_id `%s`.\n\nUse `auth_login` first.", action.FlowID), nil
	}

	if err := as.refreshSession(ctx, state); err != nil {
		logger.WithError(err).WithField("flow_id", action.FlowID).Warn("token refresh failed")
		return fmt.Sprintf("## Token Refresh Failed\n\n**Flow:** `%s`\n**Error:** %s\n\n"+
			"Consider re-authenticating with `auth_login`.",
			action.FlowID, err.Error()), nil
	}

	logger.WithField("flow_id", action.FlowID).Info("token refreshed successfully")

	return fmt.Sprintf("## Token Refreshed\n\n**Flow:** `%s`\n**New Expiry:** %s\n\n"+
		"Use `auth_inject` to get updated curl flags.",
		action.FlowID, time.Until(state.ExpiresAt).Round(time.Second)), nil
}

func (as *authStore) refreshSession(ctx context.Context, state *AuthState) error {
	state.mu.RLock()
	flowType := state.FlowType
	refreshToken := state.RefreshToken
	loginURL := state.LoginURL
	clientID := state.ClientID
	clientSecret := state.ClientSecret
	scope := state.Scope
	state.mu.RUnlock()

	switch flowType {
	case "oauth2-cc":
		// Re-execute client_credentials grant
		action := &AuthLoginAction{
			FlowType:     "oauth2-cc",
			FlowID:       state.FlowID,
			LoginURL:     loginURL,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Scope:        scope,
		}
		newState, err := executeOAuth2CC(ctx, action)
		if err != nil {
			return fmt.Errorf("oauth2-cc refresh failed: %w", err)
		}

		state.mu.Lock()
		state.AccessToken = newState.AccessToken
		state.RefreshToken = newState.RefreshToken
		state.TokenType = newState.TokenType
		state.ExpiresAt = newState.ExpiresAt
		state.IssuedAt = newState.IssuedAt
		state.mu.Unlock()
		return nil

	case "form-login":
		if refreshToken != "" {
			// Try using refresh_token with the same login URL as token endpoint
			newState, err := refreshWithToken(ctx, loginURL, refreshToken)
			if err == nil {
				state.mu.Lock()
				state.AccessToken = newState.AccessToken
				if newState.RefreshToken != "" {
					state.RefreshToken = newState.RefreshToken
				}
				state.TokenType = newState.TokenType
				state.ExpiresAt = newState.ExpiresAt
				state.IssuedAt = newState.IssuedAt
				state.mu.Unlock()
				return nil
			}
		}
		return fmt.Errorf("form-login sessions cannot be refreshed without re-authenticating; use auth_login again")

	case "api-key":
		return fmt.Errorf("api-key sessions do not expire and cannot be refreshed")

	case "custom":
		return fmt.Errorf("custom flow sessions must be refreshed by re-running auth_login with the custom command")

	default:
		return fmt.Errorf("unknown flow type '%s', cannot refresh", flowType)
	}
}

func (as *authStore) handleLogout(ctx context.Context, logger *logrus.Entry, args json.RawMessage) (string, error) {
	var action AuthLogoutAction
	if err := json.Unmarshal(args, &action); err != nil {
		logger.WithError(err).Error("failed to unmarshal auth_logout action")
		return "", fmt.Errorf("failed to unmarshal auth_logout action: %w", err)
	}

	as.mu.Lock()
	_, existed := as.sessions[action.FlowID]
	delete(as.sessions, action.FlowID)
	as.mu.Unlock()

	if !existed {
		return fmt.Sprintf("No active session found for flow_id `%s`. Nothing to clear.", action.FlowID), nil
	}

	logger.WithField("flow_id", action.FlowID).Info("auth session cleared")

	return fmt.Sprintf("## Session Cleared\n\n**Flow ID:** `%s`\n\n"+
		"All cookies, tokens, and session state have been removed.\n"+
		"Use `auth_login` to create a new session.",
		action.FlowID), nil
}

// refreshWithToken attempts an OAuth2 refresh_token grant
func refreshWithToken(ctx context.Context, tokenURL, refreshToken string) (*AuthState, error) {
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("refresh request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("refresh returned status %d", resp.StatusCode)
	}

	return parseOAuth2TokenResponse(resp)
}

func boolEmoji(v bool) string {
	if v {
		return "✅ available"
	}
	return "❌ not available"
}
