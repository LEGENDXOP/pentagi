package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	authHTTPTimeout = 30 * time.Second
	maxResponseBody = 64 * 1024 // 64 KB
)

// ──────────────────── Form Login Flow ────────────────────

// executeFormLogin POSTs credentials to a login form URL, extracts Set-Cookie headers,
// and optionally parses a JSON response for bearer tokens.
func executeFormLogin(ctx context.Context, action *AuthLoginAction) (*AuthState, error) {
	if action.LoginURL == "" {
		return nil, fmt.Errorf("login_url is required for form-login flow")
	}
	if action.Username == "" {
		return nil, fmt.Errorf("username is required for form-login flow")
	}
	if action.Password == "" {
		return nil, fmt.Errorf("password is required for form-login flow")
	}

	// Build form data
	usernameField := action.UsernameField
	if usernameField == "" {
		usernameField = "username"
	}
	passwordField := action.PasswordField
	if passwordField == "" {
		passwordField = "password"
	}

	formData := url.Values{
		usernameField: {action.Username},
		passwordField: {action.Password},
	}

	// Add extra form fields
	for k, v := range action.FormFields {
		formData.Set(k, v)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, action.LoginURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Add extra headers
	for k, v := range action.ExtraHeaders {
		req.Header.Set(k, v)
	}

	client := &http.Client{
		Timeout: authHTTPTimeout,
		// Don't follow redirects — we want the Set-Cookie from the login response
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	state := &AuthState{
		FlowID:   action.FlowID,
		FlowType: "form-login",
		LoginURL: action.LoginURL,
		IssuedAt: time.Now(),
	}

	// Extract cookies from response
	state.Cookies = resp.Cookies()

	// Look for CSRF tokens in cookies
	for _, c := range state.Cookies {
		lname := strings.ToLower(c.Name)
		if strings.Contains(lname, "csrf") || strings.Contains(lname, "xsrf") {
			state.CSRFToken = c.Value
		}
	}

	// Try to parse response body for tokens (some login APIs return JSON)
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err == nil && len(bodyBytes) > 0 {
		var tokenResp map[string]interface{}
		if json.Unmarshal(bodyBytes, &tokenResp) == nil {
			if token, ok := tokenResp["access_token"].(string); ok && token != "" {
				state.AccessToken = token
			} else if token, ok := tokenResp["token"].(string); ok && token != "" {
				state.AccessToken = token
			}

			if refresh, ok := tokenResp["refresh_token"].(string); ok {
				state.RefreshToken = refresh
			}

			if tokenType, ok := tokenResp["token_type"].(string); ok {
				state.TokenType = tokenType
			}

			if expiresIn, ok := tokenResp["expires_in"].(float64); ok && expiresIn > 0 {
				state.ExpiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
			}

			if csrf, ok := tokenResp["csrf_token"].(string); ok && csrf != "" {
				state.CSRFToken = csrf
			}
		}
	}

	// Check for CSRF token in response headers
	for _, headerName := range []string{"X-CSRF-Token", "X-XSRF-Token", "X-Csrf-Token"} {
		if val := resp.Header.Get(headerName); val != "" {
			state.CSRFToken = val
		}
	}

	// Validate: must have gotten cookies or a token
	if len(state.Cookies) == 0 && state.AccessToken == "" {
		return nil, fmt.Errorf("login returned HTTP %d but no cookies or tokens were received; check if the login URL and credentials are correct", resp.StatusCode)
	}

	return state, nil
}

// ──────────────────── OAuth2 Client Credentials Flow ────────────────────

// executeOAuth2CC performs an OAuth2 client_credentials grant
func executeOAuth2CC(ctx context.Context, action *AuthLoginAction) (*AuthState, error) {
	if action.LoginURL == "" {
		return nil, fmt.Errorf("login_url (token endpoint) is required for oauth2-cc flow")
	}
	if action.ClientID == "" {
		return nil, fmt.Errorf("client_id is required for oauth2-cc flow")
	}
	if action.ClientSecret == "" {
		return nil, fmt.Errorf("client_secret is required for oauth2-cc flow")
	}

	formData := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {action.ClientID},
		"client_secret": {action.ClientSecret},
	}
	if action.Scope != "" {
		formData.Set("scope", action.Scope)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, action.LoginURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Add extra headers
	for k, v := range action.ExtraHeaders {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: authHTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("token endpoint returned HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}

	state, err := parseOAuth2TokenResponse(resp)
	if err != nil {
		return nil, err
	}

	state.FlowID = action.FlowID
	state.FlowType = "oauth2-cc"
	state.LoginURL = action.LoginURL
	state.ClientID = action.ClientID
	state.ClientSecret = action.ClientSecret
	state.Scope = action.Scope

	return state, nil
}

// parseOAuth2TokenResponse parses a standard OAuth2 token response
func parseOAuth2TokenResponse(resp *http.Response) (*AuthState, error) {
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("failed to read token response body: %w", err)
	}

	var tokenResp struct {
		AccessToken  string  `json:"access_token"`
		TokenType    string  `json:"token_type"`
		ExpiresIn    float64 `json:"expires_in"`
		RefreshToken string  `json:"refresh_token"`
		Scope        string  `json:"scope"`
		Error        string  `json:"error"`
		ErrorDesc    string  `json:"error_description"`
	}

	if err := json.Unmarshal(bodyBytes, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response as JSON: %w (body: %s)", err, truncate(string(bodyBytes), 512))
	}

	if tokenResp.Error != "" {
		return nil, fmt.Errorf("OAuth2 error: %s — %s", tokenResp.Error, tokenResp.ErrorDesc)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("token response did not contain access_token (body: %s)", truncate(string(bodyBytes), 512))
	}

	now := time.Now()
	state := &AuthState{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		IssuedAt:     now,
	}

	if state.TokenType == "" {
		state.TokenType = "Bearer"
	}

	if tokenResp.ExpiresIn > 0 {
		state.ExpiresAt = now.Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	// Also capture cookies from the token response
	state.Cookies = resp.Cookies()

	return state, nil
}

// ──────────────────── API Key Flow ────────────────────

// executeAPIKey stores a static API key for injection into requests
func executeAPIKey(ctx context.Context, action *AuthLoginAction) (*AuthState, error) {
	if action.APIKey == "" {
		return nil, fmt.Errorf("api_key is required for api-key flow")
	}

	header := action.APIKeyHeader
	if header == "" {
		header = "X-API-Key"
	}

	state := &AuthState{
		FlowID:       action.FlowID,
		FlowType:     "api-key",
		APIKey:       action.APIKey,
		APIKeyHeader: header,
		IssuedAt:     time.Now(),
	}

	return state, nil
}

// ──────────────────── Custom Flow ────────────────────

// executeCustomFlow handles custom auth by parsing the action's fields.
// Note: actual command execution should be done via the terminal tool.
// This flow stores the provided tokens/keys directly.
func executeCustomFlow(ctx context.Context, action *AuthLoginAction) (*AuthState, error) {
	// For custom flows, we expect the agent to have already obtained tokens
	// via terminal commands and is now storing them.
	// The custom_cmd field documents what was done but we parse results
	// from the other fields.

	state := &AuthState{
		FlowID:   action.FlowID,
		FlowType: "custom",
		IssuedAt: time.Now(),
		Headers:  make(map[string]string),
	}

	// Check if API key was provided
	if action.APIKey != "" {
		header := action.APIKeyHeader
		if header == "" {
			header = "Authorization"
		}
		if strings.HasPrefix(header, "?") {
			state.APIKey = action.APIKey
			state.APIKeyHeader = header
		} else {
			state.Headers[header] = action.APIKey
		}
	}

	// Check extra headers — treat these as session headers
	for k, v := range action.ExtraHeaders {
		state.Headers[k] = v
	}

	// If no auth material was provided at all, return an error
	if state.APIKey == "" && len(state.Headers) == 0 {
		return nil, fmt.Errorf("custom flow requires at least one of: api_key or extra_headers with auth data. " +
			"Run the custom command via terminal first, then use auth_login with the obtained tokens/keys")
	}

	return state, nil
}

// truncate a string to maxLen characters
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
