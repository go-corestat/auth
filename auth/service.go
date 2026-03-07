package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Service struct {
	config     Config
	httpClient *http.Client
}

type TokenResponse struct {
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int64  `json:"expires_in"`
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
}

type UserInfo struct {
	Sub               string `json:"sub"`
	Name              string `json:"name"`
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
}

type IDTokenClaims struct {
	TenantID string `json:"tid"`
}

func New(config Config) *Service {
	return &Service{
		config: config,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (s *Service) BuildAuthorizeURL(state string) string {
	values := url.Values{}
	values.Set("client_id", s.config.ClientID)
	values.Set("response_type", "code")
	values.Set("redirect_uri", s.config.RedirectURI)
	values.Set("response_mode", "query")
	values.Set("scope", strings.Join(s.config.Scopes, " "))
	values.Set("state", state)

	return fmt.Sprintf("%s?%s", s.authorizeEndpoint(), values.Encode())
}

func (s *Service) ExchangeCode(ctx context.Context, code string) (TokenResponse, error) {
	form := url.Values{}
	form.Set("client_id", s.config.ClientID)
	form.Set("client_secret", s.config.ClientSecret)
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", s.config.RedirectURI)
	form.Set("scope", strings.Join(s.config.Scopes, " "))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenEndpoint(), strings.NewReader(form.Encode()))
	if err != nil {
		return TokenResponse{}, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("exchange auth code: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("read token response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return TokenResponse{}, fmt.Errorf("token endpoint status %d: %s", resp.StatusCode, string(body))
	}

	var token TokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return TokenResponse{}, fmt.Errorf("decode token response: %w", err)
	}
	return token, nil
}

func (s *Service) FetchUserInfo(ctx context.Context, accessToken string) (UserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://graph.microsoft.com/oidc/userinfo", nil)
	if err != nil {
		return UserInfo{}, fmt.Errorf("create userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return UserInfo{}, fmt.Errorf("fetch userinfo: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return UserInfo{}, fmt.Errorf("read userinfo response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return UserInfo{}, fmt.Errorf("userinfo endpoint status %d: %s", resp.StatusCode, string(body))
	}

	var user UserInfo
	if err := json.Unmarshal(body, &user); err != nil {
		return UserInfo{}, fmt.Errorf("decode userinfo: %w", err)
	}
	return user, nil
}

func ParseIDTokenClaims(idToken string) (IDTokenClaims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return IDTokenClaims{}, fmt.Errorf("invalid id token")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return IDTokenClaims{}, fmt.Errorf("decode id token payload: %w", err)
	}

	var claims IDTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return IDTokenClaims{}, fmt.Errorf("parse id token claims: %w", err)
	}
	return claims, nil
}

func GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate oauth state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *Service) StateTTLSeconds() int {
	seconds := int(s.config.StateTTL.Seconds())
	if seconds <= 0 {
		return 600
	}
	return seconds
}

func (s *Service) CookieSecure() bool {
	return s.config.CookieSecure
}

func (s *Service) CookieDomain() string {
	return s.config.CookieDomain
}

func (s *Service) PostLoginRedirect() string {
	return s.config.PostLoginRedirect
}

func (s *Service) PostLogoutRedirect() string {
	return s.config.PostLogoutRedirect
}

func (s *Service) authorizeEndpoint() string {
	return fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/authorize", url.PathEscape(s.config.TenantID))
}

func (s *Service) tokenEndpoint() string {
	return fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", url.PathEscape(s.config.TenantID))
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(getEnv(key, ""))
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return value
}

func getEnvBool(key string, fallback bool) bool {
	raw := strings.TrimSpace(getEnv(key, ""))
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return value
}
