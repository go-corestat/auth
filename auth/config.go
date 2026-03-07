package auth

import (
	"errors"
	"os"
	"strings"
	"time"
)

type Config struct {
	TenantID           string
	ClientID           string
	ClientSecret       string
	RedirectURI        string
	PostLoginRedirect  string
	PostLogoutRedirect string
	Scopes             []string
	StateTTL           time.Duration
	CookieSecure       bool
	CookieDomain       string
}

func ConfigFromEnv() (Config, error) {
	cfg := Config{
		TenantID:           strings.TrimSpace(os.Getenv("AZURE_TENANT_ID")),
		ClientID:           strings.TrimSpace(os.Getenv("AZURE_CLIENT_ID")),
		ClientSecret:       strings.TrimSpace(os.Getenv("AZURE_CLIENT_SECRET")),
		RedirectURI:        strings.TrimSpace(os.Getenv("AZURE_REDIRECT_URI")),
		PostLoginRedirect:  strings.TrimSpace(getEnv("AZURE_POST_LOGIN_REDIRECT", "/")),
		PostLogoutRedirect: strings.TrimSpace(getEnv("AZURE_POST_LOGOUT_REDIRECT", "/")),
		Scopes:             splitScopes(getEnv("AZURE_SCOPES", "openid profile email offline_access")),
		StateTTL:           getEnvDuration("AZURE_STATE_TTL", 10*time.Minute),
		CookieSecure:       getEnvBool("SESSION_COOKIE_SECURE", false),
		CookieDomain:       strings.TrimSpace(os.Getenv("SESSION_COOKIE_DOMAIN")),
	}

	if cfg.TenantID == "" || cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.RedirectURI == "" {
		return Config{}, errors.New("missing Azure OAuth config: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_REDIRECT_URI are required")
	}

	return cfg, nil
}

func splitScopes(raw string) []string {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return []string{"openid", "profile", "email", "offline_access"}
	}
	return fields
}

func getEnv(key, fallback string) string {
	value, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
