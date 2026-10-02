// Package oauth provides OAuth 2.0 authentication support for email channels.
package oauth

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
)

// Provider represents an OAuth provider.
type Provider string

const (
	ProviderMicrosoft Provider = "microsoft"
	ProviderGoogle    Provider = "google"
)

// Scopes for each provider.
var (
	MicrosoftScopes = []string{
		"https://outlook.office.com/IMAP.AccessAsUser.All",
		"https://outlook.office.com/SMTP.Send",
		"offline_access",
		"openid",
		"email",
	}
	GoogleScopes = []string{
		"https://mail.google.com/",
		"https://www.googleapis.com/auth/userinfo.email",
	}
)

// GetOAuth2Config returns an oauth2.Config for the given provider.
func GetOAuth2Config(provider Provider, clientID, clientSecret, redirectURI string, tenantID ...string) (*oauth2.Config, error) {
	switch provider {
	case ProviderMicrosoft:
		tenant := "common"
		if len(tenantID) > 0 && tenantID[0] != "" {
			tenant = tenantID[0]
		}
		return &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURI,
			Scopes:       MicrosoftScopes,
			Endpoint:     microsoft.AzureADEndpoint(tenant),
		}, nil
	case ProviderGoogle:
		return &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURI,
			Scopes:       GoogleScopes,
			Endpoint:     google.Endpoint,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported OAuth provider: %s", provider)
	}
}

// MicrosoftAppScope is the scope requested for app-only (client credentials) access to Exchange
// Online. The app needs the IMAP.AccessAsApp and SMTP.SendAsApp application permissions, and an
// Exchange service principal with access to the mailbox.
const MicrosoftAppScope = "https://outlook.office365.com/.default"

// AppOnlyToken gets an app-only Microsoft token with the client credentials grant. This is how
// inboxes for shared mailboxes authenticate: they have no user to sign in as, so there is no
// refresh token.
func AppOnlyToken(ctx context.Context, clientID, clientSecret, tenantID string) (*oauth2.Token, error) {
	if tenantID == "" || tenantID == "common" {
		return nil, fmt.Errorf("app-only Microsoft auth needs a tenant ID")
	}
	cfg := &clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     microsoft.AzureADEndpoint(tenantID).TokenURL,
		Scopes:       []string{MicrosoftAppScope},
	}
	return cfg.Token(ctx)
}

// ExchangeCodeForToken exchanges an authorization code for access and refresh tokens.
func ExchangeCodeForToken(ctx context.Context, provider Provider, clientID, clientSecret, code, redirectURI string, tenantID ...string) (*oauth2.Token, error) {
	cfg, err := GetOAuth2Config(provider, clientID, clientSecret, redirectURI, tenantID...)
	if err != nil {
		return nil, err
	}
	return cfg.Exchange(ctx, code)
}

// RefreshToken exchanges a refresh token for a new access token.
func RefreshToken(ctx context.Context, provider Provider, clientID, clientSecret, refreshToken string, tenantID ...string) (*oauth2.Token, error) {
	cfg, err := GetOAuth2Config(provider, clientID, clientSecret, "", tenantID...)
	if err != nil {
		return nil, err
	}

	oldToken := &oauth2.Token{
		RefreshToken: refreshToken,
	}

	src := cfg.TokenSource(ctx, oldToken)
	return src.Token()
}

// BuildAuthorizationURL builds the OAuth authorization URL.
func BuildAuthorizationURL(provider Provider, clientID, redirectURI, state string, tenantID ...string) (string, error) {
	cfg, err := GetOAuth2Config(provider, "", "", redirectURI, tenantID...)
	if err != nil {
		return "", err
	}
	cfg.ClientID = clientID

	// Google requires prompt=consent to issue a refresh token on re-authentication.
	if provider == ProviderGoogle {
		return cfg.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.ApprovalForce), nil
	}
	return cfg.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "select_account")), nil
}

// IsTokenExpired checks if an access token has expired or is about to expire.
// Returns true if the token will expire in the next 5 minutes.
func IsTokenExpired(expiresAt time.Time) bool {
	return time.Now().Add(5 * time.Minute).After(expiresAt)
}
