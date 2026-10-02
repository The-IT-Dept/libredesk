// Package mobile handles the native agent app (github.com/The-IT-Dept/libredesk-mobile): per-device
// login tokens, which the app sends as "Authorization: Bearer ldm_...", and Expo push notifications.
//
// It lives outside the versioned migrations so the fork stays easy to rebase: its table is created
// on startup if missing.
package mobile

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/zerodha/logf"
)

// TokenPrefix marks a mobile device token in the Authorization header.
const TokenPrefix = "ldm_"

const (
	expoPushURL   = "https://exp.host/--/api/v2/push/send"
	expoBatchSize = 100
)

const schema = `
CREATE TABLE IF NOT EXISTS mobile_devices (
	id BIGSERIAL PRIMARY KEY,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
	token_hash TEXT NOT NULL UNIQUE,
	name TEXT NOT NULL DEFAULT '',
	platform TEXT NOT NULL DEFAULT '',
	expo_push_token TEXT
);
CREATE INDEX IF NOT EXISTS index_mobile_devices_on_user_id ON mobile_devices(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS index_mobile_devices_on_expo_push_token ON mobile_devices(expo_push_token);
`

// Device is a signed-in installation of the mobile app.
type Device struct {
	ID       int64  `db:"id"`
	UserID   int    `db:"user_id"`
	Name     string `db:"name"`
	Platform string `db:"platform"`
}

// PushMessage is what gets shown on the device. URL is the web route of the conversation, which the
// app maps to its own screen.
type PushMessage struct {
	Title            string
	Body             string
	Tag              string
	URL              string
	ConversationUUID string
}

type Manager struct {
	db   *sqlx.DB
	lo   *logf.Logger
	http *http.Client
}

func New(db *sqlx.DB, lo *logf.Logger) (*Manager, error) {
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("creating mobile_devices table: %w", err)
	}
	return &Manager{db: db, lo: lo, http: &http.Client{Timeout: 15 * time.Second}}, nil
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// CreateDevice registers a new device for the user and returns its token. Only the hash is stored.
func (m *Manager) CreateDevice(userID int, name, platform string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := TokenPrefix + hex.EncodeToString(b)
	_, err := m.db.Exec(`INSERT INTO mobile_devices (user_id, token_hash, name, platform) VALUES ($1, $2, $3, $4)`,
		userID, hashToken(token), truncate(name, 100), truncate(platform, 20))
	return token, err
}

// Authenticate returns the device a token belongs to.
func (m *Manager) Authenticate(token string) (Device, error) {
	var d Device
	err := m.db.Get(&d, `UPDATE mobile_devices SET last_seen_at = NOW() WHERE token_hash = $1
		RETURNING id, user_id, name, platform`, hashToken(token))
	return d, err
}

// SetPushToken stores the device's Expo push token, moving it off any other device row first (the
// token follows the installation, not the login).
func (m *Manager) SetPushToken(deviceID int64, pushToken string) error {
	tx, err := m.db.Beginx()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE mobile_devices SET expo_push_token = NULL WHERE expo_push_token = $1 AND id <> $2`, pushToken, deviceID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE mobile_devices SET expo_push_token = $1 WHERE id = $2`, pushToken, deviceID); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteDevice signs the device out.
func (m *Manager) DeleteDevice(deviceID int64) error {
	_, err := m.db.Exec(`DELETE FROM mobile_devices WHERE id = $1`, deviceID)
	return err
}

// Push sends a notification to every device of the user that has a push token. It runs on the
// web push worker, so it blocks.
func (m *Manager) Push(ctx context.Context, userID int, msg PushMessage) {
	var tokens []string
	if err := m.db.Select(&tokens, `SELECT expo_push_token FROM mobile_devices WHERE user_id = $1 AND expo_push_token IS NOT NULL`, userID); err != nil {
		m.lo.Error("error listing mobile push tokens", "user_id", userID, "error", err)
		return
	}
	for start := 0; start < len(tokens); start += expoBatchSize {
		end := min(start+expoBatchSize, len(tokens))
		m.sendBatch(ctx, tokens[start:end], msg)
	}
}

type expoMessage struct {
	To       string         `json:"to"`
	Title    string         `json:"title"`
	Body     string         `json:"body,omitempty"`
	Sound    string         `json:"sound"`
	Priority string         `json:"priority"`
	ThreadID string         `json:"threadId,omitempty"`
	Data     map[string]any `json:"data"`
}

type expoResponse struct {
	Data []struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Details struct {
			Error string `json:"error"`
		} `json:"details"`
	} `json:"data"`
}

func (m *Manager) sendBatch(ctx context.Context, tokens []string, msg PushMessage) {
	msgs := make([]expoMessage, len(tokens))
	for i, t := range tokens {
		msgs[i] = expoMessage{
			To: t, Title: msg.Title, Body: msg.Body, Sound: "default", Priority: "high",
			ThreadID: msg.ConversationUUID,
			Data:     map[string]any{"url": msg.URL, "conversation_uuid": msg.ConversationUUID, "tag": msg.Tag},
		}
	}
	body, _ := json.Marshal(msgs)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, expoPushURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := m.http.Do(req)
	if err != nil {
		m.lo.Error("error sending expo push", "error", err)
		return
	}
	defer resp.Body.Close()
	var out expoResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || resp.StatusCode >= 300 {
		m.lo.Error("expo push rejected", "status", resp.StatusCode, "error", err)
		return
	}
	for i, ticket := range out.Data {
		if ticket.Status == "ok" || i >= len(tokens) {
			continue
		}
		if ticket.Details.Error == "DeviceNotRegistered" {
			if _, err := m.db.Exec(`UPDATE mobile_devices SET expo_push_token = NULL WHERE expo_push_token = $1`, tokens[i]); err != nil {
				m.lo.Error("error clearing expo push token", "error", err)
			}
			continue
		}
		m.lo.Error("expo push ticket error", "error", ticket.Details.Error, "message", ticket.Message)
	}
}

// ConversationUUID pulls the conversation UUID out of a web push route like
// /inboxes/assigned/conversation/<uuid>?scrollTo=...
func ConversationUUID(route string) string {
	route, _, _ = strings.Cut(route, "?")
	if i := strings.LastIndex(route, "/conversation/"); i >= 0 {
		return strings.Trim(route[i+len("/conversation/"):], "/")
	}
	return ""
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}
