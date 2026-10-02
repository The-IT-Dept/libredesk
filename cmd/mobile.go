package main

import (
	"strings"

	"github.com/abhinavxd/libredesk/internal/envelope"
	realip "github.com/ferluci/fast-realip"
	"github.com/valyala/fasthttp"
	"github.com/zerodha/fastglue"
)

// Handlers for the native agent app (github.com/The-IT-Dept/libredesk-mobile). See internal/mobile.

type mobileLoginRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	DeviceName string `json:"device_name"`
	Platform   string `json:"platform"`
}

// handleMobileLogin checks the agent's password like the web login, then issues a device token.
func handleMobileLogin(r *fastglue.Request) error {
	var (
		app = r.Context.(*App)
		req mobileLoginRequest
	)
	if err := r.Decode(&req, "json"); err != nil || req.Email == "" || req.Password == "" {
		return r.SendErrorEnvelope(fasthttp.StatusBadRequest, app.i18n.T("globals.messages.badRequest"), nil, envelope.InputError)
	}
	user, err := app.user.VerifyPassword(req.Email, []byte(req.Password))
	if err != nil {
		return sendErrorEnvelope(r, err)
	}
	if !user.Enabled {
		return sendErrorEnvelope(r, envelope.NewError(envelope.GeneralError, app.i18n.T("user.accountDisabled"), nil))
	}
	token, err := app.mobile.CreateDevice(user.ID, req.DeviceName, req.Platform)
	if err != nil {
		app.lo.Error("error creating mobile device", "error", err)
		return sendErrorEnvelope(r, envelope.NewError(envelope.GeneralError, app.i18n.T("globals.messages.somethingWentWrong"), nil))
	}
	if err := app.user.UpdateLastLoginAt(user.ID); err != nil {
		app.lo.Error("error updating last login", "error", err)
	}
	if err := app.activityLog.Login(user.ID, user.Email.String, realip.FromRequest(r.RequestCtx)); err != nil {
		app.lo.Error("error creating login activity log", "error", err)
	}
	return r.SendEnvelope(map[string]any{"token": token, "user": user})
}

// handleMobilePushToken stores the calling device's Expo push token.
func handleMobilePushToken(r *fastglue.Request) error {
	var (
		app = r.Context.(*App)
		req struct {
			Token string `json:"expo_push_token"`
		}
	)
	deviceID, ok := r.RequestCtx.UserValue("mobile_device_id").(int64)
	if !ok {
		return r.SendErrorEnvelope(fasthttp.StatusBadRequest, "only the mobile app can register a push token", nil, envelope.InputError)
	}
	if err := r.Decode(&req, "json"); err != nil || !strings.HasPrefix(req.Token, "ExponentPushToken[") {
		return r.SendErrorEnvelope(fasthttp.StatusBadRequest, app.i18n.T("globals.messages.badRequest"), nil, envelope.InputError)
	}
	if err := app.mobile.SetPushToken(deviceID, req.Token); err != nil {
		app.lo.Error("error saving expo push token", "error", err)
		return sendErrorEnvelope(r, envelope.NewError(envelope.GeneralError, app.i18n.T("globals.messages.somethingWentWrong"), nil))
	}
	return r.SendEnvelope(true)
}

// handleMobileLogout deletes the calling device (its token and push token).
func handleMobileLogout(r *fastglue.Request) error {
	app := r.Context.(*App)
	if deviceID, ok := r.RequestCtx.UserValue("mobile_device_id").(int64); ok {
		if err := app.mobile.DeleteDevice(deviceID); err != nil {
			app.lo.Error("error deleting mobile device", "error", err)
		}
	}
	return r.SendEnvelope(true)
}
