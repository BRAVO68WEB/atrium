package service

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	qrcode "github.com/skip2/go-qrcode"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/repository"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

type TOTPService struct {
	userRepo *repository.UserRepository
	cfg      *config.MFAConfig
}

type TOTPEnrollResult struct {
	Secret    string
	QRCodeURI string
	QRPNG     []byte
	QRBase64  string
}

func NewTOTPService(userRepo *repository.UserRepository, cfg *config.MFAConfig) *TOTPService {
	defer telemetry.Step("service.NewTOTPService")()
	return &TOTPService{
		userRepo: userRepo,
		cfg:      cfg,
	}
}

func (s *TOTPService) GenerateEnrollment(username string) (*TOTPEnrollResult, error) {
	defer telemetry.Step("service.TOTPService.GenerateEnrollment")()
	issuer := s.cfg.Issuer
	if issuer == "" {
		issuer = "OAuthImplServer"
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: username,
		SecretSize:  20,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP key: %w", err)
	}

	pngBytes, err := qrcode.Encode(key.URL(), qrcode.Medium, 256)
	if err != nil {
		return nil, fmt.Errorf("failed to generate QR code: %w", err)
	}

	qrBase64 := base64.StdEncoding.EncodeToString(pngBytes)

	return &TOTPEnrollResult{
		Secret:    key.Secret(),
		QRCodeURI: key.URL(),
		QRPNG:     pngBytes,
		QRBase64:  qrBase64,
	}, nil
}

func (s *TOTPService) GenerateQRImage(secret string, size int) ([]byte, error) {
	defer telemetry.Step("service.TOTPService.GenerateQRImage")()
	issuer := s.cfg.Issuer
	if issuer == "" {
		issuer = "OAuthImplServer"
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: "user",
		SecretSize:  20,
	})
	if err != nil {
		return nil, err
	}

	qrBytes, err := qrcode.Encode(key.URL(), qrcode.Medium, size)
	if err != nil {
		return nil, err
	}

	return qrBytes, nil
}

func (s *TOTPService) GenerateQRText(uri string) (string, error) {
	defer telemetry.Step("service.TOTPService.GenerateQRText")()
	qr, err := qrcode.New(uri, qrcode.Medium)
	if err != nil {
		return "", err
	}
	return qr.ToSmallString(false), nil
}

func (s *TOTPService) GenerateQRImageFromURI(uri string, size int) ([]byte, error) {
	defer telemetry.Step("service.TOTPService.GenerateQRImageFromURI")()
	return qrcode.Encode(uri, qrcode.Medium, size)
}

func (s *TOTPService) GenerateQRBase64FromURI(uri string, size int) (string, error) {
	defer telemetry.Step("service.TOTPService.GenerateQRBase64FromURI")()
	pngBytes, err := qrcode.Encode(uri, qrcode.Medium, size)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pngBytes), nil
}

func (s *TOTPService) GenerateQRImageBytes(key *otp.Key, size int) ([]byte, error) {
	defer telemetry.Step("service.TOTPService.GenerateQRImageBytes")()
	return qrcode.Encode(key.URL(), qrcode.Medium, size)
}

func (s *TOTPService) GenerateQRBase64(key *otp.Key, size int) (string, error) {
	defer telemetry.Step("service.TOTPService.GenerateQRBase64")()
	pngBytes, err := qrcode.Encode(key.URL(), qrcode.Medium, size)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pngBytes), nil
}

func (s *TOTPService) GenerateQRImagePNG(key *otp.Key, width, height int) ([]byte, error) {
	defer telemetry.Step("service.TOTPService.GenerateQRImagePNG")()
	img, err := key.Image(width, height)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s *TOTPService) GenerateQRBase64FromKey(key *otp.Key, width, height int) (string, error) {
	defer telemetry.Step("service.TOTPService.GenerateQRBase64FromKey")()
	pngBytes, err := s.GenerateQRImagePNG(key, width, height)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pngBytes), nil
}

func (s *TOTPService) ValidateCode(secret, code string) bool {
	defer telemetry.Step("service.TOTPService.ValidateCode")()
	return totp.Validate(code, secret)
}

func (s *TOTPService) EnableMFA(userID, username string) (*TOTPEnrollResult, error) {
	defer telemetry.Step("service.TOTPService.EnableMFA")()
	issuer := s.cfg.Issuer
	if issuer == "" {
		issuer = "OAuthImplServer"
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: username,
		SecretSize:  20,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP key: %w", err)
	}

	secret := key.Secret()

	// Store the pending secret
	if err := s.userRepo.SavePendingSecret(userID, secret); err != nil {
		return nil, fmt.Errorf("failed to save pending secret: %w", err)
	}

	pngBytes, err := qrcode.Encode(key.URL(), qrcode.Medium, 256)
	if err != nil {
		return nil, fmt.Errorf("failed to generate QR code: %w", err)
	}

	qrBase64 := base64.StdEncoding.EncodeToString(pngBytes)

	return &TOTPEnrollResult{
		Secret:    secret,
		QRCodeURI: key.URL(),
		QRPNG:     pngBytes,
		QRBase64:  qrBase64,
	}, nil
}

func (s *TOTPService) ConfirmMFA(userID, code string) error {
	defer
	// Get the pending secret
	telemetry.Step("service.TOTPService.ConfirmMFA")()

	secret, err := s.userRepo.GetPendingSecret(userID)
	if err != nil {
		return fmt.Errorf("no pending MFA enrollment found")
	}

	if !s.ValidateCode(secret, code) {
		return fmt.Errorf("invalid TOTP code")
	}

	// Enable MFA and clear pending secret
	return s.userRepo.UpdateMFA(userID, true, secret)
}

func (s *TOTPService) VerifyLogin(userID, code string) (bool, error) {
	defer telemetry.Step("service.TOTPService.VerifyLogin")()
	mfaEnabled, secret, err := s.userRepo.GetMFA(userID)
	if err != nil {
		return false, fmt.Errorf("failed to get MFA status: %w", err)
	}

	if !mfaEnabled {
		return true, nil
	}

	return s.ValidateCode(secret, code), nil
}

func (s *TOTPService) IsMFAEnabled(userID string) (bool, error) {
	defer telemetry.Step("service.TOTPService.IsMFAEnabled")()
	mfaEnabled, _, err := s.userRepo.GetMFA(userID)
	return mfaEnabled, err
}

func (s *TOTPService) DisableMFA(userID string) error {
	defer telemetry.Step("service.TOTPService.DisableMFA")()
	return s.userRepo.UpdateMFA(userID, false, "")
}
