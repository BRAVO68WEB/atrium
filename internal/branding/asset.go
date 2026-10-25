package branding

import (
	"errors"
	"io"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/telemetry"
)

var errTooLarge = errors.New("asset exceeds 1MiB")

// AssetHandler serves one file from branding.assets_dir.
// The response CSP is stricter than the page CSP so an SVG opened on its own
// cannot run script. Callers that set a global CSP first still lose that
// header, because this handler replaces it before writing the body.
func AssetHandler(cfg *config.Config) http.HandlerFunc {
	defer telemetry.Step("branding.AssetHandler")()
	return func(w http.ResponseWriter, r *http.Request) {
		dir := ""
		if cfg != nil {
			dir = cfg.Branding.AssetsDir
		}
		if dir == "" {
			http.NotFound(w, r)
			return
		}
		f, ctype, err := openAsset(dir, chi.URLParam(r, "name"))
		if errors.Is(err, errTooLarge) {
			http.Error(w, "asset too large", http.StatusRequestEntityTooLarge)
			return
		}
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer func() { _ = f.Close() }()
		w.Header().Set("Content-Type", ctype)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'none'; sandbox")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = io.Copy(w, f)
	}
}

// AssetExists reports whether name is a file the asset handler would serve.
func AssetExists(dir, name string) bool {
	defer telemetry.Step("branding.AssetExists")()
	f, _, err := openAsset(dir, name)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

func openAsset(dir, name string) (io.ReadCloser, string, error) {
	defer telemetry.Step("branding.openAsset")()
	if !safeAssetName(name) {
		return nil, "", os.ErrNotExist
	}
	ctype := config.BrandAssetType(name)
	if ctype == "" {
		return nil, "", os.ErrNotExist
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, "", err
	}
	f, err := root.Open(name)
	if err != nil {
		_ = root.Close()
		return nil, "", err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		_ = root.Close()
		return nil, "", err
	}
	if info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		_ = f.Close()
		_ = root.Close()
		return nil, "", os.ErrNotExist
	}
	if info.Size() > config.MaxBrandAssetBytes {
		_ = f.Close()
		_ = root.Close()
		return nil, "", errTooLarge
	}
	return &rootedFile{ReadCloser: f, root: root}, ctype, nil
}

type rootedFile struct {
	io.ReadCloser
	root *os.Root
}

func (f *rootedFile) Close() error {
	defer telemetry.Step("branding.rootedFile.Close")()
	err := f.ReadCloser.Close()
	if closeErr := f.root.Close(); err == nil {
		err = closeErr
	}
	return err
}
