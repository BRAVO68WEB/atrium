//go:build embed

package dashboard

import (
	"embed"
	"io/fs"
)

// The Vite build writes this directory. `go build -tags embed` serves it
// from the atrium binary. `go test` without the tag uses the stub page.

//go:embed all:dist
var distFS embed.FS

func assetFS() fs.FS {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}

func uiEmbedded() bool { return true }
