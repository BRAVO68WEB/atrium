//go:build !embed

package dashboard

import (
	"embed"
	"io/fs"
)

//go:embed stub/index.html
var stubFS embed.FS

func assetFS() fs.FS {
	sub, err := fs.Sub(stubFS, "stub")
	if err != nil {
		panic(err)
	}
	return sub
}

func uiEmbedded() bool { return false }
