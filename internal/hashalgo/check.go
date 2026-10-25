// Package hashalgo is the password hasher compiled into the server.
// Edit algo.go only. That file exports one function, Hash.
package hashalgo

import (
	"bytes"
	_ "embed"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"

	"github.com/bravo68web/atrium/pkg/passhash"
)

// CanonicalRel is the hasher file, relative to the project root.
const CanonicalRel = "internal/hashalgo/algo.go"

const passhashPath = "github.com/bravo68web/atrium/pkg/passhash"

//go:embed algo.go
var embeddedAlgo []byte

// Prepare checks the on-disk hasher against this binary and returns it.
// start is the process working directory. envValue is HASH_ALGO.
// configValue is security.hash_algo. An empty value uses CanonicalRel.
func Prepare(start, envValue, configValue string) (passhash.Hasher, error) {
	path, err := ResolveServerPath(start, envValue, configValue)
	if err != nil {
		return nil, err
	}
	if err := Check(path); err != nil {
		return nil, err
	}
	if err := MatchesEmbedded(path); err != nil {
		return nil, err
	}
	return Hash(), nil
}

// ResolveServerPath returns the absolute canonical hasher path.
// HASH_ALGO and security.hash_algo must name that same file.
func ResolveServerPath(start, envValue, configValue string) (string, error) {
	canon, err := CanonicalFile(start)
	if err != nil {
		return "", err
	}
	raw := strings.TrimSpace(envValue)
	if raw == "" {
		raw = strings.TrimSpace(configValue)
	}
	if raw == "" {
		return canon, nil
	}
	if pathMatches(start, raw, canon) {
		return canon, nil
	}
	return "", fmt.Errorf("HASH_ALGO must be %s", CanonicalRel)
}

// CanonicalFile walks from start to the project hasher file.
func CanonicalFile(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		candidate := filepath.Join(dir, filepath.FromSlash(CanonicalRel))
		info, statErr := os.Stat(candidate)
		if statErr == nil && !info.IsDir() {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("cannot find %s; start the server from the project root", CanonicalRel)
		}
		dir = parent
	}
}

// Check parses path and requires one exported function: func Hash() passhash.Hasher.
func Check(path string) error {
	src, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read password hasher %s: %w", path, err)
	}
	return CheckSource(path, src)
}

// CheckSource is Check for a buffer. filename is used in error positions.
func CheckSource(filename string, src []byte) error {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, parser.AllErrors)
	if err != nil {
		return fmt.Errorf("parse password hasher: %w", err)
	}
	if file.Name == nil || file.Name.Name != "hashalgo" {
		got := ""
		if file.Name != nil {
			got = file.Name.Name
		}
		return fmt.Errorf("hasher file package must be hashalgo, found %s", got)
	}

	var exported []*ast.FuncDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Name == nil || !fn.Name.IsExported() {
			continue
		}
		exported = append(exported, fn)
	}
	if len(exported) != 1 || exported[0].Name.Name != "Hash" {
		return fmt.Errorf("hasher file must export exactly one function, named Hash")
	}

	importer := newSynthImporter()
	conf := types.Config{
		IgnoreFuncBodies:         true,
		DisableUnusedImportCheck: true,
		Importer:                 importer,
	}
	info := &types.Info{Defs: map[*ast.Ident]types.Object{}}
	if _, err := conf.Check("github.com/bravo68web/atrium/internal/hashalgo", fset, []*ast.File{file}, info); err != nil {
		return fmt.Errorf("typecheck password hasher: %w", err)
	}

	obj := info.Defs[exported[0].Name]
	fn, ok := obj.(*types.Func)
	if !ok || fn == nil {
		return fmt.Errorf("Hash must have signature func() passhash.Hasher")
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.TypeParams().Len() != 0 || sig.Params().Len() != 0 || sig.Results().Len() != 1 {
		return fmt.Errorf("Hash must have signature func() passhash.Hasher")
	}
	res := sig.Results().At(0).Type()
	named, ok := res.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Name() != "Hasher" || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != passhashPath {
		return fmt.Errorf("Hash must return passhash.Hasher")
	}
	return nil
}

// MatchesEmbedded reports whether path is the hasher compiled into this binary.
func MatchesEmbedded(path string) error {
	disk, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("password hasher %s not found; start the server from the project root", path)
		}
		return fmt.Errorf("read password hasher %s: %w", path, err)
	}
	if !bytes.Equal(disk, embeddedAlgo) {
		return fmt.Errorf("password hasher %s does not match this binary; run just build or just run from the project root", CanonicalRel)
	}
	return nil
}

// Install writes the hasher file under dir.
// external, when set, is copied onto the canonical file.
// A file that is not the shipped bcrypt template is left in place unless force is set.
// The shipped template may be replaced by --hash without force.
func Install(dir, hashKind, external string, force bool) (string, error) {
	if hashKind == "" {
		hashKind = "bcrypt"
	}
	if hashKind != "bcrypt" && hashKind != "argon2id" {
		return "", fmt.Errorf("unsupported --hash %q (use bcrypt or argon2id)", hashKind)
	}

	dest := filepath.Join(dir, filepath.FromSlash(CanonicalRel))
	existing, err := os.ReadFile(dest)
	missing := false
	if err != nil {
		if !os.IsNotExist(err) {
			return "", err
		}
		missing = true
	}
	stock := !missing && bytes.Equal(existing, []byte(BcryptTemplate()))
	if !missing && !stock && !force {
		if external != "" {
			return fmt.Sprintf("Kept existing password hasher at %s (HASH_ALGO was not copied; pass --force)", CanonicalRel), nil
		}
		return fmt.Sprintf("Kept existing password hasher at %s", CanonicalRel), nil
	}

	var content []byte
	switch {
	case external != "":
		content, err = os.ReadFile(external)
		if err != nil {
			return "", fmt.Errorf("read HASH_ALGO %s: %w", external, err)
		}
	case hashKind == "argon2id":
		content = []byte(Argon2Template)
	default:
		content = []byte(BcryptTemplate())
	}

	if err := CheckSource(dest, content); err != nil {
		return "", err
	}
	if !missing && bytes.Equal(existing, content) {
		return fmt.Sprintf("Password hasher already present at %s", CanonicalRel), nil
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(dest, content, 0o644); err != nil {
		return "", fmt.Errorf("write password hasher: %w", err)
	}
	if missing {
		return fmt.Sprintf("Password hasher written to %s", CanonicalRel), nil
	}
	return fmt.Sprintf("Password hasher updated at %s", CanonicalRel), nil
}

func pathMatches(start, raw, canon string) bool {
	canon = filepath.Clean(canon)
	if filepath.IsAbs(raw) {
		return filepath.Clean(raw) == canon
	}
	if filepath.Clean(filepath.Join(start, raw)) == canon {
		return true
	}
	root := moduleRootFromCanon(canon)
	return filepath.Clean(filepath.Join(root, raw)) == canon
}

func moduleRootFromCanon(canon string) string {
	rel := filepath.Clean(CanonicalRel)
	cleaned := filepath.Clean(canon)
	suffix := string(filepath.Separator) + rel
	if strings.HasSuffix(cleaned, suffix) {
		return filepath.Clean(strings.TrimSuffix(cleaned, suffix))
	}
	if strings.HasSuffix(cleaned, rel) {
		return filepath.Clean(strings.TrimSuffix(cleaned, rel))
	}
	return filepath.Dir(cleaned)
}

type synthImporter struct {
	pkgs map[string]*types.Package
}

func newSynthImporter() *synthImporter {
	return &synthImporter{pkgs: map[string]*types.Package{}}
}

func (s *synthImporter) Import(path string) (*types.Package, error) {
	if pkg, ok := s.pkgs[path]; ok {
		return pkg, nil
	}
	name := path
	if i := strings.LastIndex(path, "/"); i >= 0 {
		name = path[i+1:]
	}
	pkg := types.NewPackage(path, name)
	if path == passhashPath {
		iface := types.NewInterfaceType(nil, nil)
		iface.Complete()
		obj := types.NewTypeName(token.NoPos, pkg, "Hasher", nil)
		types.NewNamed(obj, iface, nil)
		pkg.Scope().Insert(obj)
	}
	pkg.MarkComplete()
	s.pkgs[path] = pkg
	return pkg, nil
}

func (s *synthImporter) ImportFrom(path, _ string, _ types.ImportMode) (*types.Package, error) {
	return s.Import(path)
}
