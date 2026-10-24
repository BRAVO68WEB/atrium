package testpg

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/database"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

func init() {
	// go test runs each package as its own process under one parent.
	// testcontainers derives a single session id from that parent pid, so
	// every package shares one Ryuk. A package that starts after Ryuk has
	// exited still finds the stopped container and blocks on the 60s
	// readiness check. The reaper retry budget is 20s, so that wait is
	// never tried again, and startOnce keeps the error for every test in
	// the package. A session id of our own gives this process its own Ryuk.
	if os.Getenv("TESTCONTAINERS_SESSION_ID") == "" {
		_ = os.Setenv("TESTCONTAINERS_SESSION_ID", newSessionID())
	}
}

// Instance is one Postgres container shared by a process.
type Instance struct {
	container *postgres.PostgresContainer
	adminDSN  string
	admin     *sql.DB
}

var (
	startOnce sync.Once
	shared    *Instance
	startErr  error
)

// Start launches Postgres 16. Later calls in the same process reuse it.
// The container is removed when the process exits.
func Start(ctx context.Context) (*Instance, error) {
	startOnce.Do(func() {
		shared, startErr = launch(ctx)
	})
	if startErr != nil {
		return nil, startErr
	}
	return shared, nil
}

func launch(ctx context.Context) (*Instance, error) {
	container, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("oauth"),
		postgres.WithUsername("oauth"),
		postgres.WithPassword("oauth"),
		// BasicWaitStrategies waits until Postgres logs that it is ready, then
		// until the port is open. Replacing that with a port-only wait reports
		// ready while the server still rejects connections with SQLSTATE 57P03.
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		return nil, fmt.Errorf("start postgres: %w", err)
	}
	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("postgres dsn: %w", err)
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		_ = container.Terminate(context.Background())
		return nil, err
	}
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := admin.PingContext(pingCtx); err != nil {
		_ = admin.Close()
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("postgres ping: %w", err)
	}
	return &Instance{container: container, adminDSN: dsn, admin: admin}, nil
}

// Terminate stops the container. Tests leave this to process exit.
func (in *Instance) Terminate(ctx context.Context) error {
	if in == nil {
		return nil
	}
	if in.admin != nil {
		_ = in.admin.Close()
	}
	if in.container != nil {
		return in.container.Terminate(ctx)
	}
	return nil
}

// CreateDB makes an empty database and returns its DSN.
func (in *Instance) CreateDB(ctx context.Context) (string, error) {
	name, err := randomName()
	if err != nil {
		return "", err
	}
	if _, err := in.admin.ExecContext(ctx, "CREATE DATABASE "+name); err != nil {
		return "", fmt.Errorf("create database %s: %w", name, err)
	}
	u, err := url.Parse(in.adminDSN)
	if err != nil {
		return "", err
	}
	u.Path = "/" + name
	return u.String(), nil
}

func randomName() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "t_" + hex.EncodeToString(buf), nil
}

// newSessionID returns 64 hex characters, the length testcontainers uses
// for the reaper container name.
func newSessionID() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		copy(buf, []byte(fmt.Sprintf("%032d", os.Getpid())))
	}
	return hex.EncodeToString(buf)
}

// Open returns a migrated database in its own Postgres database.
func Open(t testing.TB) *database.DB {
	t.Helper()
	db, _ := OpenDSN(t)
	return db
}

// OpenDSN returns the migrated database and the DSN used to reopen it.
func OpenDSN(t testing.TB) (*database.DB, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	inst, err := Start(ctx)
	if err != nil {
		t.Fatalf("postgres: %v", err)
	}
	dsn, err := inst.CreateDB(ctx)
	if err != nil {
		t.Fatalf("postgres database: %v", err)
	}
	return Connect(t, dsn), dsn
}

// Connect opens an existing DSN and migrates it.
func Connect(t testing.TB, dsn string) *database.DB {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Database.Driver = "postgres"
	cfg.Database.DSN = dsn
	db, err := database.Open(cfg)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(); err != nil {
		t.Fatalf("migrate postgres: %v", err)
	}
	return db
}
