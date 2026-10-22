package repository

import (
	"database/sql"
	"time"

	"github.com/google/uuid"

	"github.com/bravo68web/oauth-impl/internal/database"
	"github.com/bravo68web/oauth-impl/internal/models"
)

type LoginEventRepository struct {
	db database.SQL
}

func NewLoginEventRepository(db database.SQL) *LoginEventRepository {
	return &LoginEventRepository{db: db}
}

func (r *LoginEventRepository) Insert(ev *models.LoginEvent) error {
	if ev.ID == "" {
		ev.ID = uuid.NewString()
	}
	if ev.CreatedAt.IsZero() {
		ev.CreatedAt = time.Now()
	}
	_, err := r.db.Exec(`INSERT INTO login_events (id, user_id, success, mfa, ip, user_agent, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ev.ID, ev.UserID, boolInt(ev.Success), boolInt(ev.MFA), ev.IP, ev.UserAgent, ev.CreatedAt,
	)
	return err
}

// LatestIP returns the newest stored address for userID.
// Mail uses this row instead of the request header.
func (r *LoginEventRepository) LatestIP(userID string) (string, error) {
	var ip string
	err := r.db.QueryRow(`SELECT COALESCE(ip, '') FROM login_events
		WHERE user_id = ? AND COALESCE(ip, '') <> ''
		ORDER BY created_at DESC LIMIT 1`, userID).Scan(&ip)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return ip, err
}

func (r *LoginEventRepository) ListByUser(userID string, limit int) ([]*models.LoginEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.db.Query(`SELECT id, user_id, success, mfa, COALESCE(ip, ''), COALESCE(user_agent, ''), created_at
		FROM login_events WHERE user_id = ? ORDER BY created_at DESC LIMIT ?`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make([]*models.LoginEvent, 0)
	for rows.Next() {
		ev := &models.LoginEvent{}
		var success, mfa int
		var created dbTime
		if err := rows.Scan(&ev.ID, &ev.UserID, &success, &mfa, &ev.IP, &ev.UserAgent, &created); err != nil {
			return nil, err
		}
		ev.CreatedAt = created.Time
		ev.Success = success != 0
		ev.MFA = mfa != 0
		out = append(out, ev)
	}
	return out, rows.Err()
}

func (r *LoginEventRepository) CountFailuresSince(userID string, since time.Time) (int, error) {
	var n int
	err := r.db.QueryRow(`SELECT COUNT(*) FROM login_events WHERE user_id = ? AND success = 0 AND created_at >= ?`, userID, since).Scan(&n)
	return n, err
}

func (r *LoginEventRepository) HasIP(userID, ip string) (bool, error) {
	if ip == "" {
		return false, nil
	}
	var n int
	err := r.db.QueryRow(`SELECT COUNT(*) FROM login_events WHERE user_id = ? AND ip = ?`, userID, ip).Scan(&n)
	return n > 0, err
}

func (r *LoginEventRepository) Analytics(userID string, since time.Time) (*models.LoginAnalytics, error) {
	where := `created_at >= ?`
	args := []any{since}
	if userID != "" {
		where += ` AND user_id = ?`
		args = append(args, userID)
	}

	byIP, err := r.ipStats(where, args, userID, since)
	if err != nil {
		return nil, err
	}
	byDay, err := r.dayStats(where, args)
	if err != nil {
		return nil, err
	}
	out := &models.LoginAnalytics{
		UserID: userID,
		From:   since,
		To:     time.Now(),
		ByIP:   byIP,
		ByDay:  byDay,
	}
	users := map[string]struct{}{}
	for _, row := range byIP {
		out.Attempts += row.Attempts
		out.Successes += row.Successes
		out.Failures += row.Failures
		out.MFAAttempts += row.MFA
		if row.IP != "" {
			out.UniqueIPs++
		}
		if row.New {
			out.NewIPs++
		}
	}
	if userID == "" {
		rows, err := r.db.Query(`SELECT DISTINCT user_id FROM login_events WHERE `+where, args...)
		if err != nil {
			return nil, err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return nil, err
			}
			users[id] = struct{}{}
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		out.UniqueUsers = len(users)
	}
	if out.Attempts > 0 {
		out.FailureRate = float64(out.Failures) / float64(out.Attempts)
	}
	return out, nil
}

func (r *LoginEventRepository) ipStats(where string, args []any, userID string, since time.Time) ([]models.IPLoginStat, error) {
	userCount := `0`
	if userID == "" {
		userCount = `COUNT(DISTINCT user_id)`
	}
	query := `SELECT COALESCE(ip, ''), COUNT(*),
		COALESCE(SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN mfa = 1 THEN 1 ELSE 0 END), 0),
		` + userCount + `,
		MIN(created_at), MAX(created_at)
		FROM login_events WHERE ` + where + ` GROUP BY ip ORDER BY MAX(created_at) DESC`
	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var stats []models.IPLoginStat
	for rows.Next() {
		var row models.IPLoginStat
		var first, last dbTime
		if err := rows.Scan(&row.IP, &row.Attempts, &row.Successes, &row.Failures, &row.MFA, &row.Users, &first, &last); err != nil {
			return nil, err
		}
		row.FirstSeen = first.Time
		row.LastSeen = last.Time
		stats = append(stats, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if stats == nil {
		stats = []models.IPLoginStat{}
	}
	first, err := r.firstSeen(userID)
	if err != nil {
		return nil, err
	}
	agents, err := r.lastAgents(where, args)
	if err != nil {
		return nil, err
	}
	for i := range stats {
		if agent, ok := agents[stats[i].IP]; ok {
			stats[i].LastUserAgent = agent
		}
		if seen, ok := first[stats[i].IP]; ok && !seen.Before(since) {
			stats[i].New = true
		}
	}
	return stats, nil
}

func (r *LoginEventRepository) firstSeen(userID string) (map[string]time.Time, error) {
	query := `SELECT COALESCE(ip, ''), MIN(created_at) FROM login_events`
	var args []any
	if userID != "" {
		query += ` WHERE user_id = ?`
		args = append(args, userID)
	}
	query += ` GROUP BY ip`
	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]time.Time{}
	for rows.Next() {
		var ip string
		var at dbTime
		if err := rows.Scan(&ip, &at); err != nil {
			return nil, err
		}
		out[ip] = at.Time
	}
	return out, rows.Err()
}

func (r *LoginEventRepository) lastAgents(where string, args []any) (map[string]string, error) {
	query := `SELECT COALESCE(e.ip, ''), COALESCE(e.user_agent, '')
		FROM login_events e
		JOIN (
			SELECT COALESCE(ip, '') AS ip, MAX(created_at) AS mx
			FROM login_events WHERE ` + where + ` GROUP BY ip
		) t ON COALESCE(e.ip, '') = t.ip AND e.created_at = t.mx`
	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var ip, agent string
		if err := rows.Scan(&ip, &agent); err != nil {
			return nil, err
		}
		if _, ok := out[ip]; !ok {
			out[ip] = agent
		}
	}
	return out, rows.Err()
}

func (r *LoginEventRepository) dayStats(where string, args []any) ([]models.DayLoginStat, error) {
	day := `substr(created_at, 1, 10)`
	if r.db.Dialect() == "postgres" {
		day = `to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD')`
	}
	rows, err := r.db.Query(`SELECT `+day+`,
		COALESCE(SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END), 0)
		FROM login_events WHERE `+where+` GROUP BY `+day+` ORDER BY `+day, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []models.DayLoginStat{}
	for rows.Next() {
		var row models.DayLoginStat
		if err := rows.Scan(&row.Date, &row.Successes, &row.Failures); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
