package dashboard

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/telemetry"
)

func (h *Handler) configPath() string {
	if h.cfg != nil && strings.TrimSpace(h.cfg.File) != "" {
		return h.cfg.File
	}
	return "config.yaml"
}

func (h *Handler) sourceConfig() *config.Config {
	path := ""
	if h.cfg != nil {
		path = strings.TrimSpace(h.cfg.File)
	}
	if path != "" {
		if cfg, err := config.Load(path); err == nil {
			return cfg
		}
	}
	return h.cfg
}

func (h *Handler) getConfig(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("dashboard.getConfig")()
	cfg := h.sourceConfig()
	doc := toMap(cfg)
	root, _ := doc.(map[string]any)
	if root == nil {
		root = map[string]any{}
	}
	delete(root, "file")
	maskSecrets(root)
	if notify, ok := root["notify"].(map[string]any); ok {
		if rabbit, ok := notify["rabbitmq"].(map[string]any); ok {
			maskOne(rabbit, "url")
		}
	}
	root["path"] = h.configPath()
	root["in_docker"] = h.inDocker
	writeJSON(w, http.StatusOK, root)
}

func (h *Handler) putConfig(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("dashboard.putConfig")()
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var updates map[string]any
	if err := dec.Decode(&updates); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	delete(updates, "path")
	delete(updates, "in_docker")
	cleanJSON(updates)
	fillSocialSecrets(h.sourceConfig(), updates)
	dropBlankSecrets(updates)
	path := h.configPath()
	if err := config.ApplyFile(path, updates); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if h.cfg != nil && strings.TrimSpace(h.cfg.File) == "" {
		h.cfg.File = path
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"saved":            true,
		"restart_required": true,
		"in_docker":        h.inDocker,
		"auto_restart":     h.inDocker,
		"path":             path,
	})
}

func toMap(v any) any {
	if d, ok := v.(time.Duration); ok {
		if d == 0 {
			return "0s"
		}
		return d.String()
	}
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return nil
	}
	if rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return nil
		}
		return toMap(rv.Elem().Interface())
	}
	switch rv.Kind() {
	case reflect.Struct:
		out := map[string]any{}
		rt := rv.Type()
		for i := 0; i < rt.NumField(); i++ {
			field := rt.Field(i)
			if field.PkgPath != "" {
				continue
			}
			name := yamlName(field)
			if name == "" || name == "-" {
				continue
			}
			out[name] = toMap(rv.Field(i).Interface())
		}
		return out
	case reflect.Slice, reflect.Array:
		out := make([]any, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			out[i] = toMap(rv.Index(i).Interface())
		}
		return out
	case reflect.Map:
		out := map[string]any{}
		for _, key := range rv.MapKeys() {
			out[key.String()] = toMap(rv.MapIndex(key).Interface())
		}
		return out
	default:
		return v
	}
}

func yamlName(field reflect.StructField) string {
	tag := field.Tag.Get("yaml")
	if tag == "" {
		return ""
	}
	return strings.Split(tag, ",")[0]
}

func maskSecrets(m map[string]any) {
	for _, key := range []string{"password", "client_secret", "secret_key", "data_key", "signing_key", "pairwise_salt", "dsn"} {
		maskOne(m, key)
	}
	for _, value := range m {
		switch item := value.(type) {
		case map[string]any:
			maskSecrets(item)
		case []any:
			for _, child := range item {
				if nested, ok := child.(map[string]any); ok {
					maskSecrets(nested)
				}
			}
		}
	}
}

func maskOne(m map[string]any, key string) {
	value, ok := m[key]
	if !ok {
		return
	}
	text, _ := value.(string)
	m[key+"_set"] = strings.TrimSpace(text) != ""
	m[key] = ""
}

func cleanJSON(v any) any {
	switch item := v.(type) {
	case map[string]any:
		for key, value := range item {
			if strings.HasSuffix(key, "_set") {
				delete(item, key)
				continue
			}
			item[key] = cleanJSON(value)
		}
		return item
	case []any:
		for i := range item {
			item[i] = cleanJSON(item[i])
		}
		return item
	case json.Number:
		if i, err := item.Int64(); err == nil {
			return i
		}
		if f, err := item.Float64(); err == nil {
			return f
		}
		return item.String()
	default:
		return v
	}
}

func dropBlankSecrets(v any) {
	m, ok := v.(map[string]any)
	if !ok {
		if list, ok := v.([]any); ok {
			for _, item := range list {
				dropBlankSecrets(item)
			}
		}
		return
	}
	for _, key := range []string{"password", "client_secret", "secret_key", "data_key", "signing_key", "pairwise_salt", "dsn", "url"} {
		text, isString := m[key].(string)
		if isString && strings.TrimSpace(text) == "" {
			delete(m, key)
		}
	}
	for _, value := range m {
		dropBlankSecrets(value)
	}
}

func fillSocialSecrets(cfg *config.Config, updates map[string]any) {
	if cfg == nil {
		return
	}
	social, ok := updates["social"].(map[string]any)
	if !ok {
		return
	}
	list, ok := social["providers"].([]any)
	if !ok {
		return
	}
	prev := map[string]map[string]any{}
	for _, provider := range cfg.Social.Providers {
		row, ok := toMap(provider).(map[string]any)
		if ok {
			prev[provider.ID] = row
		}
	}
	for i, item := range list {
		row, ok := item.(map[string]any)
		if !ok {
			continue
		}
		id, _ := row["id"].(string)
		base := map[string]any{}
		for key, value := range prev[id] {
			base[key] = value
		}
		for key, value := range row {
			if key == "client_secret_set" {
				continue
			}
			if key == "client_secret" {
				text, _ := value.(string)
				if strings.TrimSpace(text) == "" {
					continue
				}
			}
			base[key] = value
		}
		list[i] = base
	}
}
