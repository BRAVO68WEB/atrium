package service

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/bravo68web/atrium/internal/telemetry"
)

const (
	maxMetadataKeys  = 50
	maxMetadataBytes = 16 << 10
)

// ErrMetadataLimit is returned when a string map exceeds 16 KiB or 50 keys.
var ErrMetadataLimit = errors.New("metadata exceeds 16 KiB or 50 keys")

// ErrMetadataValue is returned when a metadata document is not an object of strings.
var ErrMetadataValue = errors.New("metadata must be an object of strings")

// ErrMetadataKey is returned when a metadata key is empty.
var ErrMetadataKey = errors.New("metadata key is empty")

// ParseMetadataPatch reads a partial string map. A JSON null deletes that key.
// A missing document or a JSON null document is not a patch.
func ParseMetadataPatch(raw json.RawMessage) (map[string]*string, bool, error) {
	defer telemetry.Step("service.ParseMetadataPatch")()
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil, false, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &obj); err != nil {
		return nil, true, ErrMetadataValue
	}
	patch := make(map[string]*string, len(obj))
	for key, value := range obj {
		if key == "" {
			return nil, true, ErrMetadataKey
		}
		item := bytes.TrimSpace(value)
		if string(item) == "null" {
			patch[key] = nil
			continue
		}
		var text string
		if err := json.Unmarshal(item, &text); err != nil {
			return nil, true, ErrMetadataValue
		}
		copied := text
		patch[key] = &copied
	}
	return patch, true, nil
}

// MergeStringMap applies patch to current. A nil patch value deletes the key.
func MergeStringMap(current map[string]string, patch map[string]*string) (map[string]string, error) {
	defer telemetry.Step("service.MergeStringMap")()
	next := make(map[string]string, len(current)+len(patch))
	for key, value := range current {
		next[key] = value
	}
	for key, value := range patch {
		if value == nil {
			delete(next, key)
			continue
		}
		next[key] = *value
	}
	if err := CheckMetadata(next); err != nil {
		return nil, err
	}
	return next, nil
}

// CheckMetadata rejects an empty key, more than 50 keys, or more than 16 KiB of JSON.
func CheckMetadata(attrs map[string]string) error {
	defer telemetry.Step("service.CheckMetadata")()
	if len(attrs) == 0 {
		return nil
	}
	if len(attrs) > maxMetadataKeys {
		return ErrMetadataLimit
	}
	for key := range attrs {
		if key == "" {
			return ErrMetadataKey
		}
	}
	raw, err := json.Marshal(attrs)
	if err != nil {
		return err
	}
	if len(raw) > maxMetadataBytes {
		return ErrMetadataLimit
	}
	return nil
}
