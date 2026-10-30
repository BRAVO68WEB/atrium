package config

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// ApplyFile merges updates into the YAML file at path and writes it back.
// A mapping merges key by key, so keys the update does not mention stay, including
// comments on those keys. A sequence replaces that key. An empty file is created.
// The merged document must pass ValidateReady. The write works on a bind-mounted
// file, where rename over the mount point fails.
func ApplyFile(path string, updates map[string]any) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("config path is empty")
	}
	original, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read config: %w", err)
	}
	mode := os.FileMode(0o600)
	if info, statErr := os.Stat(path); statErr == nil {
		mode = info.Mode().Perm()
		if mode == 0 {
			mode = 0o600
		}
	}
	root, err := documentRoot(original)
	if err != nil {
		return err
	}
	mapping := root.Content[0]
	if err := mergeNode(mapping, updates); err != nil {
		return err
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(mapping); err != nil {
		_ = enc.Close()
		return fmt.Errorf("encode config: %w", err)
	}
	if err := enc.Close(); err != nil {
		return err
	}
	if _, err := Parse(buf.Bytes()); err != nil {
		return err
	}
	return writeConfig(path, buf.Bytes(), mode)
}

func documentRoot(data []byte) (*yaml.Node, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		mapping := &yaml.Node{Kind: yaml.MappingNode}
		return &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{mapping}}, nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("config file must be a YAML mapping")
	}
	return &doc, nil
}

func mergeNode(dst *yaml.Node, value any) error {
	var src yaml.Node
	if err := src.Encode(value); err != nil {
		return fmt.Errorf("encode config value: %w", err)
	}
	return mergeYAML(dst, &src)
}

func mergeYAML(dst, src *yaml.Node) error {
	if src == nil {
		return nil
	}
	if src.Kind == yaml.DocumentNode {
		if len(src.Content) == 0 {
			return nil
		}
		src = src.Content[0]
	}
	if dst.Kind == yaml.MappingNode && src.Kind == yaml.MappingNode {
		for i := 0; i < len(src.Content); i += 2 {
			key := src.Content[i]
			val := src.Content[i+1]
			if existing := mappingValue(dst, key.Value); existing != nil {
				if existing.Kind == yaml.MappingNode && val.Kind == yaml.MappingNode {
					if err := mergeYAML(existing, val); err != nil {
						return err
					}
					continue
				}
				if existing.Kind == yaml.ScalarNode && val.Kind == yaml.ScalarNode {
					existing.Tag = val.Tag
					existing.Value = val.Value
					continue
				}
				*existing = *val
				continue
			}
			dst.Content = append(dst.Content, key, val)
		}
		return nil
	}
	*dst = *src
	return nil
}

func mappingValue(mapping *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func writeConfig(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err == nil {
		if err := os.Rename(tmp, path); err == nil {
			return nil
		}
		_ = os.Remove(tmp)
	}
	return os.WriteFile(path, data, mode)
}
