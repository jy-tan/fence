package configschema

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/Use-Tusk/fence/internal/config"
)

const (
	// DefaultSchemaPath is the canonical raw URL for the published schema.
	DefaultSchemaPath = "https://raw.githubusercontent.com/Use-Tusk/fence/main/docs/schema/fence.schema.json"
)

// Generate creates a JSON Schema document from the config structs.
func Generate() ([]byte, error) {
	rootType := reflect.TypeOf(config.Config{})
	rootSchema, err := schemaForType(rootType)
	if err != nil {
		return nil, err
	}

	properties, ok := rootSchema["properties"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("root schema missing properties")
	}

	// Optional editor hint key; fence ignores unknown keys when parsing config.
	properties["$schema"] = map[string]any{
		"type":   "string",
		"format": "uri",
	}

	document := map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"$id":     DefaultSchemaPath,
		"title":   "Fence configuration schema",
		"type":    "object",
		// Keep config typo-safe in editors while allowing known fields.
		"additionalProperties": false,
		"properties":           properties,
	}

	return json.MarshalIndent(document, "", "  ")
}

func schemaForType(t reflect.Type) (map[string]any, error) {
	switch t.Kind() {
	case reflect.Pointer:
		inner, err := schemaForType(t.Elem())
		if err != nil {
			return nil, err
		}
		return nullable(inner), nil
	case reflect.Struct:
		properties := make(map[string]any)
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			if !field.IsExported() {
				continue
			}

			jsonName, skip := jsonFieldName(field)
			if skip {
				continue
			}

			fieldSchema, err := schemaForType(field.Type)
			if err != nil {
				return nil, err
			}
			properties[jsonName] = fieldSchema
		}

		return map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"properties":           properties,
		}, nil
	case reflect.Slice, reflect.Array:
		itemSchema, err := schemaForType(t.Elem())
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"type":  "array",
			"items": itemSchema,
		}, nil
	case reflect.String:
		return map[string]any{"type": "string"}, nil
	case reflect.Bool:
		return map[string]any{"type": "boolean"}, nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return map[string]any{"type": "integer"}, nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer", "minimum": 0}, nil
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}, nil
	default:
		return nil, fmt.Errorf("unsupported config field kind: %s", t.Kind())
	}
}

func nullable(base map[string]any) map[string]any {
	copied := make(map[string]any, len(base)+1)
	for k, v := range base {
		copied[k] = v
	}

	typeValue, hasType := copied["type"]
	if !hasType {
		return copied
	}

	switch tv := typeValue.(type) {
	case string:
		copied["type"] = []string{tv, "null"}
	case []string:
		if !containsString(tv, "null") {
			copied["type"] = append(tv, "null")
		}
	case []any:
		if !containsAnyString(tv, "null") {
			copied["type"] = append(tv, "null")
		}
	}

	return copied
}

func jsonFieldName(field reflect.StructField) (name string, skip bool) {
	tag := field.Tag.Get("json")
	if tag == "-" {
		return "", true
	}
	if tag == "" {
		return field.Name, false
	}

	parts := strings.Split(tag, ",")
	if len(parts) == 0 || parts[0] == "" {
		return field.Name, false
	}
	return parts[0], false
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsAnyString(values []any, target string) bool {
	for _, value := range values {
		if asString, ok := value.(string); ok && asString == target {
			return true
		}
	}
	return false
}
