package strictjson

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"
)

// ValidObject accepts a bounded, nonempty JSON object with unambiguous keys
// and valid Unicode. It does not validate application-specific semantics.
func ValidObject(document []byte, maxBytes, maxDepth int) bool {
	if maxBytes < 2 || maxDepth < 1 || maxDepth > 128 || len(document) < 2 || len(document) > maxBytes || !utf8.Valid(document) || !json.Valid(document) || !validJSONUnicodeEscapes(document) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	root, err := decoder.Token()
	if err != nil || root != json.Delim('{') || !decoder.More() {
		return false
	}
	if !validObjectValue(decoder, root, 1, maxDepth) {
		return false
	}
	_, err = decoder.Token()
	return err == io.EOF
}

func validObjectValue(decoder *json.Decoder, token json.Token, depth, maxDepth int) bool {
	delim, isContainer := token.(json.Delim)
	if !isContainer {
		return true
	}
	if depth > maxDepth || (delim != '{' && delim != '[') {
		return false
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		if delim == '{' {
			key, err := decoder.Token()
			name, ok := key.(string)
			if err != nil || !ok {
				return false
			}
			if _, duplicate := seen[name]; duplicate {
				return false
			}
			seen[name] = struct{}{}
		}
		value, err := decoder.Token()
		if err != nil || !validObjectValue(decoder, value, depth+1, maxDepth) {
			return false
		}
	}
	end, err := decoder.Token()
	return err == nil && ((delim == '{' && end == json.Delim('}')) || (delim == '[' && end == json.Delim(']')))
}

// encoding/json replaces unpaired UTF-16 surrogate escapes with U+FFFD, while
// other parsers may reject them or interpret them differently. Reject these
// before key comparison. json.Valid has already checked the escape syntax.
func validJSONUnicodeEscapes(document []byte) bool {
	for i := 0; i < len(document); i++ {
		if document[i] != '"' {
			continue
		}
		for i++; i < len(document) && document[i] != '"'; i++ {
			if document[i] != '\\' {
				continue
			}
			i++
			if document[i] != 'u' {
				continue
			}
			value := jsonHex4(document[i+1 : i+5])
			i += 4
			if value >= 0xdc00 && value <= 0xdfff {
				return false
			}
			if value >= 0xd800 && value <= 0xdbff {
				if i+6 >= len(document) || document[i+1] != '\\' || document[i+2] != 'u' {
					return false
				}
				low := jsonHex4(document[i+3 : i+7])
				if low < 0xdc00 || low > 0xdfff {
					return false
				}
				i += 6
			}
		}
	}
	return true
}

// json.Valid guarantees exactly four hexadecimal digits for every \u escape.
func jsonHex4(b []byte) uint16 {
	var value uint16
	for _, c := range b {
		value <<= 4
		switch {
		case c >= '0' && c <= '9':
			value += uint16(c - '0')
		case c >= 'a' && c <= 'f':
			value += uint16(c-'a') + 10
		default:
			value += uint16(c-'A') + 10
		}
	}
	return value
}
