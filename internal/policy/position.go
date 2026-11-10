package policy

import (
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// statementOffset selects the same last top-level Statement member as encoding/json.
func statementOffset(doc string) (int, error) {
	dec := json.NewDecoder(strings.NewReader(doc))
	if _, err := dec.Token(); err != nil {
		return 0, malformed("statement position: %v", err)
	}
	offset := 0
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return 0, malformed("statement position: %v", err)
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return 0, malformed("statement position: %v", err)
		}
		if name, ok := key.(string); ok && strings.EqualFold(name, "Statement") {
			offset = int(dec.InputOffset()) - len(raw)
		}
	}
	return offset, nil
}

type sourcePosition struct{ offset, line, column int }

func (p *sourcePosition) at(doc string, offset int) Position {
	for p.offset < offset {
		r, size := utf8.DecodeRuneInString(doc[p.offset:])
		p.offset += size
		if r == '\n' {
			p.line++
			p.column = 1
		} else {
			p.column++
		}
	}
	return Position{Line: p.line, Column: p.column}
}
