package fixtures

import (
	"path/filepath"
	"sort"

	"embyproxy/internal/capture"
)

type Capture = capture.Record

type Set struct {
	Records []Capture
}

func Load(path string) (Set, error) {
	records, err := capture.ReadJSONL(path)
	if err != nil {
		return Set{}, err
	}
	return Set{Records: records}, nil
}

func LoadDefault(root string) (Set, error) {
	return Load(filepath.Join(root, "data", "traffic-captures.jsonl"))
}

func (s Set) UniqueBySignature() []Capture {
	seen := map[string]bool{}
	out := []Capture{}
	for _, record := range s.Records {
		key := record.CaseSignature
		if key == "" {
			key = record.Mode + "|" + record.Stage + "|" + record.Method
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, record)
	}
	return out
}

func (s Set) Stages() []string {
	seen := map[string]bool{}
	for _, record := range s.Records {
		if record.Stage != "" {
			seen[record.Stage] = true
		}
	}
	out := make([]string, 0, len(seen))
	for stage := range seen {
		out = append(out, stage)
	}
	sort.Strings(out)
	return out
}
