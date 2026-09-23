// runner is the Go reference runner for the a2a-jcs-v01 corpus, validating
// against gowebpki/jcs -- the second, independent implementation the
// corpus was cross-checked against at generation time. Two runners in two
// languages exist so the vectors are demonstrably not encoding one
// implementation's habits.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/gowebpki/jcs"
)

const specCommitPinned = "19598c4" // a2a-protocol.org/A2A commit this corpus's clauses were read from

type vector struct {
	ID          string                 `json:"id"`
	Clause      string                 `json:"clause"`
	Disposition string                 `json:"disposition"`
	Input       map[string]interface{} `json:"input,omitempty"`
	InputRaw    string                 `json:"input_raw,omitempty"`
	Expected    struct {
		CanonicalUTF8Hex string `json:"canonical_utf8_hex"`
	} `json:"expected"`
}

type manifestEntry struct {
	Path string `json:"path"`
}

type manifest struct {
	CorpusDigest string          `json:"corpusDigest"`
	Vectors      []manifestEntry `json:"vectors"`
}

type result struct {
	ID     string `json:"id"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail"`
}

func stripSignatures(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		if k == "signatures" {
			continue
		}
		out[k] = v
	}
	return out
}

// signingBytes returns the bytes a card signature covers: drop `signatures`
// (rule 3), then RFC 8785. Swap it for another implementation's signing path
// to test that path. The rule-3 vectors in both directions go through it, so an
// implementation that keeps `signatures` through canonicalization fails them.
func signingBytes(card map[string]interface{}) ([]byte, error) {
	raw, err := json.Marshal(stripSignatures(card))
	if err != nil {
		return nil, err
	}
	return jcs.Transform(raw)
}

func checkVector(v vector) (bool, string) {
	if v.Disposition == "MUST-ACCEPT" {
		var out []byte
		var err error
		if v.Clause == "a2a-spec-8.4.1-rule-3" {
			out, err = signingBytes(v.Input)
		} else {
			var raw []byte
			raw, err = json.Marshal(v.Input)
			if err != nil {
				return false, "could not re-marshal input: " + err.Error()
			}
			out, err = jcs.Transform(raw)
		}
		if err != nil {
			return false, "canonicalization errored, expected success: " + err.Error()
		}
		want, err := hex.DecodeString(v.Expected.CanonicalUTF8Hex)
		if err != nil {
			return false, "bad expected hex in vector file: " + err.Error()
		}
		if string(out) != string(want) {
			return false, fmt.Sprintf("byte mismatch: got %q want %q", out, want)
		}
		return true, "ok"
	}
	// MUST-REJECT
	if v.Clause == "a2a-spec-8.4.1-rule-3" {
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(v.InputRaw), &obj); err != nil {
			return false, "could not parse input_raw: " + err.Error()
		}
		// The input is presented AS a card's canonical signing bytes. A verifier
		// recomputes the signing bytes from the parsed card and refuses when they
		// differ. That comparison runs the implementation under test; a check on
		// the fixture alone would pass whatever the implementation does.
		out, err := signingBytes(obj)
		if err != nil {
			return false, "signing path errored on well-formed input: " + err.Error()
		}
		if string(out) != v.InputRaw {
			return true, "correctly refused: not this card's signing bytes"
		}
		return false, "accepted claimed-canonical bytes that still carry 'signatures'"
	}
	if _, err := jcs.Transform([]byte(v.InputRaw)); err != nil {
		return true, "correctly refused: " + err.Error()
	}
	return false, "accepted input that should have been refused"
}

func main() {
	vroot := "vectors"
	if len(os.Args) > 1 {
		vroot = os.Args[1]
	}
	mraw, err := os.ReadFile(filepath.Join(vroot, "MANIFEST.json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "read manifest:", err)
		os.Exit(2)
	}
	var m manifest
	if err := json.Unmarshal(mraw, &m); err != nil {
		fmt.Fprintln(os.Stderr, "parse manifest:", err)
		os.Exit(2)
	}

	var results []result
	passed := 0
	entries := append([]manifestEntry(nil), m.Vectors...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(vroot, e.Path))
		if err != nil {
			fmt.Fprintln(os.Stderr, "read vector:", e.Path, err)
			os.Exit(2)
		}
		var v vector
		if err := json.Unmarshal(raw, &v); err != nil {
			fmt.Fprintln(os.Stderr, "parse vector:", e.Path, err)
			os.Exit(2)
		}
		ok, detail := checkVector(v)
		if ok {
			passed++
		}
		results = append(results, result{ID: v.ID, Pass: ok, Detail: detail})
	}

	record := map[string]interface{}{
		"runner":       "go/gowebpki-jcs",
		"corpusDigest": m.CorpusDigest,
		"specCommit":   specCommitPinned,
		"coverage": map[string]int{
			"total": len(results), "passed": passed, "failed": len(results) - passed,
		},
		"results": results,
	}
	out, _ := json.MarshalIndent(record, "", "  ")
	fmt.Println(string(out))
	if passed != len(results) {
		os.Exit(1)
	}
}
