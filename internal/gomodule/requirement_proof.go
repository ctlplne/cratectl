// SPDX-License-Identifier: BUSL-1.1
package gomodule

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"golang.org/x/mod/semver"
)

const RequirementProofProfile = "cratectl.go.requirement-proof.v1"
const MaxRequirementProof = 2 << 20
const MaxRequirementProofSources = 1024
const MaxRequirementProofSelections = 256

var ErrRequirementProof = errors.New("invalid, incomplete or changed Go requirement proof")

type RequirementObject struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type RequirementSource struct {
	Module  string            `json:"module"`
	Version string            `json:"version"`
	Mod     RequirementObject `json:"mod"`
}
type RequirementSelection struct {
	Module        string `json:"module"`
	Version       string `json:"version"`
	SourceModule  string `json:"source_module"`
	SourceVersion string `json:"source_version"`
}

// RequirementProof binds original metadata bytes and a derived module build list.
// It carries no signature, source permission, package/platform closure, checksum
// authority or admission grant. A caller must authenticate its exact bytes and
// expected selection through the export's independently verified outer proof.
type RequirementProof struct {
	Profile  string                 `json:"profile"`
	Main     RequirementObject      `json:"main_go_mod"`
	Sources  []RequirementSource    `json:"sources"`
	Selected []RequirementSelection `json:"selected"`
}

type RequirementInput struct {
	Source Coordinate
	Mod    []byte
}

func requirementHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func requirementSourceOrder(a, b Coordinate) int {
	if n := strings.Compare(a.Module, b.Module); n != 0 {
		return n
	}
	if n := semver.Compare(a.Version, b.Version); n != 0 {
		return n
	}
	// Go preserves +incompatible in canonical identities even when semantic
	// comparison ties. Keep distinct originals in a deterministic total order.
	return strings.Compare(a.Version, b.Version)
}

func (p RequirementProof) Bytes() ([]byte, error) {
	if p.Profile != RequirementProofProfile || !requirementHash(p.Main.SHA256) || p.Main.Size < 1 || p.Main.Size > MaxGoMod ||
		p.Sources == nil || len(p.Sources) > MaxRequirementProofSources || p.Selected == nil || len(p.Selected) > MaxRequirementProofSelections {
		return nil, ErrRequirementProof
	}
	total := p.Main.Size
	var previous Coordinate
	for n, s := range p.Sources {
		c, err := Canonical(s.Module, s.Version)
		if err != nil || !requirementHash(s.Mod.SHA256) || s.Mod.Size < 1 || s.Mod.Size > MaxGoMod ||
			s.Mod.Size > DefaultGraphLimits().MetadataBytes-total || n > 0 && requirementSourceOrder(previous, c) >= 0 {
			return nil, ErrRequirementProof
		}
		total += s.Mod.Size
		previous = c
	}
	used := map[Coordinate]bool{}
	for n, s := range p.Selected {
		_, err := Canonical(s.Module, s.Version)
		c, sourceErr := Canonical(s.SourceModule, s.SourceVersion)
		if err != nil || sourceErr != nil || used[c] || n > 0 && p.Selected[n-1].Module >= s.Module {
			return nil, ErrRequirementProof
		}
		used[c] = true
	}
	raw, err := json.Marshal(p)
	if err != nil || len(raw)+1 > MaxRequirementProof {
		return nil, ErrRequirementProof
	}
	return append(raw, '\n'), nil
}

// ParseRequirementProof bounds array cardinality before typed allocation and
// requires the producer's exact canonical encoding, including all nested fields.
func ParseRequirementProof(raw []byte) (RequirementProof, error) {
	if len(raw) < 1 || len(raw) > MaxRequirementProof {
		return RequirementProof{}, ErrRequirementProof
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return RequirementProof{}, ErrRequirementProof
	}
	p := RequirementProof{Sources: []RequirementSource{}, Selected: []RequirementSelection{}}
	seen := map[string]bool{}
	for d.More() {
		t, err := d.Token()
		name, ok := t.(string)
		if err != nil || !ok || seen[name] {
			return RequirementProof{}, ErrRequirementProof
		}
		seen[name] = true
		if name == "sources" || name == "selected" {
			t, err = d.Token()
			if err != nil || t != json.Delim('[') {
				return RequirementProof{}, ErrRequirementProof
			}
			for d.More() {
				if name == "sources" && len(p.Sources) >= MaxRequirementProofSources || name == "selected" && len(p.Selected) >= MaxRequirementProofSelections {
					return RequirementProof{}, ErrRequirementProof
				}
				var item json.RawMessage
				if d.Decode(&item) != nil || len(item) > 4096 {
					return RequirementProof{}, ErrRequirementProof
				}
				if name == "sources" {
					var source RequirementSource
					if json.Unmarshal(item, &source) != nil {
						return RequirementProof{}, ErrRequirementProof
					}
					p.Sources = append(p.Sources, source)
				} else {
					var selection RequirementSelection
					if json.Unmarshal(item, &selection) != nil {
						return RequirementProof{}, ErrRequirementProof
					}
					p.Selected = append(p.Selected, selection)
				}
			}
			t, err = d.Token()
			if err != nil || t != json.Delim(']') {
				return RequirementProof{}, ErrRequirementProof
			}
		} else {
			var target any
			switch name {
			case "profile":
				target = &p.Profile
			case "main_go_mod":
				target = &p.Main
			default:
				return RequirementProof{}, ErrRequirementProof
			}
			var item json.RawMessage
			if d.Decode(&item) != nil || len(item) > 4096 || json.Unmarshal(item, target) != nil {
				return RequirementProof{}, ErrRequirementProof
			}
		}
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') || len(seen) != 4 {
		return RequirementProof{}, ErrRequirementProof
	}
	if _, err = d.Token(); err != io.EOF {
		return RequirementProof{}, ErrRequirementProof
	}
	canonical, err := p.Bytes()
	if err != nil || !bytes.Equal(canonical, raw) {
		return RequirementProof{}, ErrRequirementProof
	}
	return p, nil
}

// BuildRequirementProof retains exactly the examined originals, including lower
// unselected versions. Extra private inputs are refused instead of transported.
func BuildRequirementProof(ctx context.Context, main []byte, originals []RequirementInput) ([]byte, *RequirementGraph, error) {
	if ctx == nil || len(originals) > MaxRequirementProofSources || len(main) < 1 || len(main) > MaxGoMod {
		return nil, nil, ErrRequirementProof
	}
	inputs := map[Coordinate][]byte{}
	used := map[Coordinate]bool{}
	total := int64(len(main))
	for _, input := range originals {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if _, err := Canonical(input.Source.Module, input.Source.Version); err != nil || inputs[input.Source] != nil || len(input.Mod) < 1 || len(input.Mod) > MaxGoMod || int64(len(input.Mod)) > DefaultGraphLimits().MetadataBytes-total {
			return nil, nil, ErrRequirementProof
		}
		total += int64(len(input.Mod))
		inputs[input.Source] = slices.Clone(input.Mod)
	}
	graph, err := ResolveRequirements(ctx, main, func(_ context.Context, c Coordinate, maximum int64) ([]byte, error) {
		raw, ok := inputs[c]
		if !ok || int64(len(raw)) > maximum {
			return nil, ErrRequirementProof
		}
		used[c] = true
		return raw, nil
	}, DefaultGraphLimits())
	if err != nil {
		return nil, nil, err
	}
	if len(used) != len(inputs) {
		return nil, nil, ErrRequirementProof
	}
	p := RequirementProof{Profile: RequirementProofProfile, Main: RequirementObject{crypt.Digest(main), int64(len(main))}, Sources: []RequirementSource{}, Selected: []RequirementSelection{}}
	for c, raw := range inputs {
		p.Sources = append(p.Sources, RequirementSource{c.Module, c.Version, RequirementObject{crypt.Digest(raw), int64(len(raw))}})
	}
	slices.SortFunc(p.Sources, func(a, b RequirementSource) int {
		return requirementSourceOrder(Coordinate{a.Module, a.Version}, Coordinate{b.Module, b.Version})
	})
	for _, s := range graph.BuildList {
		p.Selected = append(p.Selected, RequirementSelection{s.Logical.Module, s.Logical.Version, s.Source.Module, s.Source.Version})
	}
	raw, err := p.Bytes()
	if err != nil {
		return nil, nil, err
	}
	return raw, graph, nil
}

// VerifyRequirementProof independently rebuilds the metadata graph from original
// bounded bytes and compares it with the caller's separately authenticated set.
// The loader must honor its context/byte bound. No package/toolchain code runs.
func VerifyRequirementProof(ctx context.Context, raw, main []byte, load GraphLoader, expected []GraphSelection) (*RequirementGraph, error) {
	if ctx == nil || load == nil || len(expected) > MaxRequirementProofSelections {
		return nil, ErrRequirementProof
	}
	p, err := ParseRequirementProof(raw)
	if err != nil {
		return nil, err
	}
	if int64(len(main)) != p.Main.Size || crypt.Digest(main) != p.Main.SHA256 {
		return nil, ErrRequirementProof
	}
	refs := map[Coordinate]RequirementObject{}
	cache := map[Coordinate][]byte{}
	for _, s := range p.Sources {
		refs[Coordinate{s.Module, s.Version}] = s.Mod
	}
	graph, err := ResolveRequirements(ctx, main, func(ctx context.Context, c Coordinate, maximum int64) ([]byte, error) {
		ref, ok := refs[c]
		if !ok || ref.Size > maximum {
			return nil, ErrRequirementProof
		}
		if body, ok := cache[c]; ok {
			return body, nil
		}
		body, err := load(ctx, c, ref.Size)
		if err != nil {
			return nil, err
		}
		if int64(len(body)) != ref.Size || crypt.Digest(body) != ref.SHA256 {
			return nil, ErrRequirementProof
		}
		cache[c] = slices.Clone(body)
		return body, nil
	}, DefaultGraphLimits())
	if err != nil {
		return nil, err
	}
	if len(cache) != len(refs) || len(graph.BuildList) != len(p.Selected) || !slices.Equal(graph.BuildList, expected) {
		return nil, ErrRequirementProof
	}
	for n, s := range p.Selected {
		if graph.BuildList[n] != (GraphSelection{Coordinate{s.Module, s.Version}, Coordinate{s.SourceModule, s.SourceVersion}}) {
			return nil, ErrRequirementProof
		}
	}
	return graph, nil
}
