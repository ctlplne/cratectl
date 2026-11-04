// SPDX-License-Identifier: BUSL-1.1
package gomodule

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestUpstreamInfoBindsCanonicalIdentityAndOptionalTime(t *testing.T) {
	for _, data := range []string{
		`{"Version":"v1.2.3"}`,
		`{"Version":"v1.2.3","Time":"2026-01-02T04:04:05+01:00"}`,
		`{"Origin":{"VCS":"git","URL":"https://example.invalid/owned","Hash":"opaque"},"Version":"v1.2.3","Future":[1,true,null]}`,
	} {
		before := []byte(data)
		got, e := ParseVersionInfo(before, testCoordinate)
		if e != nil || got.Version != testCoordinate.Version || string(before) != data {
			t.Fatal("valid bounded protocol metadata changed or rejected", got, e)
		}
		if strings.Contains(data, "Time") && got.Time.UTC().Format("2006-01-02T15:04:05Z") != "2026-01-02T03:04:05Z" {
			t.Fatal("original instant not retained", got)
		}
	}
	fields := `"Version":"v1.2.3"`
	for n := 0; n < 63; n++ {
		fields += fmt.Sprintf(",%q:null", fmt.Sprint(n))
	}
	if _, e := ParseVersionInfo([]byte("{"+fields+"}"), testCoordinate); e != nil {
		t.Fatal("exact field budget rejected", e)
	}
	if _, e := ParseVersionInfo([]byte("{"+fields+`,"extra":null}`), testCoordinate); e == nil {
		t.Fatal("field budget escaped")
	}
	minimal := []byte(`{"Version":"v1.2.3"}`)
	boundary := append(bytes.Clone(minimal), bytes.Repeat([]byte{' '}, MaxVersionInfo-len(minimal))...)
	if _, e := ParseVersionInfo(boundary, testCoordinate); e != nil {
		t.Fatal("exact byte budget rejected", e)
	}
	if _, e := ParseVersionInfo(append(boundary, ' '), testCoordinate); e == nil {
		t.Fatal("byte budget escaped")
	}
}

func TestUpstreamInfoRejectsAmbiguityAliasesAndPartialResults(t *testing.T) {
	for _, data := range []string{
		`null`, `[]`, `{}`, `{"Time":"2026-01-02T03:04:05Z"}`, `{"Version":null}`,
		`{"Version":"v1.2"}`, `{"Version":"v1.2.4"}`, `{"Version":"v2.0.0"}`,
		`{"version":"v1.2.3"}`, `{"Version":"v1.2.3","version":"v1.2.4"}`,
		`{"Version":"v1.2.3","Version":"v1.2.3"}`, `{"Version":"v1.2.3","\u0056ersion":"v1.2.3"}`,
		`{"Version":"v1.2.3","Future":1,"Future":2}`,
		`{"Version":"v1.2.3","time":"2026-01-02T03:04:05Z"}`,
		`{"Version":"v1.2.3","Time":null}`, `{"Version":"v1.2.3","Time":7}`,
		`{"Version":"v1.2.3","Time":"0001-01-01T00:00:00Z"}`,
		`{"Version":"v1.2.3","Time":"yesterday"}`, `{"Version":"v1.2.3"} {}`,
		`{"Version":"v1.2.3","Future":`, `{"Version":"v1.2.3","Future":"` + string([]byte{255}) + `"}`,
		strings.Repeat(" ", MaxVersionInfo) + `{"Version":"v1.2.3"}`,
	} {
		got, e := ParseVersionInfo([]byte(data), testCoordinate)
		if !errors.Is(e, ErrModule) || got != (Info{}) {
			t.Fatal("ambiguous metadata accepted or partial identity returned", got, e)
		}
	}
	c := Coordinate{testCoordinate.Module, "v1.0.1-0.20260102030405-0123456789ab"}
	if got, e := ParseVersionInfo([]byte(`{"Version":"`+c.Version+`"}`), c); e != nil || !got.Time.IsZero() {
		t.Fatal("optional upstream pseudo-version time synthesized or rejected", e)
	}
	for _, instant := range []string{"2026-01-02T03:04:05Z", "2026-01-02T03:04:06Z"} {
		data, _ := json.Marshal(map[string]string{"Version": c.Version, "Time": instant})
		_, e := ParseVersionInfo(data, c)
		if (e == nil) != (instant == "2026-01-02T03:04:05Z") {
			t.Fatal("pseudo-version instant binding", e)
		}
	}
	for _, version := range []string{"v1.0.1-0.20261302030405-0123456789ab", "v1.0.1-0.20260102250405-0123456789ab"} {
		c.Version = version
		if got, e := ParseVersionInfo([]byte(`{"Version":"`+version+`"}`), c); e == nil || got != (Info{}) {
			t.Fatal("optional time hid an invalid pseudo-version date", got, e)
		}
	}
}

func TestUpstreamBundleRequiresExactIndependentModAndArchiveIdentity(t *testing.T) {
	files := baseFiles(testCoordinate)
	zip := moduleFixture(t, testCoordinate, files)
	mod := []byte(files[0].body)
	info := []byte(`{"Version":"v1.2.3"}`)
	got, e := InspectRepresentations(context.Background(), bytes.NewReader(zip), int64(len(zip)), testCoordinate, mod, info, testLimits)
	if e != nil || !bytes.Equal(got.GoMod, mod) {
		t.Fatal("complete upstream bundle rejected", e)
	}
	for _, change := range []struct{ mod, info, zip []byte }{
		{append(bytes.Clone(mod), '\n'), info, zip},
		{bytes.ReplaceAll(mod, []byte("\n"), []byte("\r\n")), info, zip},
		{mod, []byte(`{"Version":"v1.2.4"}`), zip},
		{[]byte("module go.cratectl.invalid/other\n"), info, zip},
		{bytes.Repeat([]byte{'/'}, MaxGoMod+1), info, zip},
		{mod, info, zip[:len(zip)-1]},
	} {
		got, e := InspectRepresentations(context.Background(), bytes.NewReader(change.zip), int64(len(change.zip)), testCoordinate, change.mod, change.info, testLimits)
		if e == nil || !reflect.DeepEqual(got, Archive{}) {
			t.Fatal("independent representation changed or partial identity returned", e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, e := InspectRepresentations(ctx, bytes.NewReader(zip), int64(len(zip)), testCoordinate, mod, info, testLimits); !errors.Is(e, context.Canceled) || !reflect.DeepEqual(got, Archive{}) {
		t.Fatal("canceled bundle admitted", e)
	}
}

func FuzzUpstreamVersionInfo(f *testing.F) {
	for _, s := range []string{`{"Version":"v1.2.3"}`, `{"Version":"v1.2.3","Time":"2026-01-02T03:04:05Z"}`, `{"Version":"v1.2.3","Version":null}`, "[]"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		got, e := ParseVersionInfo(data, testCoordinate)
		if e != nil {
			if got != (Info{}) {
				t.Fatal("partial identity returned")
			}
			return
		}
		if len(data) > MaxVersionInfo || got.Version != testCoordinate.Version {
			t.Fatal("identity or byte budget escaped")
		}
	})
}
