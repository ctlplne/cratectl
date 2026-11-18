// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"ctlplne.dev/cratectl/internal/store"
)

func TestCargoAuthorizationRequiresOneOpaqueHeader(t *testing.T) {
	token := strings.Repeat("a", 32)
	for _, test := range []struct {
		headers []string
		valid   bool
	}{
		{[]string{token}, true},
		{nil, false},
		{[]string{token, token}, false},
		{[]string{"Bearer " + token}, false},
		{[]string{token + "," + token}, false},
		{[]string{" " + token}, false},
	} {
		r := httptest.NewRequest("GET", "/cargo/packages/index/config.json", nil)
		for _, h := range test.headers {
			r.Header.Add("Authorization", h)
		}
		got, err := requestCredential(r)
		if test.valid && (err != nil || got != token) ||
			!test.valid && (!errors.Is(err, store.ErrUnauthenticated) || got != "") {
			t.Fatalf("opaque header selection: valid=%t, matched token=%t, error=%v", test.valid, got == token, err)
		}
	}
}
