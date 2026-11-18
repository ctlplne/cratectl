// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/xml"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"unicode"

	"ctlplne.dev/cratectl/internal/store"
)

const pythonSearchBody = 16 << 10

var errPythonSearchRequest = errors.New("expected the bounded XML-RPC search request used by pip")

type pythonSearchMember struct {
	Name  string   `xml:"name"`
	Terms []string `xml:"value>array>data>value>string"`
}

type pythonSearchParam struct {
	Mode    []string             `xml:"value>string"`
	Members []pythonSearchMember `xml:"value>struct>member"`
}

type pythonSearchCall struct {
	XMLName xml.Name            `xml:"methodCall"`
	Methods []string            `xml:"methodName"`
	Params  []pythonSearchParam `xml:"params>param"`
}

type pythonSearchField struct {
	Name  string `xml:"name"`
	Value string `xml:"value>string"`
}

type pythonSearchValue struct {
	Fields []pythonSearchField `xml:"struct>member"`
}

type pythonSearchReply struct {
	XMLName xml.Name `xml:"methodResponse"`
	Data    struct {
		Values []pythonSearchValue `xml:"value"`
	} `xml:"params>param>value>array>data"`
}

func decodePythonSearch(r io.Reader) (names, summaries []string, err error) {
	d := xml.NewDecoder(r)
	var call pythonSearchCall
	if d.Decode(&call) != nil || call.XMLName.Space != "" || len(call.Methods) != 1 || call.Methods[0] != "search" ||
		len(call.Params) != 2 || len(call.Params[0].Mode) != 0 || len(call.Params[1].Members) != 0 ||
		len(call.Params[1].Mode) != 1 || call.Params[1].Mode[0] != "or" ||
		len(call.Params[0].Members) < 1 || len(call.Params[0].Members) > 2 {
		return nil, nil, errPythonSearchRequest
	}
	for {
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		data, ok := token.(xml.CharData)
		if err != nil || !ok || strings.TrimSpace(string(data)) != "" {
			return nil, nil, errPythonSearchRequest
		}
	}
	for _, member := range call.Params[0].Members {
		var selected *[]string
		switch member.Name {
		case "name":
			selected = &names
		case "summary":
			selected = &summaries
		default:
			return nil, nil, errPythonSearchRequest
		}
		if *selected != nil || len(member.Terms) < 1 || len(member.Terms) > 16 {
			return nil, nil, errPythonSearchRequest
		}
		for _, term := range member.Terms {
			if len(term) > 256 || strings.TrimSpace(term) == "" || strings.IndexFunc(term, unicode.IsControl) >= 0 {
				return nil, nil, errPythonSearchRequest
			}
			if member.Name == "name" {
				term = NormalizePython(term)
			}
			*selected = append(*selected, strings.ToLower(term))
		}
	}
	return names, summaries, nil
}

func (s *Server) pythonSearch(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		fail(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use pip's XML-RPC search with POST.")
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || (media != "text/xml" && media != "application/xml") {
		fail(w, http.StatusUnsupportedMediaType, "invalid_python_search_type", "Send an XML-RPC search request.")
		return
	}
	names, summaries, err := decodePythonSearch(http.MaxBytesReader(w, r.Body, pythonSearchBody))
	if err != nil {
		fail(w, http.StatusBadRequest, "invalid_python_search", err.Error())
		return
	}
	hits, err := s.DB.PythonSearch(r.Context(), i, repo.Name, names, summaries, min(s.NativeVersionLimit, 10000),
		min(s.NativeMetadataBytes, 64<<20))
	if err != nil {
		respondErr(w, err)
		return
	}
	var response pythonSearchReply
	for _, hit := range hits {
		response.Data.Values = append(response.Data.Values, pythonSearchValue{Fields: []pythonSearchField{
			{Name: "name", Value: hit.Name}, {Name: "version", Value: hit.Version}, {Name: "summary", Value: hit.Summary},
		}})
	}
	data, err := xml.Marshal(response)
	if err != nil {
		respondErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	_, _ = w.Write(data)
}
