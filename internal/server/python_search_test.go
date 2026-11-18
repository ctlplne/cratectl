// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/xml"
	"reflect"
	"strings"
	"testing"
)

func stockPythonSearchXML(query string) string {
	return `<?xml version="1.0"?><methodCall><methodName>search</methodName><params>
<param><value><struct>
<member><name>name</name><value><array><data><value><string>` + query + `</string></value></data></array></value></member>
<member><name>summary</name><value><array><data><value><string>` + query + `</string></value></data></array></value></member>
</struct></value></param>
<param><value><string>or</string></value></param></params></methodCall>`
}

func TestDecodePythonSearchMatchesStockXMLRPCParameters(t *testing.T) {
	payload := stockPythonSearchXML("Cratectl_Probe")
	names, summaries, err := decodePythonSearch(strings.NewReader(payload))
	if err != nil || !reflect.DeepEqual(names, []string{"cratectl-probe"}) ||
		!reflect.DeepEqual(summaries, []string{"cratectl_probe"}) {
		t.Fatalf("name terms %v, summary terms %v, error %v", names, summaries, err)
	}
	for _, query := range []string{
		stockPythonSearchXML(strings.Repeat("n", 257)),
		stockPythonSearchXML(" "),
		strings.Replace(payload, "<name>summary</name>", "<name>name</name>", 1),
		strings.Replace(payload, "<methodName>search</methodName>", "<methodName>list_packages</methodName>", 1),
		strings.Replace(payload, "<string>or</string>", "<string>and</string>", 1),
		payload + "<methodCall/>",
	} {
		if _, _, err := decodePythonSearch(strings.NewReader(query)); err == nil {
			t.Errorf("accepted unsupported search request %q", query[:min(len(query), 96)])
		}
	}
}

func TestPythonSearchEmptyResponseRetainsTheXMLRPCArray(t *testing.T) {
	data, err := xml.Marshal(pythonSearchReply{})
	if err != nil || string(data) != "<methodResponse><params><param><value><array><data></data></array></value></param></params></methodResponse>" {
		t.Fatalf("empty response = %s, %v", data, err)
	}
}
