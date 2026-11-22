package runtime

import "testing"

func TestCapabilitiesZeroValue(t *testing.T) {
	var caps Capabilities
	if caps.IPv6 {
		t.Fatal("IPv6 must be opt-in")
	}
}

// TestRuleHTTPConditionsCompile pins the HTTP L7 condition shape on the
// runtime rule type: conditions are pure data carriers to the gateway
// adapter, and an unconditioned rule must keep zero values.
func TestRuleHTTPConditionsShape(t *testing.T) {
	r := Rule{
		ID:       "r1",
		Protocol: "tcp",
		Domain:   "api.example.com",
		Methods:  []string{"GET", "ANY"},
		Path:     "/v1/**",
		Query:    []QueryCondition{{Name: "trace", Value: "*"}},
	}
	if len(r.Methods) != 2 || r.Path != "/v1/**" || r.Query[0].Name != "trace" {
		t.Fatalf("HTTP conditions did not round-trip through the rule struct: %+v", r)
	}
	var bare Rule
	if len(bare.Methods) != 0 || bare.Path != "" || len(bare.Query) != 0 {
		t.Fatal("zero-value rule must carry no HTTP conditions")
	}
}
