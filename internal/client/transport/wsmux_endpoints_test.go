package transport

import (
	"testing"
)

func TestBuildEndpointsFallsBackToSingle(t *testing.T) {
	eps := buildEndpoints(nil, nil, "ir.aosky.ir:443", "1.2.3.4")
	if len(eps) != 1 {
		t.Fatalf("want 1 endpoint, got %d", len(eps))
	}
	if eps[0].addr != "ir.aosky.ir:443" || eps[0].edgeIP != "1.2.3.4" {
		t.Fatalf("unexpected endpoint: %+v", eps[0])
	}
}

func TestBuildEndpointsAlignsEdgeIPs(t *testing.T) {
	addrs := []string{"aosky.ir:443", "nekocafe.sbs:443", "onionchips.sbs:443"}
	edges := []string{"10.0.0.1"} // only the first has an edge IP
	eps := buildEndpoints(addrs, edges, "", "")
	if len(eps) != 3 {
		t.Fatalf("want 3 endpoints, got %d", len(eps))
	}
	if eps[0].addr != "aosky.ir:443" || eps[0].edgeIP != "10.0.0.1" {
		t.Errorf("endpoint 0 wrong: %+v", eps[0])
	}
	if eps[1].edgeIP != "" || eps[2].edgeIP != "" {
		t.Errorf("endpoints without an edge IP should be empty: %+v %+v", eps[1], eps[2])
	}
}

func TestNextEndpointRoundRobinsEvenly(t *testing.T) {
	addrs := []string{"a:443", "b:443", "c:443"}
	c := &WsMuxTransport{endpoints: buildEndpoints(addrs, nil, "", "")}

	counts := map[string]int{}
	const per = 100
	for i := 0; i < per*len(addrs); i++ {
		counts[c.nextEndpoint().addr]++
	}
	for _, a := range addrs {
		if counts[a] != per {
			t.Errorf("endpoint %q dialed %d times, want %d (uneven spread)", a, counts[a], per)
		}
	}
}

func TestNextEndpointSingleIsStable(t *testing.T) {
	c := &WsMuxTransport{endpoints: buildEndpoints(nil, nil, "only:443", "")}
	for i := 0; i < 5; i++ {
		if got := c.nextEndpoint().addr; got != "only:443" {
			t.Fatalf("single endpoint returned %q", got)
		}
	}
}
