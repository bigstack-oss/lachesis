package neutron

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// keystoneStub is a minimal Keystone v3 /v3/auth/tokens responder
// for client tests. It does NOT model the full Keystone surface —
// just enough that gophercloud can complete authentication and
// discover a Neutron endpoint.
type keystoneStub struct {
	*httptest.Server
	status       int    // override response status when non-zero
	lastBody     string // last raw POST body, for shape assertions
	neutronURL   string // catalogued internal endpoint URL
	neutronURLP  string // catalogued public endpoint URL
	neutronURLA  string // catalogued admin endpoint URL
	tokenCounter int    // incremented per successful auth; tokens are "tok-N"
}

func newKeystoneStub(t *testing.T) *keystoneStub {
	t.Helper()
	ks := &keystoneStub{
		neutronURL:  "http://neutron.internal:9696/v2.0/",
		neutronURLP: "http://neutron.public:9696/v2.0/",
		neutronURLA: "http://neutron.admin:9696/v2.0/",
	}
	ks.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/auth/tokens") || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if body, err := io.ReadAll(r.Body); err == nil {
			ks.lastBody = string(body)
		}
		if ks.status != 0 {
			w.WriteHeader(ks.status)
			_, _ = w.Write([]byte(`{"error":{"message":"stub failure"}}`))
			return
		}
		ks.tokenCounter++
		w.Header().Set("X-Subject-Token", "tok-stub")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token": map[string]any{
				"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
				"catalog": []any{
					map[string]any{
						"type": "network",
						"name": "neutron",
						"endpoints": []any{
							map[string]any{"interface": "internal", "region": "R1", "region_id": "R1", "url": ks.neutronURL},
							map[string]any{"interface": "public", "region": "R1", "region_id": "R1", "url": ks.neutronURLP},
							map[string]any{"interface": "admin", "region": "R1", "region_id": "R1", "url": ks.neutronURLA},
						},
					},
					map[string]any{
						"type": "identity",
						"name": "keystone",
						"endpoints": []any{
							// All three interfaces point back at the stub itself —
							// these tests only exercise the catalog wiring, not
							// real identity calls.
							map[string]any{"interface": "internal", "region": "R1", "region_id": "R1", "url": ks.URL + "/v3"},
							map[string]any{"interface": "public", "region": "R1", "region_id": "R1", "url": ks.URL + "/v3"},
							map[string]any{"interface": "admin", "region": "R1", "region_id": "R1", "url": ks.URL + "/v3"},
						},
					},
				},
			},
		})
	}))
	return ks
}

func testCreds(authURL string) Credentials {
	return Credentials{
		AuthURL:       authURL + "/v3",
		Username:      "admin_cli",
		Password:      "test-password-placeholder",
		ProjectName:   "admin",
		UserDomain:    "default",
		ProjectDomain: "default",
		Region:        "R1",
	}
}

func TestNewClient_DefaultsToInternal(t *testing.T) {
	ks := newKeystoneStub(t)
	defer ks.Close()

	c, err := NewClient(context.Background(), testCreds(ks.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if !strings.HasPrefix(c.EndpointURL(), "http://neutron.internal:9696") {
		t.Fatalf("EndpointURL = %q, want internal endpoint", c.EndpointURL())
	}
}

func TestNewClient_InterfaceOverride(t *testing.T) {
	ks := newKeystoneStub(t)
	defer ks.Close()

	creds := testCreds(ks.URL)
	creds.Interface = "public"
	c, err := NewClient(context.Background(), creds)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if !strings.HasPrefix(c.EndpointURL(), "http://neutron.public:9696") {
		t.Fatalf("EndpointURL = %q, want public endpoint", c.EndpointURL())
	}
}

func TestNewClient_RejectsBadInterface(t *testing.T) {
	creds := testCreds("http://unused")
	creds.Interface = "external"
	if _, err := NewClient(context.Background(), creds); err == nil {
		t.Fatal("expected error for invalid interface")
	} else if !strings.Contains(err.Error(), "invalid interface") {
		t.Errorf("error should mention invalid interface: %v", err)
	}
}

func TestNewClient_AuthFailureWrapsError(t *testing.T) {
	ks := newKeystoneStub(t)
	defer ks.Close()
	ks.status = http.StatusUnauthorized

	_, err := NewClient(context.Background(), testCreds(ks.URL))
	if err == nil {
		t.Fatal("expected error on 401")
	}
	// The auth mechanics live in osclient now; neutron adds its own
	// prefix on top of osclient's "keystone auth" context.
	if !strings.Contains(err.Error(), "neutron:") || !strings.Contains(err.Error(), "keystone auth") {
		t.Errorf("error should be wrapped with package + auth context: %v", err)
	}
}

// TestNewClient_AuthRequestShape sanity-checks the body gophercloud
// posts. We don't pin the exact JSON (gophercloud owns the wire
// format and might reorder fields between releases), only that the
// fields the agent's credentials feed in are present.
func TestNewClient_AuthRequestShape(t *testing.T) {
	ks := newKeystoneStub(t)
	defer ks.Close()
	if _, err := NewClient(context.Background(), testCreds(ks.URL)); err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	for _, want := range []string{"admin_cli", "test-password-placeholder", `"name":"admin"`, `"name":"default"`} {
		if !strings.Contains(ks.lastBody, want) {
			t.Errorf("auth body missing %q\nbody: %s", want, ks.lastBody)
		}
	}
}
