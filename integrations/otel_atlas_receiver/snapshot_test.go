// Copyright 2026 Application Atlas contributors
// SPDX-License-Identifier: Apache-2.0
package otel_atlas_receiver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	translator "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/translator/splunk"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/plog"
)

func testConfig() *Config {
	c := defaultConfig()
	c.Cluster = "cluster1"
	c.Scope = "scope1"
	c.ProducerID = "producer1"
	c.PageSize = 2
	return c
}
func decodePage(t *testing.T, s string) page {
	t.Helper()
	var p page
	if err := json.Unmarshal([]byte(s), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

const node1 = `{"metadata":{"uid":"uid-1","name":"node-a"},"status":{"addresses":[{"type":"InternalIP","address":"10.0.0.1"}]}}`
const node2 = `{"metadata":{"uid":"uid-2","name":"node-b"},"status":{"addresses":[{"type":"InternalIP","address":"10.0.0.2"}]}}`

func mkPage(t *testing.T, rv, cont string, items ...string) page {
	return decodePage(t, `{"kind":"NodeList","apiVersion":"v1","metadata":{"resourceVersion":"`+rv+`","continue":"`+cont+`"},"items":[`+strings.Join(items, ",")+`]}`)
}
func fixedNow() time.Time { return time.Unix(1800000000, 0) }
func TestPaginationCompleteAndEmptyGeneration(t *testing.T) {
	c := testConfig()
	responses := []page{mkPage(t, "rv1", "next", node1), mkPage(t, "rv1", "", node2)}
	i := 0
	fetch := func(_ context.Context, _ string, cont string, _ *Config, _ *int64) (page, error) {
		if i == 1 && cont != "next" {
			t.Fatal("continuation not propagated")
		}
		p := responses[i]
		i++
		return p, nil
	}
	var budget int64
	s, err := collect(context.Background(), "nodes", c, fetch, &budget, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Rows) != 2 || s.Manifest["expected_count"] != 2 || s.Manifest["validity_basis"] != "point_snapshot" {
		t.Fatal("incorrect manifest")
	}
	for _, r := range s.Rows {
		if r["generation_id"] != s.Manifest["generation_id"] || r["record_fingerprint"] == "" {
			t.Fatal("missing generation/fingerprint")
		}
	}
	empty := func(context.Context, string, string, *Config, *int64) (page, error) { return mkPage(t, "rv2", ""), nil }
	s, err = collect(context.Background(), "nodes", c, empty, &budget, fixedNow)
	if err != nil || len(s.Rows) != 0 || s.Manifest["expected_count"] != 0 || s.Manifest["records_sha256"] != digest(nil) {
		t.Fatal("empty generation invalid", err)
	}
}
func TestRejectPartialChangedRVDuplicateAndReuse(t *testing.T) {
	cases := map[string][]page{
		"missing items":      {decodePage(t, `{"kind":"NodeList","apiVersion":"v1","metadata":{"resourceVersion":"r"}}`)},
		"null items":         {decodePage(t, `{"kind":"NodeList","apiVersion":"v1","metadata":{"resourceVersion":"r"},"items":null}`)},
		"changed rv":         {mkPage(t, "a", "next", node1), mkPage(t, "b", "", node2)},
		"duplicate uid":      {mkPage(t, "a", "next", node1), mkPage(t, "a", "", node1)},
		"reused node name":   {mkPage(t, "a", "", node1, strings.ReplaceAll(node2, "node-b", "node-a"))},
		"ambiguous address":  {mkPage(t, "a", "", node1, strings.ReplaceAll(node2, "10.0.0.2", "10.0.0.1"))},
		"bad address":        {mkPage(t, "a", "", strings.ReplaceAll(node1, "10.0.0.1", "not-an-ip"))},
		"mapped unspecified": {mkPage(t, "a", "", strings.ReplaceAll(node1, "10.0.0.1", "::ffff:0.0.0.0"))},
		"namespaced nodes":   {mkPage(t, "a", "", strings.Replace(node1, `"name":"node-a"`, `"name":"node-a","namespace":"a"`, 1), strings.Replace(strings.Replace(node2, `"name":"node-b"`, `"name":"node-a","namespace":"b"`, 1), "10.0.0.2", "10.0.0.3", 1))},
		"continuation loop":  {mkPage(t, "a", "next", node1), mkPage(t, "a", "next", node2)},
	}
	for name, pages := range cases {
		t.Run(name, func(t *testing.T) {
			i := 0
			fetch := func(context.Context, string, string, *Config, *int64) (page, error) {
				if i >= len(pages) {
					return page{}, errors.New("unexpected fetch")
				}
				p := pages[i]
				i++
				return p, nil
			}
			var b int64
			s, e := collect(context.Background(), "nodes", testConfig(), fetch, &b, fixedNow)
			if e == nil || s.Manifest != nil || len(s.Rows) != 0 {
				t.Fatal("invalid generation accepted")
			}
		})
	}
}

func TestRemainingItemCountValidation(t *testing.T) {
	count := func(v int64) *int64 { return &v }
	withCount := func(p page, n *int64) page { p.Metadata.RemainingItemCount = n; return p }
	tests := []struct {
		name     string
		pages    []page
		accepted bool
	}{
		{"consistent", []page{withCount(mkPage(t, "a", "next", node1), count(1)), withCount(mkPage(t, "a", "", node2), count(0))}, true},
		{"missing later count", []page{withCount(mkPage(t, "a", "next", node1), count(1)), mkPage(t, "a", "", node2)}, true},
		{"terminal positive", []page{withCount(mkPage(t, "a", "", node1), count(1))}, false},
		{"negative", []page{withCount(mkPage(t, "a", "", node1), count(-1))}, false},
		{"contradictory", []page{withCount(mkPage(t, "a", "next", node1), count(2)), withCount(mkPage(t, "a", "", node2), count(0))}, false},
		{"zero with continuation", []page{withCount(mkPage(t, "a", "next", node1), count(0))}, false},
		{"missing terminal count hides incomplete", []page{withCount(mkPage(t, "a", "next", node1), count(2)), mkPage(t, "a", "", node2)}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			i := 0
			fetch := func(context.Context, string, string, *Config, *int64) (page, error) {
				if i >= len(test.pages) {
					return page{}, errors.New("unexpected fetch")
				}
				p := test.pages[i]
				i++
				return p, nil
			}
			var b int64
			result, err := collect(context.Background(), "nodes", testConfig(), fetch, &b, fixedNow)
			if (err == nil) != test.accepted {
				t.Fatalf("accepted=%v error=%v", test.accepted, err)
			}
			if !test.accepted && (result.Manifest != nil || len(result.Rows) != 0) {
				t.Fatal("partial generation returned")
			}
		})
	}
}

func TestWindowRejectsBackwardWallClockDespiteForwardMonotonic(t *testing.T) {
	started := time.Now()
	completed := started.Add(100 * time.Millisecond)
	if validateWindow(started, completed, started.UnixNano(), started.UnixNano()-int64(200*time.Millisecond)) == nil {
		t.Fatal("backward wall clock accepted")
	}
}
func TestPodHostAndAddressSemantics(t *testing.T) {
	p := decodePage(t, `{"kind":"PodList","apiVersion":"v1","metadata":{"resourceVersion":"r"},"items":[{"metadata":{"uid":"p-1","name":"pod-a","namespace":"shop"},"spec":{"nodeName":"node-a","hostNetwork":false},"status":{"podIP":"10.1.0.2","podIPs":[{"ip":"10.1.0.2"}],"phase":"Running"}}]}`)
	fetch := func(context.Context, string, string, *Config, *int64) (page, error) { return p, nil }
	var b int64
	s, e := collect(context.Background(), "pods", testConfig(), fetch, &b, fixedNow)
	if e != nil {
		t.Fatal(e)
	}
	r := s.Rows[0]
	if r["node_name"] != "node-a" || r["uid"] != "p-1" || r["host_network"] != false {
		t.Fatal("pod facts missing")
	}
	if _, ok := r["node_uid"]; ok {
		t.Fatal("inferred node UID")
	}
	p.Items[0].Status.PodIP = "10.1.0.3"
	if _, e = collect(context.Background(), "pods", testConfig(), fetch, &b, fixedNow); e == nil {
		t.Fatal("inconsistent pod IP accepted")
	}
}
func TestCapsAndTimeout(t *testing.T) {
	c := testConfig()
	c.MaxRecords = 1
	fetch := func(context.Context, string, string, *Config, *int64) (page, error) {
		return mkPage(t, "a", "", node1, node2), nil
	}
	var b int64
	if _, e := collect(context.Background(), "nodes", c, fetch, &b, fixedNow); e == nil {
		t.Fatal("record cap not enforced")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := collect(ctx, "nodes", c, fetch, &b, fixedNow); e == nil {
		t.Fatal("cancel not honored")
	}
	c.Scope = "UNMAPPED:x"
	if c.Validate() == nil {
		t.Fatal("reserved scope accepted")
	}
}
func TestNoEmitUntilBothListsAndDeliveryError(t *testing.T) {
	c := testConfig()
	var calls int
	var partiallyDelivered map[string]any
	next, _ := consumer.NewLogs(func(_ context.Context, logs plog.Logs) error {
		calls++
		records := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
		body, err := json.Marshal(records.At(records.Len() - 1).Body().AsRaw())
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(body, &partiallyDelivered); err != nil {
			t.Fatal(err)
		}
		// Simulate a downstream sender delivering only the manifest before failing.
		return errors.New("exporter secret must not leak")
	})
	r := snapshotReceiver{config: *c, next: next}
	r.fetch = func(_ context.Context, res, _ string, _ *Config, _ *int64) (page, error) {
		if res == "nodes" {
			return mkPage(t, "r", "", node1), nil
		}
		return page{}, errors.New("partial")
	}
	if e := r.collectAndSend(context.Background()); e == nil || calls != 0 {
		t.Fatal("partial input emitted")
	}
	r.fetch = func(_ context.Context, res, _ string, _ *Config, _ *int64) (page, error) {
		if res == "nodes" {
			return mkPage(t, "r", "", node1), nil
		}
		return decodePage(t, `{"kind":"PodList","apiVersion":"v1","metadata":{"resourceVersion":"p"},"items":[{"metadata":{"uid":"pod-1","name":"frontend","namespace":"shop"},"spec":{"nodeName":"node-a"},"status":{"podIP":"10.1.0.2","phase":"Running"}}]}`), nil
	}
	if e := r.collectAndSend(context.Background()); e == nil || strings.Contains(e.Error(), "secret") || calls != 1 {
		t.Fatal("exporter failure not propagated safely")
	}
	if partiallyDelivered["kind"] != "manifest" || partiallyDelivered["expected_count"] != float64(1) {
		t.Fatal("partial-delivery fixture did not contain a manifest requiring one object")
	}
}

func TestCancellationDuringFinalPodPagePreventsConsumerCall(t *testing.T) {
	c := testConfig()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	next, _ := consumer.NewLogs(func(context.Context, plog.Logs) error { calls++; return nil })
	r := snapshotReceiver{config: *c, next: next}
	r.fetch = func(_ context.Context, res, _ string, _ *Config, _ *int64) (page, error) {
		if res == "nodes" {
			return mkPage(t, "r", "", node1), nil
		}
		cancel()
		return decodePage(t, `{"kind":"PodList","apiVersion":"v1","metadata":{"resourceVersion":"p"},"items":[]}`), nil
	}
	if err := r.collectAndSend(ctx); err == nil || calls != 0 {
		t.Fatal("cancelled final fetch reached consumer")
	}
}
func TestExporterMetadataAndCompleteManifests(t *testing.T) {
	c := testConfig()
	calls := 0
	next, _ := consumer.NewLogs(func(_ context.Context, l plog.Logs) error {
		calls++
		if l.ResourceLogs().Len() != 2 {
			t.Fatal("expected separate generations")
		}
		for i := 0; i < 2; i++ {
			rl := l.ResourceLogs().At(i)
			a := rl.Resource().Attributes()
			for _, key := range []string{"com.splunk.index", "com.splunk.source", "com.splunk.sourcetype"} {
				if _, ok := a.Get(key); !ok {
					t.Fatal("missing exporter metadata")
				}
			}
			logs := rl.ScopeLogs().At(0).LogRecords()
			var rowBytes []string
			for j := 0; j < logs.Len(); j++ {
				event := translator.LogToSplunkEvent(rl.Resource(), logs.At(j), translator.DefaultHecToOtelAttrs(), translator.DefaultOtelToHecFields(), "", "", "")
				wantedType := "adm:k8s_node_snapshot:v1"
				if i == 1 {
					wantedType = "adm:k8s_pod_node_snapshot:v1"
				}
				if event == nil || event.Source != c.Source || event.Index != c.Index || event.SourceType != wantedType {
					t.Fatal("HEC translation did not retain routing metadata")
				}
				bodyMap, ok := event.Event.(map[string]any)
				if !ok {
					t.Fatal("HEC event body is not a structured object")
				}
				if bodyMap["kind"] == "object" {
					body, _ := json.Marshal(bodyMap)
					rowBytes = append(rowBytes, string(body))
					fingerprint := bodyMap["record_fingerprint"]
					delete(bodyMap, "record_fingerprint")
					withoutFingerprint, _ := json.Marshal(bodyMap)
					if fingerprint != digest(withoutFingerprint) {
						t.Fatalf("HEC body changed row fingerprint: %s", withoutFingerprint)
					}
				}
			}
			var m map[string]any
			body, err := json.Marshal(logs.At(logs.Len() - 1).Body().AsRaw())
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(body, &m); err != nil || m["kind"] != "manifest" || m["validity_basis"] != "point_snapshot" {
				t.Fatal("invalid manifest")
			}
			if m["records_sha256"] != digest([]byte(strings.Join(rowBytes, "\n"))) {
				t.Fatal("HEC translation changed canonical manifest digest")
			}
		}
		return nil
	})
	r := snapshotReceiver{config: *c, next: next}
	r.fetch = func(_ context.Context, res, _ string, _ *Config, _ *int64) (page, error) {
		if res == "nodes" {
			return mkPage(t, "r", "", node1), nil
		}
		return decodePage(t, `{"kind":"PodList","apiVersion":"v1","metadata":{"resourceVersion":"p"},"items":[{"metadata":{"uid":"pod-1","name":"frontend","namespace":"shop"},"spec":{"nodeName":"node-a"},"status":{"podIP":"10.1.0.2","phase":"Running"}}]}`), nil
	}
	if e := r.collectAndSend(context.Background()); e != nil || calls != 1 {
		t.Fatal(e)
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestCredentialRotatesAndRedirectStatusFailsClosed(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "token")
	if e := os.WriteFile(p, []byte("first"), 0600); e != nil {
		t.Fatal(e)
	}
	calls := 0
	k := kubeClient{origin: "https://kubernetes.default.svc", tokenPath: p, client: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		want := "Bearer first"
		if calls == 2 {
			want = "Bearer second"
		}
		if r.Header.Get("Authorization") != want {
			t.Fatal("token not refreshed")
		}
		status := 200
		if calls == 2 {
			status = 302
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(`{"kind":"NodeList","apiVersion":"v1","metadata":{"resourceVersion":"r"},"items":[]}`)), Header: make(http.Header)}, nil
	})}}
	var b int64
	if _, e := k.fetch(context.Background(), "nodes", "", testConfig(), &b); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(p, []byte("second"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := k.fetch(context.Background(), "nodes", "", testConfig(), &b); e == nil {
		t.Fatal("redirect accepted")
	}
}
