// Copyright 2026 Application Atlas contributors
// SPDX-License-Identifier: Apache-2.0
package otel_atlas_receiver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

type record map[string]any
type snapshot struct {
	Manifest record
	Rows     []record
}
type fetcher func(context.Context, string, string, *Config, *int64) (page, error)

func generationID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", errors.New("generation failed")
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
func encoded(v any) ([]byte, error) { return json.Marshal(v) }
func digest(b []byte) string        { x := sha256.Sum256(b); return hex.EncodeToString(x[:]) }
func address(s string) (string, error) {
	a, e := netip.ParseAddr(s)
	if e != nil || a.Zone() != "" {
		return "", errors.New("invalid address")
	}
	a = a.Unmap()
	if a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return "", errors.New("invalid address")
	}
	return a.String(), nil
}
func validateWindow(started, completed time.Time, startWall, endWall int64) error {
	if completed.Before(started) || endWall < startWall {
		return errors.New("clock discontinuity")
	}
	drift := time.Duration(endWall-startWall) - completed.Sub(started)
	if drift > 500*time.Millisecond || drift < -500*time.Millisecond {
		return errors.New("clock discontinuity")
	}
	return nil
}
func collect(ctx context.Context, resource string, c *Config, fetch fetcher, budget *int64, now func() time.Time) (snapshot, error) {
	var result snapshot
	kind, schema := "NodeList", "application_atlas.k8s_node_snapshot.v1"
	if resource == "pods" {
		kind = "PodList"
		schema = "application_atlas.k8s_pod_node_snapshot.v1"
	} else if resource != "nodes" {
		return result, errors.New("invalid resource")
	}
	started := now()
	id, err := generationID()
	if err != nil {
		return result, err
	}
	seenUID := map[string]bool{}
	seenName := map[string]bool{}
	seenContinue := map[string]bool{}
	seenNodeIP := map[string]string{}
	var rows []record
	var rv, continuation string
	var remaining int64
	haveRemaining := false
	complete := false
	for p := 0; p < c.MaxPages; p++ {
		if err := ctx.Err(); err != nil {
			return result, errors.New("collection timeout")
		}
		data, err := fetch(ctx, resource, continuation, c, budget)
		if err != nil {
			return result, err
		}
		if err := ctx.Err(); err != nil {
			return result, errors.New("collection timeout")
		}
		if data.Kind != kind || data.APIVersion != "v1" || data.Metadata.RV == "" || data.Items == nil || (rv != "" && data.Metadata.RV != rv) || len(data.Items) > c.PageSize {
			return result, errors.New("invalid list generation")
		}
		if haveRemaining {
			remaining -= int64(len(data.Items))
			if remaining < 0 {
				return result, errors.New("invalid remaining count")
			}
		}
		if data.Metadata.RemainingItemCount != nil {
			count := *data.Metadata.RemainingItemCount
			if count < 0 || (haveRemaining && count != remaining) {
				return result, errors.New("invalid remaining count")
			}
			remaining, haveRemaining = count, true
		}
		if haveRemaining && ((data.Metadata.Continue == "" && remaining != 0) || (data.Metadata.Continue != "" && remaining == 0)) {
			return result, errors.New("invalid remaining count")
		}
		rv = data.Metadata.RV
		for _, x := range data.Items {
			if resource == "nodes" && x.Metadata.Namespace != "" {
				return result, errors.New("invalid node namespace")
			}
			if !identity.MatchString(x.Metadata.UID) || !identity.MatchString(x.Metadata.Name) || seenUID[x.Metadata.UID] {
				return result, errors.New("invalid or duplicate object")
			}
			seenUID[x.Metadata.UID] = true
			nameKey := x.Metadata.Namespace + "/" + x.Metadata.Name
			if seenName[nameKey] {
				return result, errors.New("duplicate object name")
			}
			seenName[nameKey] = true
			row := record{"schema": schema, "schema_version": 1, "kind": "object", "generation_id": id, "cluster": c.Cluster, "scope": c.Scope, "producer_id": c.ProducerID, "uid": x.Metadata.UID, "name": x.Metadata.Name}
			if resource == "nodes" {
				var a []nodeAddress
				seen := map[string]bool{}
				for _, v := range x.Status.Addresses {
					if v.Type != "InternalIP" && v.Type != "ExternalIP" {
						continue
					}
					ip, e := address(v.Address)
					if e != nil || seen[v.Type+"/"+ip] {
						return result, errors.New("invalid node address")
					}
					seen[v.Type+"/"+ip] = true
					if prior, ok := seenNodeIP[ip]; ok && prior != x.Metadata.UID {
						return result, errors.New("ambiguous node address")
					}
					seenNodeIP[ip] = x.Metadata.UID
					a = append(a, nodeAddress{Type: v.Type, Address: ip})
				}
				sort.Slice(a, func(i, j int) bool {
					if a[i].Type != a[j].Type {
						return a[i].Type < a[j].Type
					}
					return a[i].Address < a[j].Address
				})
				if a == nil {
					a = []nodeAddress{}
				}
				row["addresses"] = a
			} else {
				if !identity.MatchString(x.Metadata.Namespace) || (x.Spec.NodeName != "" && !identity.MatchString(x.Spec.NodeName)) {
					return result, errors.New("invalid pod identity")
				}
				ips := []string{}
				seen := map[string]bool{}
				for _, v := range x.Status.PodIPs {
					ip, e := address(v.IP)
					if e != nil || seen[ip] {
						return result, errors.New("invalid pod address")
					}
					seen[ip] = true
					ips = append(ips, ip)
				}
				if x.Status.PodIP != "" {
					ip, e := address(x.Status.PodIP)
					if e != nil {
						return result, errors.New("invalid pod address")
					}
					if len(ips) == 0 {
						ips = append(ips, ip)
					} else if !seen[ip] {
						return result, errors.New("contradictory pod address")
					}
				}
				sort.Strings(ips)
				row["namespace"] = x.Metadata.Namespace
				row["node_name"] = x.Spec.NodeName
				row["host_network"] = x.Spec.HostNetwork
				row["pod_ips"] = ips
				row["phase"] = x.Status.Phase
			}
			rows = append(rows, row)
			if len(rows) > c.MaxRecords {
				return result, errors.New("record limit")
			}
		}
		continuation = data.Metadata.Continue
		if continuation == "" {
			complete = true
			break
		}
		if len(continuation) > 4096 || seenContinue[continuation] {
			return result, errors.New("invalid continuation")
		}
		seenContinue[continuation] = true
	}
	if !complete {
		return result, errors.New("page limit")
	}
	completed := now()
	if err := validateWindow(started, completed, started.UnixNano(), completed.UnixNano()); err != nil {
		return result, err
	}
	start, end := float64(started.UnixNano())/1e9, float64(completed.UnixNano())/1e9
	sort.Slice(rows, func(i, j int) bool { return rows[i]["uid"].(string) < rows[j]["uid"].(string) })
	var canonical []string
	var outputSize int64
	for _, row := range rows {
		row["observation_started_at"] = start
		row["observation_completed_at"] = end
		b, e := encoded(row)
		if e != nil {
			return result, e
		}
		row["record_fingerprint"] = digest(b)
		b, e = encoded(row)
		if e != nil {
			return result, e
		}
		if len(b) >= 65536 {
			return result, errors.New("event size limit")
		}
		outputSize += int64(len(b) + 1)
		if outputSize > c.MaxBytes {
			return result, errors.New("output size limit")
		}
		canonical = append(canonical, string(b))
	}
	manifest := record{"schema": schema, "schema_version": 1, "kind": "manifest", "generation_id": id, "cluster": c.Cluster, "scope": c.Scope, "producer_id": c.ProducerID, "resource_version": rv, "observation_started_at": start, "observation_completed_at": end, "expected_count": len(rows), "records_sha256": digest([]byte(strings.Join(canonical, "\n"))), "complete": true, "validity_basis": "point_snapshot", "namespace_scope": "all"}
	mb, err := encoded(manifest)
	if err != nil || len(mb) >= 65536 || outputSize+int64(len(mb)+1) > c.MaxBytes {
		return result, errors.New("output size limit")
	}
	if err := ctx.Err(); err != nil {
		return result, errors.New("collection timeout")
	}
	result.Manifest = manifest
	result.Rows = rows
	return result, nil
}
