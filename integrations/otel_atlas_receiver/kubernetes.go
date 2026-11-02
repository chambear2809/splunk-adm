// Copyright 2026 Application Atlas contributors
// SPDX-License-Identifier: Apache-2.0
package otel_atlas_receiver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
const caPath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
const kubeOrigin = "https://kubernetes.default.svc"

type kubeClient struct {
	client    *http.Client
	tokenPath string
	origin    string
}

func newKubeClient() (*kubeClient, error) {
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return nil, errors.New("kubernetes CA unavailable")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("invalid kubernetes CA")
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, MaxIdleConnsPerHost: 2}
	return &kubeClient{client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, tokenPath: tokenPath, origin: kubeOrigin}, nil
}

type metadata struct {
	UID             string `json:"uid"`
	Name            string `json:"name"`
	Namespace       string `json:"namespace"`
	ResourceVersion string `json:"resourceVersion"`
}
type nodeAddress struct {
	Address string `json:"address"`
	Type    string `json:"type"`
}
type item struct {
	Metadata metadata `json:"metadata"`
	Spec     struct {
		NodeName    string `json:"nodeName"`
		HostNetwork bool   `json:"hostNetwork"`
	} `json:"spec"`
	Status struct {
		Addresses []nodeAddress `json:"addresses"`
		PodIP     string        `json:"podIP"`
		PodIPs    []struct {
			IP string `json:"ip"`
		} `json:"podIPs"`
		Phase string `json:"phase"`
	} `json:"status"`
}
type page struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion"`
	Metadata   struct {
		RV                 string `json:"resourceVersion"`
		Continue           string `json:"continue"`
		RemainingItemCount *int64 `json:"remainingItemCount"`
	} `json:"metadata"`
	Items []item `json:"items"`
}

func (k *kubeClient) fetch(ctx context.Context, resource, continuation string, c *Config, budget *int64) (page, error) {
	var out page
	if resource != "nodes" && resource != "pods" {
		return out, errors.New("invalid resource")
	}
	token, err := os.ReadFile(k.tokenPath)
	if err != nil {
		return out, errors.New("kubernetes token unavailable")
	}
	t := strings.TrimSpace(string(token))
	if t == "" || strings.ContainsAny(t, "\r\n \t") {
		return out, errors.New("invalid kubernetes token")
	}
	q := url.Values{"limit": {fmt.Sprint(c.PageSize)}}
	if continuation != "" {
		q.Set("continue", continuation)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", k.origin+"/api/v1/"+resource+"?"+q.Encode(), nil)
	if err != nil {
		return out, errors.New("invalid request")
	}
	req.Header.Set("Authorization", "Bearer "+t)
	req.Header.Set("Accept", "application/json")
	resp, err := k.client.Do(req)
	if err != nil {
		return out, errors.New("kubernetes request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, errors.New("kubernetes list failed")
	}
	remaining := c.MaxBytes - *budget
	if remaining <= 0 {
		return out, errors.New("collection byte limit")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, remaining+1))
	if err != nil || int64(len(raw)) > remaining {
		return out, errors.New("collection byte limit")
	}
	*budget += int64(len(raw))
	if err = json.Unmarshal(raw, &out); err != nil {
		return out, errors.New("malformed kubernetes response")
	}
	return out, nil
}
