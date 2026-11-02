// Copyright 2026 Application Atlas contributors
// SPDX-License-Identifier: Apache-2.0
package otel_atlas_receiver

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

var identity = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$`)
var indexName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$`)

type Config struct {
	Cluster    string        `mapstructure:"cluster"`
	Scope      string        `mapstructure:"scope"`
	ProducerID string        `mapstructure:"producer_id"`
	Index      string        `mapstructure:"index"`
	Source     string        `mapstructure:"source"`
	Interval   time.Duration `mapstructure:"interval"`
	Timeout    time.Duration `mapstructure:"timeout"`
	PageSize   int           `mapstructure:"page_size"`
	MaxPages   int           `mapstructure:"max_pages"`
	MaxRecords int           `mapstructure:"max_records"`
	MaxBytes   int64         `mapstructure:"max_bytes"`
}

func defaultConfig() *Config {
	return &Config{Index: "atlas_identity", Source: "atlas_k8s_snapshot", Interval: time.Minute, Timeout: 30 * time.Second, PageSize: 200, MaxPages: 100, MaxRecords: 10000, MaxBytes: 16 << 20}
}
func (c *Config) Validate() error {
	for _, v := range []string{c.Cluster, c.Scope, c.ProducerID, c.Source} {
		if !identity.MatchString(v) {
			return fmt.Errorf("invalid identity configuration")
		}
	}
	baseScope := strings.ToLower(strings.SplitN(c.Scope, ":", 2)[0])
	if baseScope == "unknown" || baseScope == "unmapped" || baseScope == "reserved" || !indexName.MatchString(c.Index) {
		return fmt.Errorf("invalid scope or index")
	}
	if c.Interval < 20*time.Second || c.Interval > time.Hour || c.Timeout <= 0 || c.Timeout > c.Interval || c.PageSize < 1 || c.PageSize > 500 || c.MaxPages < 1 || c.MaxPages > 100 || c.MaxRecords < 1 || c.MaxRecords > 10000 || c.MaxBytes < 1024 || c.MaxBytes > 16<<20 {
		return fmt.Errorf("invalid collection bounds")
	}
	return nil
}
