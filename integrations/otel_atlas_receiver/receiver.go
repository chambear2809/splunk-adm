// Copyright 2026 Application Atlas contributors
// SPDX-License-Identifier: Apache-2.0
package otel_atlas_receiver

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/receiver"
	"go.uber.org/zap"
)

func NewFactory() receiver.Factory {
	return receiver.NewFactory(component.MustNewType("atlas_k8s_snapshot"), func() component.Config { return defaultConfig() }, receiver.WithLogs(createLogs, component.StabilityLevelDevelopment))
}
func createLogs(_ context.Context, set receiver.Settings, cfg component.Config, next consumer.Logs) (receiver.Logs, error) {
	c, ok := cfg.(*Config)
	if !ok {
		return nil, errors.New("invalid configuration")
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	k, err := newKubeClient()
	if err != nil {
		return nil, err
	}
	return &snapshotReceiver{config: *c, fetch: k.fetch, next: next, logger: set.Logger}, nil
}

type snapshotReceiver struct {
	config Config
	fetch  fetcher
	next   consumer.Logs
	logger *zap.Logger
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

func (r *snapshotReceiver) Start(_ context.Context, _ component.Host) error {
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.done = make(chan struct{})
	go func() {
		defer close(r.done)
		ticker := time.NewTicker(r.config.Interval)
		defer ticker.Stop()
		for {
			if err := r.collectAndSend(ctx); err != nil && ctx.Err() == nil {
				r.logger.Error("atlas kubernetes snapshot failed")
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return nil
}
func (r *snapshotReceiver) Shutdown(ctx context.Context) error {
	r.once.Do(func() {
		if r.cancel != nil {
			r.cancel()
		}
	})
	if r.done == nil {
		return nil
	}
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (r *snapshotReceiver) collectAndSend(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, r.config.Timeout)
	defer cancel()
	var budget int64
	nodes, err := collect(ctx, "nodes", &r.config, r.fetch, &budget, time.Now)
	if err != nil {
		return errors.New("snapshot collection failed")
	}
	pods, err := collect(ctx, "pods", &r.config, r.fetch, &budget, time.Now)
	if err != nil {
		return errors.New("snapshot collection failed")
	}
	logs := plog.NewLogs()
	for _, s := range []snapshot{nodes, pods} {
		rl := logs.ResourceLogs().AppendEmpty()
		attrs := rl.Resource().Attributes()
		attrs.PutStr("com.splunk.source", r.config.Source)
		attrs.PutStr("com.splunk.index", r.config.Index)
		sourcetype := "adm:k8s_node_snapshot:v1"
		if s.Manifest["schema"] == "application_atlas.k8s_pod_node_snapshot.v1" {
			sourcetype = "adm:k8s_pod_node_snapshot:v1"
		}
		attrs.PutStr("com.splunk.sourcetype", sourcetype)
		rl.ScopeLogs().AppendEmpty()
		sl := rl.ScopeLogs().At(0)
		sl.Scope().SetName("atlas_k8s_snapshot")
		for _, row := range append(s.Rows, s.Manifest) {
			b, err := encoded(row)
			if err != nil {
				return errors.New("snapshot encoding failed")
			}
			var body map[string]any
			if err := json.Unmarshal(b, &body); err != nil {
				return errors.New("snapshot encoding failed")
			}
			l := sl.LogRecords().AppendEmpty()
			if err := l.Body().SetEmptyMap().FromRaw(body); err != nil {
				return errors.New("snapshot encoding failed")
			}
			seconds := row["observation_completed_at"].(float64)
			l.SetTimestamp(pcommon.NewTimestampFromTime(time.Unix(0, int64(seconds*1e9))))
		}
	}
	if ctx.Err() != nil {
		return errors.New("snapshot collection timed out")
	}
	if err := r.next.ConsumeLogs(ctx, logs); err != nil {
		return errors.New("snapshot delivery failed")
	}
	return nil
}
