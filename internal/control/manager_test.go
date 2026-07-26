package control

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/webcyber/webcyber/internal/model"
	"github.com/webcyber/webcyber/internal/scan"
)

type scannerFunc func(context.Context, scan.Config) (model.Report, error)

func (function scannerFunc) Scan(ctx context.Context, config scan.Config) (model.Report, error) {
	return function(ctx, config)
}

func testManager(t *testing.T, scanner Scanner, config ManagerConfig) *Manager {
	t.Helper()
	manager, err := NewManager(scanner, config)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(manager.Close)
	return manager
}

func testConfig() ManagerConfig {
	return ManagerConfig{MaxConcurrency: 1, MaxJobs: 4, MaxRetained: 10}
}

func testScanConfig(target string) scan.Config {
	return scan.Config{Type: model.ScanTypeWeb, Target: target, Profile: model.ProfileObserve}
}

func completedReport(config scan.Config, status string) model.Report {
	return model.Report{
		SchemaVersion: model.SchemaVersion,
		Tool:          model.ToolInfo{Name: "WebCyber", Version: scan.Version},
		Scan: model.ScanInfo{
			ID:         model.NewScanID(),
			Type:       config.Type,
			Target:     config.Target,
			Profile:    config.Profile,
			Status:     status,
			StartedAt:  time.Now().UTC(),
			FinishedAt: time.Now().UTC(),
		},
		Findings: []model.Finding{},
		Modules:  []model.ModuleResult{},
	}
}

func waitForStatus(t *testing.T, manager *Manager, id string, statuses ...JobStatus) Job {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		job, err := manager.Get(id)
		if err != nil {
			t.Fatalf("Get(%q): %v", id, err)
		}
		for _, status := range statuses {
			if job.Status == status {
				return job
			}
		}
		time.Sleep(time.Millisecond)
	}
	job, _ := manager.Get(id)
	t.Fatalf("job %s did not reach %v; current status is %s", id, statuses, job.Status)
	return Job{}
}

func privateRecordSnapshot(t *testing.T, manager *Manager, id string) (scan.Config, bool, bool) {
	t.Helper()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	record := manager.jobs[id]
	if record == nil {
		t.Fatalf("job record %q is missing", id)
	}
	return record.config, record.ctx != nil, record.cancel != nil
}

func TestManagerLifecycleAndSubscription(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	manager := testManager(t, scannerFunc(func(ctx context.Context, config scan.Config) (model.Report, error) {
		close(started)
		select {
		case <-release:
			return completedReport(config, "completed"), nil
		case <-ctx.Done():
			return completedReport(config, "failed"), ctx.Err()
		}
	}), testConfig())

	job, err := manager.Submit(testScanConfig("https://example.test"))
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if job.Status != StatusQueued || job.StartedAt != nil || job.FinishedAt != nil {
		t.Fatalf("unexpected queued job: %#v", job)
	}
	<-started
	running := waitForStatus(t, manager, job.ID, StatusRunning)
	if running.StartedAt == nil {
		t.Fatal("running job has no startedAt")
	}

	subscription, err := manager.Subscribe(job.ID)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer subscription.Close()
	if subscription.Current.Status != StatusRunning {
		t.Fatalf("subscription current status = %s", subscription.Current.Status)
	}

	close(release)
	select {
	case event := <-subscription.Events:
		if event.Status != StatusCompleted || event.ID != job.ID {
			t.Fatalf("terminal event = %#v", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for terminal event")
	}
	completed := waitForStatus(t, manager, job.ID, StatusCompleted)
	if completed.FinishedAt == nil || completed.Report == nil {
		t.Fatalf("completed job is missing terminal data: %#v", completed)
	}
	if completed.Report.Scan.Target != "https://example.test" {
		t.Fatalf("report target = %q", completed.Report.Scan.Target)
	}
	if completed.Report.Scan.ID != completed.ID {
		t.Fatalf("report scan id = %q, job id = %q", completed.Report.Scan.ID, completed.ID)
	}
}

func TestManagerKeepsRawWebTargetPrivateAndRedactsReportMetadata(t *testing.T) {
	raw := "https://alice:user-secret@example.test/path?api_key=query-secret#fragment-secret"
	received := make(chan string, 1)
	manager := testManager(t, scannerFunc(func(_ context.Context, config scan.Config) (model.Report, error) {
		received <- config.Target
		return completedReport(config, "completed"), nil
	}), testConfig())

	job, err := manager.Submit(testScanConfig(raw))
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if job.Target != "https://example.test/path" {
		t.Fatalf("public job target = %q", job.Target)
	}
	if scanned := <-received; scanned != raw {
		t.Fatalf("scanner target = %q, want raw private target", scanned)
	}
	completed := waitForStatus(t, manager, job.ID, StatusCompleted)
	if completed.Target != "https://example.test/path" {
		t.Fatalf("completed target = %q", completed.Target)
	}
	if completed.Report == nil {
		t.Fatal("completed report is missing")
	}
	if completed.Report.Scan.Target != completed.Target {
		t.Fatalf("report target = %q, job target = %q", completed.Report.Scan.Target, completed.Target)
	}
	if completed.Report.Scan.ID != completed.ID {
		t.Fatalf("report id = %q, job id = %q", completed.Report.Scan.ID, completed.ID)
	}
	if config, hasContext, hasCancel := privateRecordSnapshot(t, manager, completed.ID); config != (scan.Config{}) || hasContext || hasCancel {
		t.Fatalf("terminal record retained private state: config=%#v context=%v cancel=%v", config, hasContext, hasCancel)
	}
}

func TestManagerClearsQueuedPrivateStateImmediatelyOnCancellation(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	manager := testManager(t, scannerFunc(func(_ context.Context, config scan.Config) (model.Report, error) {
		close(started)
		<-release
		return completedReport(config, "completed"), nil
	}), ManagerConfig{MaxConcurrency: 1, MaxJobs: 2, MaxRetained: 10})
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })

	running, err := manager.Submit(testScanConfig("https://example.test/running?token=running-secret"))
	if err != nil {
		t.Fatalf("Submit running: %v", err)
	}
	<-started
	waitForStatus(t, manager, running.ID, StatusRunning)
	queued, err := manager.Submit(testScanConfig("https://example.test/queued?token=queued-secret"))
	if err != nil {
		t.Fatalf("Submit queued: %v", err)
	}

	if config, hasContext, hasCancel := privateRecordSnapshot(t, manager, running.ID); config.Target == "" || !hasContext || !hasCancel {
		t.Fatalf("running record lost required private state: config=%#v context=%v cancel=%v", config, hasContext, hasCancel)
	}
	cancelled, err := manager.Cancel(queued.ID)
	if err != nil || cancelled.Status != StatusCancelled {
		t.Fatalf("Cancel queued = %#v, %v", cancelled, err)
	}
	if config, hasContext, hasCancel := privateRecordSnapshot(t, manager, queued.ID); config != (scan.Config{}) || hasContext || hasCancel {
		t.Fatalf("queued terminal record retained private state: config=%#v context=%v cancel=%v", config, hasContext, hasCancel)
	}

	releaseOnce.Do(func() { close(release) })
	waitForStatus(t, manager, running.ID, StatusCompleted)
	if config, hasContext, hasCancel := privateRecordSnapshot(t, manager, running.ID); config != (scan.Config{}) || hasContext || hasCancel {
		t.Fatalf("completed record retained private state: config=%#v context=%v cancel=%v", config, hasContext, hasCancel)
	}
}

func TestManagerMapsPartialAndFailure(t *testing.T) {
	manager := testManager(t, scannerFunc(func(_ context.Context, config scan.Config) (model.Report, error) {
		switch config.Target {
		case "partial":
			return completedReport(config, "partial"), nil
		default:
			return completedReport(config, "failed"), errors.New("scanner failed")
		}
	}), testConfig())

	partial, err := manager.Submit(testScanConfig("partial"))
	if err != nil {
		t.Fatalf("Submit partial: %v", err)
	}
	if job := waitForStatus(t, manager, partial.ID, StatusPartial); job.Error != "" || job.Report == nil {
		t.Fatalf("partial job = %#v", job)
	}

	failed, err := manager.Submit(testScanConfig("failed"))
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}
	if job := waitForStatus(t, manager, failed.ID, StatusFailed); job.Error != "scanner failed" || job.Report == nil {
		t.Fatalf("failed job = %#v", job)
	}
}

func TestManagerContainsScannerPanicAndKeepsWorkerAvailable(t *testing.T) {
	manager := testManager(t, scannerFunc(func(_ context.Context, config scan.Config) (model.Report, error) {
		if config.Target == "panic" {
			panic("untrusted parser panic details")
		}
		return completedReport(config, "completed"), nil
	}), testConfig())

	panicked, err := manager.Submit(testScanConfig("panic"))
	if err != nil {
		t.Fatalf("Submit panic: %v", err)
	}
	failed := waitForStatus(t, manager, panicked.ID, StatusFailed)
	if failed.Error != "scanner terminated unexpectedly" {
		t.Fatalf("panic error = %q", failed.Error)
	}
	if strings.Contains(failed.Error, "untrusted parser") {
		t.Fatal("panic details escaped the worker boundary")
	}

	next, err := manager.Submit(testScanConfig("next"))
	if err != nil {
		t.Fatalf("Submit next: %v", err)
	}
	waitForStatus(t, manager, next.ID, StatusCompleted)
}

func TestManagerBoundsQueueAndRemovesCancelledQueuedJobs(t *testing.T) {
	started := make(chan struct{})
	manager := testManager(t, scannerFunc(func(ctx context.Context, config scan.Config) (model.Report, error) {
		if config.Target == "first" {
			close(started)
			<-ctx.Done()
			return completedReport(config, "failed"), ctx.Err()
		}
		return completedReport(config, "completed"), nil
	}), ManagerConfig{MaxConcurrency: 1, MaxJobs: 2, MaxRetained: 10})

	first, err := manager.Submit(testScanConfig("first"))
	if err != nil {
		t.Fatalf("Submit first: %v", err)
	}
	<-started
	second, err := manager.Submit(testScanConfig("second"))
	if err != nil {
		t.Fatalf("Submit second: %v", err)
	}
	if _, err := manager.Submit(testScanConfig("third")); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("third Submit error = %v, want ErrQueueFull", err)
	}
	cancelled, err := manager.Cancel(second.ID)
	if err != nil || cancelled.Status != StatusCancelled {
		t.Fatalf("Cancel queued = %#v, %v", cancelled, err)
	}
	third, err := manager.Submit(testScanConfig("third"))
	if err != nil {
		t.Fatalf("Submit after queued cancellation: %v", err)
	}
	if _, err := manager.Cancel(first.ID); err != nil {
		t.Fatalf("Cancel running: %v", err)
	}
	waitForStatus(t, manager, third.ID, StatusCompleted)
}

func TestManagerRunningCancellationIsTwoPhaseAndIdempotent(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	manager := testManager(t, scannerFunc(func(_ context.Context, config scan.Config) (model.Report, error) {
		close(started)
		<-release
		return completedReport(config, "completed"), nil
	}), ManagerConfig{MaxConcurrency: 1, MaxJobs: 1, MaxRetained: 1})
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })

	job, err := manager.Submit(testScanConfig("https://example.test/private?token=secret"))
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	<-started
	waitForStatus(t, manager, job.ID, StatusRunning)
	subscription, err := manager.Subscribe(job.ID)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer subscription.Close()

	cancelling, err := manager.Cancel(job.ID)
	if err != nil {
		t.Fatalf("Cancel running: %v", err)
	}
	if cancelling.Status != StatusCancelling || cancelling.FinishedAt != nil {
		t.Fatalf("first cancellation response = %#v", cancelling)
	}
	repeated, err := manager.Cancel(job.ID)
	if err != nil {
		t.Fatalf("repeat Cancel: %v", err)
	}
	if repeated.Status != StatusCancelling || repeated.FinishedAt != nil {
		t.Fatalf("repeated cancellation response = %#v", repeated)
	}
	if changed := manager.CancelAll(); len(changed) != 0 {
		t.Fatalf("repeated CancelAll changed %d jobs", len(changed))
	}
	if _, err := manager.Submit(testScanConfig("https://second.example")); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("Submit while cancelling error = %v, want ErrQueueFull", err)
	}

	select {
	case event := <-subscription.Events:
		if event.Status != StatusCancelling {
			t.Fatalf("first cancellation event = %#v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelling event was not published")
	}
	select {
	case event, open := <-subscription.Events:
		t.Fatalf("stream ended before worker exit: event=%#v open=%v", event, open)
	case <-time.After(20 * time.Millisecond):
	}

	releaseOnce.Do(func() { close(release) })
	select {
	case event := <-subscription.Events:
		if event.Status != StatusCancelled {
			t.Fatalf("terminal cancellation event = %#v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("terminal cancelled event was not published")
	}
	cancelled := waitForStatus(t, manager, job.ID, StatusCancelled)
	if cancelled.FinishedAt == nil || cancelled.Report == nil {
		t.Fatalf("terminal cancelled job = %#v", cancelled)
	}
	if cancelled.Report.Scan.Status != string(StatusCancelled) {
		t.Fatalf("cancelled report status = %q", cancelled.Report.Scan.Status)
	}
	if cancelled.Report.Scan.ID != cancelled.ID || cancelled.Report.Scan.Target != cancelled.Target {
		t.Fatalf("cancelled report identity = %#v, job = %#v", cancelled.Report.Scan, cancelled)
	}
}

func TestManagerCancelAllPublishesTerminalState(t *testing.T) {
	started := make(chan struct{})
	manager := testManager(t, scannerFunc(func(ctx context.Context, config scan.Config) (model.Report, error) {
		close(started)
		<-ctx.Done()
		return completedReport(config, "failed"), ctx.Err()
	}), testConfig())

	running, _ := manager.Submit(testScanConfig("running"))
	<-started
	queued, _ := manager.Submit(testScanConfig("queued"))
	subscription, err := manager.Subscribe(running.ID)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer subscription.Close()

	cancelled := manager.CancelAll()
	if len(cancelled) != 2 {
		t.Fatalf("CancelAll changed %d jobs, want 2", len(cancelled))
	}
	if waitForStatus(t, manager, running.ID, StatusCancelled).FinishedAt == nil {
		t.Fatal("running cancelled job has no finishedAt")
	}
	waitForStatus(t, manager, queued.ID, StatusCancelled)
	select {
	case event := <-subscription.Events:
		if event.Status != StatusCancelling {
			t.Fatalf("event status = %s", event.Status)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelling event was not published")
	}
	select {
	case event := <-subscription.Events:
		if event.Status != StatusCancelled {
			t.Fatalf("terminal event status = %s", event.Status)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled terminal event was not published")
	}
}

func TestManagerRetainsNewestJobs(t *testing.T) {
	manager := testManager(t, scannerFunc(func(_ context.Context, config scan.Config) (model.Report, error) {
		return completedReport(config, "completed"), nil
	}), ManagerConfig{MaxConcurrency: 1, MaxJobs: 3, MaxRetained: 2})

	var ids []string
	for _, target := range []string{"one", "two", "three"} {
		job, err := manager.Submit(testScanConfig(target))
		if err != nil {
			t.Fatalf("Submit(%q): %v", target, err)
		}
		waitForStatus(t, manager, job.ID, StatusCompleted)
		ids = append(ids, job.ID)
	}
	jobs := manager.List()
	if len(jobs) != 2 || jobs[0].ID != ids[2] || jobs[1].ID != ids[1] {
		t.Fatalf("retained jobs = %#v", jobs)
	}
	if _, err := manager.Get(ids[0]); !errors.Is(err, ErrNotFound) {
		t.Fatalf("oldest job error = %v, want ErrNotFound", err)
	}
}

func TestManagerRetentionCountsTerminalHistorySeparatelyFromActiveJobs(t *testing.T) {
	targets := []string{
		"https://one.example",
		"https://two.example",
		"https://three.example",
		"https://four.example",
	}
	releases := make(map[string]chan struct{}, len(targets))
	for _, target := range targets {
		releases[target] = make(chan struct{})
	}
	manager := testManager(t, scannerFunc(func(ctx context.Context, config scan.Config) (model.Report, error) {
		select {
		case <-releases[config.Target]:
			return completedReport(config, "completed"), nil
		case <-ctx.Done():
			return completedReport(config, "failed"), ctx.Err()
		}
	}), ManagerConfig{MaxConcurrency: 4, MaxJobs: 4, MaxRetained: 1})

	jobs := make([]Job, 0, len(targets))
	for _, target := range targets {
		job, err := manager.Submit(testScanConfig(target))
		if err != nil {
			t.Fatalf("Submit(%q): %v", target, err)
		}
		jobs = append(jobs, job)
	}
	for _, job := range jobs {
		waitForStatus(t, manager, job.ID, StatusRunning)
	}

	close(releases[targets[0]])
	waitForStatus(t, manager, jobs[0].ID, StatusCompleted)
	if _, err := manager.Get(jobs[0].ID); err != nil {
		t.Fatalf("first terminal job was trimmed while three jobs were active: %v", err)
	}

	close(releases[targets[1]])
	waitForStatus(t, manager, jobs[1].ID, StatusCompleted)
	if _, err := manager.Get(jobs[0].ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("oldest terminal error = %v, want ErrNotFound", err)
	}
	if _, err := manager.Get(jobs[1].ID); err != nil {
		t.Fatalf("newest terminal job was not retained: %v", err)
	}
}

func TestManagerRetentionUsesTerminalCompletionOrder(t *testing.T) {
	targetA := "https://a.example"
	targetB := "https://b.example"
	releases := map[string]chan struct{}{
		targetA: make(chan struct{}),
		targetB: make(chan struct{}),
	}
	manager := testManager(t, scannerFunc(func(ctx context.Context, config scan.Config) (model.Report, error) {
		select {
		case <-releases[config.Target]:
			return completedReport(config, "completed"), nil
		case <-ctx.Done():
			return completedReport(config, "failed"), ctx.Err()
		}
	}), ManagerConfig{MaxConcurrency: 2, MaxJobs: 2, MaxRetained: 1})

	jobA, err := manager.Submit(testScanConfig(targetA))
	if err != nil {
		t.Fatalf("Submit A: %v", err)
	}
	jobB, err := manager.Submit(testScanConfig(targetB))
	if err != nil {
		t.Fatalf("Submit B: %v", err)
	}
	waitForStatus(t, manager, jobA.ID, StatusRunning)
	waitForStatus(t, manager, jobB.ID, StatusRunning)

	close(releases[targetB])
	waitForStatus(t, manager, jobB.ID, StatusCompleted)
	if _, err := manager.Get(jobB.ID); err != nil {
		t.Fatalf("first terminal B was not retained: %v", err)
	}

	close(releases[targetA])
	waitForStatus(t, manager, jobA.ID, StatusCompleted)
	if _, err := manager.Get(jobA.ID); err != nil {
		t.Fatalf("freshly terminal A was not retained: %v", err)
	}
	if _, err := manager.Get(jobB.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("older terminal B error = %v, want ErrNotFound", err)
	}
}

func TestManagerRetentionPreservesFreshQueuedCancellation(t *testing.T) {
	blocker := "https://blocker.example"
	manager := testManager(t, scannerFunc(func(ctx context.Context, config scan.Config) (model.Report, error) {
		if config.Target == blocker {
			<-ctx.Done()
			return completedReport(config, "failed"), ctx.Err()
		}
		return completedReport(config, "completed"), nil
	}), ManagerConfig{MaxConcurrency: 1, MaxJobs: 2, MaxRetained: 1})

	prior, err := manager.Submit(testScanConfig("https://prior.example"))
	if err != nil {
		t.Fatalf("Submit prior: %v", err)
	}
	waitForStatus(t, manager, prior.ID, StatusCompleted)

	running, err := manager.Submit(testScanConfig(blocker))
	if err != nil {
		t.Fatalf("Submit blocker: %v", err)
	}
	waitForStatus(t, manager, running.ID, StatusRunning)
	queued, err := manager.Submit(testScanConfig("https://queued.example/private?token=secret"))
	if err != nil {
		t.Fatalf("Submit queued: %v", err)
	}
	cancelled, err := manager.Cancel(queued.ID)
	if err != nil || cancelled.Status != StatusCancelled {
		t.Fatalf("Cancel queued = %#v, %v", cancelled, err)
	}
	if _, err := manager.Get(queued.ID); err != nil {
		t.Fatalf("fresh queued cancellation was not retained: %v", err)
	}
	if _, err := manager.Get(prior.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("older terminal prior error = %v, want ErrNotFound", err)
	}
}

func TestNewManagerRejectsUnsafeBounds(t *testing.T) {
	scanner := scannerFunc(func(context.Context, scan.Config) (model.Report, error) {
		return model.Report{}, nil
	})
	for _, config := range []ManagerConfig{
		{MaxConcurrency: 0, MaxJobs: 1, MaxRetained: 1},
		{MaxConcurrency: 2, MaxJobs: 1, MaxRetained: 1},
		{MaxConcurrency: 1, MaxJobs: 1, MaxRetained: 0},
	} {
		if manager, err := NewManager(scanner, config); err == nil {
			manager.Close()
			t.Fatalf("NewManager(%#v) succeeded", config)
		}
	}
}
