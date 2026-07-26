// Package control exposes WebCyber's scan engine through a bounded,
// cancellation-aware local control plane.
package control

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/webcyber/webcyber/internal/model"
	"github.com/webcyber/webcyber/internal/scan"
)

// JobStatus is the externally visible lifecycle state of a scan job.
type JobStatus string

const (
	StatusQueued     JobStatus = "queued"
	StatusRunning    JobStatus = "running"
	StatusCancelling JobStatus = "cancelling"
	StatusCompleted  JobStatus = "completed"
	StatusPartial    JobStatus = "partial"
	StatusFailed     JobStatus = "failed"
	StatusCancelled  JobStatus = "cancelled"
)

var (
	ErrClosed    = errors.New("scan manager is closed")
	ErrQueueFull = errors.New("scan queue is full")
	ErrNotFound  = errors.New("scan job was not found")
)

// Scanner is implemented by scan.Engine. Keeping the boundary small makes the
// queue independently testable and leaves room for isolated workers later.
type Scanner interface {
	Scan(context.Context, scan.Config) (model.Report, error)
}

// ManagerConfig bounds concurrent work and retained terminal API history.
type ManagerConfig struct {
	MaxConcurrency int
	MaxJobs        int
	MaxRetained    int
}

// DefaultManagerConfig is deliberately conservative for a local control
// process. Operators can override these values in cmd/webcyberd.
func DefaultManagerConfig() ManagerConfig {
	concurrency := runtime.GOMAXPROCS(0)
	if concurrency > 4 {
		concurrency = 4
	}
	if concurrency < 1 {
		concurrency = 1
	}
	return ManagerConfig{
		MaxConcurrency: concurrency,
		MaxJobs:        100,
		MaxRetained:    100,
	}
}

// Job is the stable JSON representation returned by the control API.
type Job struct {
	ID         string         `json:"id"`
	Type       model.ScanType `json:"type"`
	Target     string         `json:"target"`
	Profile    model.Profile  `json:"profile"`
	Status     JobStatus      `json:"status"`
	CreatedAt  time.Time      `json:"createdAt"`
	StartedAt  *time.Time     `json:"startedAt,omitempty"`
	FinishedAt *time.Time     `json:"finishedAt,omitempty"`
	Error      string         `json:"error,omitempty"`
	Report     *model.Report  `json:"report,omitempty"`
}

// Event intentionally contains no target or report data. Clients fetch the
// authenticated job endpoint after a terminal event.
type Event struct {
	ID        string    `json:"id"`
	Status    JobStatus `json:"status"`
	Timestamp time.Time `json:"timestamp"`
}

type jobRecord struct {
	job    Job
	config scan.Config
	ctx    context.Context
	cancel context.CancelFunc
}

// Subscription is an atomic current-state snapshot followed by future state
// changes. Close must be called when the consumer disconnects.
type Subscription struct {
	Current Job
	Events  <-chan Event
	Close   func()
}

// Manager owns the bounded in-memory queue and worker pool.
type Manager struct {
	scanner Scanner
	config  ManagerConfig

	mu            sync.Mutex
	cond          *sync.Cond
	closed        bool
	jobs          map[string]*jobRecord
	order         []string
	terminalOrder []string
	queue         []string
	subscribers   map[string]map[uint64]chan Event
	nextSubID     uint64
	rootCtx       context.Context
	rootCancel    context.CancelFunc
	workerWG      sync.WaitGroup
	closeOnce     sync.Once
}

// NewManager starts a fixed-size worker pool.
func NewManager(scanner Scanner, config ManagerConfig) (*Manager, error) {
	if scanner == nil {
		return nil, errors.New("scanner must not be nil")
	}
	if config.MaxConcurrency < 1 {
		return nil, errors.New("max concurrency must be at least 1")
	}
	if config.MaxJobs < config.MaxConcurrency {
		return nil, fmt.Errorf("max jobs (%d) must be at least max concurrency (%d)", config.MaxJobs, config.MaxConcurrency)
	}
	if config.MaxRetained < 1 {
		return nil, errors.New("max retained jobs must be at least 1")
	}

	rootCtx, rootCancel := context.WithCancel(context.Background())
	manager := &Manager{
		scanner:     scanner,
		config:      config,
		jobs:        make(map[string]*jobRecord),
		subscribers: make(map[string]map[uint64]chan Event),
		rootCtx:     rootCtx,
		rootCancel:  rootCancel,
	}
	manager.cond = sync.NewCond(&manager.mu)
	for range config.MaxConcurrency {
		manager.workerWG.Add(1)
		go manager.worker()
	}
	return manager, nil
}

// MaxConcurrency is reported as an API capability.
func (m *Manager) MaxConcurrency() int {
	return m.config.MaxConcurrency
}

// Submit enqueues a scan without blocking on execution.
func (m *Manager) Submit(config scan.Config) (Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return Job{}, ErrClosed
	}
	if m.activeCountLocked() >= m.config.MaxJobs {
		return Job{}, ErrQueueFull
	}

	id := model.NewScanID()
	for m.jobs[id] != nil {
		id = model.NewScanID()
	}
	ctx, cancel := context.WithCancel(m.rootCtx)
	created := time.Now().UTC()
	record := &jobRecord{
		job: Job{
			ID:        id,
			Type:      config.Type,
			Target:    publicTarget(config),
			Profile:   config.Profile,
			Status:    StatusQueued,
			CreatedAt: created,
		},
		config: config,
		ctx:    ctx,
		cancel: cancel,
	}
	m.jobs[id] = record
	m.order = append(m.order, id)
	m.queue = append(m.queue, id)
	m.trimLocked()
	m.cond.Signal()
	return cloneJob(record.job), nil
}

// Get returns a snapshot of one job.
func (m *Manager) Get(id string) (Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	record := m.jobs[id]
	if record == nil {
		return Job{}, ErrNotFound
	}
	return cloneJob(record.job), nil
}

// List returns newest jobs first.
func (m *Manager) List() []Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	jobs := make([]Job, 0, len(m.jobs))
	for index := len(m.order) - 1; index >= 0; index-- {
		if record := m.jobs[m.order[index]]; record != nil {
			job := cloneJob(record.job)
			// Reports can contain thousands of findings. Keep list responses
			// bounded; clients fetch one terminal job for its full report.
			job.Report = nil
			jobs = append(jobs, job)
		}
	}
	return jobs
}

// Cancel immediately terminates queued work or requests cancellation of a
// running worker. Running work becomes terminal only after the worker returns.
func (m *Manager) Cancel(id string) (Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	record := m.jobs[id]
	if record == nil {
		return Job{}, ErrNotFound
	}
	if !terminal(record.job.Status) {
		m.requestCancelLocked(record)
		m.trimLocked()
	}
	return cloneJob(record.job), nil
}

// CancelAll applies the one-way kill switch to all queued and running jobs.
// The returned slice contains only jobs changed by this call; repeated
// requests against cancelling jobs are idempotent.
func (m *Manager) CancelAll() []Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	cancelled := make([]Job, 0)
	for _, id := range m.order {
		record := m.jobs[id]
		if record == nil || terminal(record.job.Status) {
			continue
		}
		if m.requestCancelLocked(record) {
			cancelled = append(cancelled, cloneJob(record.job))
		}
	}
	m.queue = m.queue[:0]
	m.trimLocked()
	return cancelled
}

// Subscribe atomically registers for future transitions and returns the
// current state so a fast worker cannot create a gap between GET and SSE.
func (m *Manager) Subscribe(id string) (Subscription, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	record := m.jobs[id]
	if record == nil {
		return Subscription{}, ErrNotFound
	}

	events := make(chan Event, 8)
	if terminal(record.job.Status) {
		close(events)
		return Subscription{
			Current: cloneJob(record.job),
			Events:  events,
			Close:   func() {},
		}, nil
	}

	m.nextSubID++
	subscriptionID := m.nextSubID
	if m.subscribers[id] == nil {
		m.subscribers[id] = make(map[uint64]chan Event)
	}
	m.subscribers[id][subscriptionID] = events
	var once sync.Once
	closeSubscription := func() {
		once.Do(func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			subscriptions := m.subscribers[id]
			if subscriptions == nil {
				return
			}
			if channel, exists := subscriptions[subscriptionID]; exists {
				delete(subscriptions, subscriptionID)
				close(channel)
			}
			if len(subscriptions) == 0 {
				delete(m.subscribers, id)
			}
		})
	}
	return Subscription{
		Current: cloneJob(record.job),
		Events:  events,
		Close:   closeSubscription,
	}, nil
}

// Close cancels all work and stops workers. It is safe to call more than once.
func (m *Manager) Close() {
	m.closeOnce.Do(func() {
		m.mu.Lock()
		m.closed = true
		for _, record := range m.jobs {
			if !terminal(record.job.Status) {
				m.requestCancelLocked(record)
			}
		}
		m.queue = nil
		m.rootCancel()
		m.cond.Broadcast()
		m.mu.Unlock()
		m.workerWG.Wait()
	})
}

func (m *Manager) worker() {
	defer m.workerWG.Done()
	for {
		m.mu.Lock()
		for len(m.queue) == 0 && !m.closed {
			m.cond.Wait()
		}
		if m.closed {
			m.mu.Unlock()
			return
		}
		id := m.queue[0]
		m.queue = m.queue[1:]
		record := m.jobs[id]
		if record == nil || record.job.Status != StatusQueued {
			m.mu.Unlock()
			continue
		}
		started := time.Now().UTC()
		record.job.Status = StatusRunning
		record.job.StartedAt = &started
		m.publishLocked(id, StatusRunning, started)
		config := record.config
		ctx := record.ctx
		m.mu.Unlock()

		report, scanErr := runScan(m.scanner, ctx, config)
		finished := time.Now().UTC()

		m.mu.Lock()
		record = m.jobs[id]
		if record == nil {
			m.mu.Unlock()
			continue
		}
		record.job.FinishedAt = &finished
		if record.job.Status != StatusCancelled {
			switch {
			case errors.Is(ctx.Err(), context.Canceled):
				record.job.Status = StatusCancelled
			case scanErr != nil:
				record.job.Status = StatusFailed
				record.job.Error = scanErr.Error()
			case report.Scan.Status == string(StatusPartial):
				record.job.Status = StatusPartial
			case report.Scan.Status == string(StatusFailed):
				record.job.Status = StatusFailed
			default:
				record.job.Status = StatusCompleted
			}
		}
		if report.SchemaVersion != "" {
			report.Scan.ID = record.job.ID
			report.Scan.Target = publicTarget(config)
			if record.job.Status == StatusCancelled {
				report.Scan.Status = string(StatusCancelled)
			}
			reportCopy := report
			record.job.Report = &reportCopy
		}
		record.cancel()
		clearPrivateRecord(record)
		m.terminalOrder = append(m.terminalOrder, id)
		m.publishLocked(id, record.job.Status, finished)
		m.closeSubscribersLocked(id)
		m.trimLocked()
		m.mu.Unlock()
	}
}

func runScan(scanner Scanner, ctx context.Context, config scan.Config) (report model.Report, err error) {
	defer func() {
		if recover() != nil {
			report = model.Report{}
			err = errors.New("scanner terminated unexpectedly")
		}
	}()
	return scanner.Scan(ctx, config)
}

func (m *Manager) requestCancelLocked(record *jobRecord) bool {
	switch record.job.Status {
	case StatusQueued:
		record.cancel()
		record.job.Status = StatusCancelled
		finished := time.Now().UTC()
		record.job.FinishedAt = &finished
		m.removeQueuedLocked(record.job.ID)
		clearPrivateRecord(record)
		m.terminalOrder = append(m.terminalOrder, record.job.ID)
		m.publishLocked(record.job.ID, StatusCancelled, finished)
		m.closeSubscribersLocked(record.job.ID)
		return true
	case StatusRunning:
		record.cancel()
		record.job.Status = StatusCancelling
		m.publishLocked(record.job.ID, StatusCancelling, time.Now().UTC())
		return true
	case StatusCancelling:
		// context.CancelFunc is idempotent, but no second lifecycle event is
		// emitted and the original terminal boundary remains with the worker.
		record.cancel()
		return false
	default:
		return false
	}
}

func clearPrivateRecord(record *jobRecord) {
	record.config = scan.Config{}
	record.ctx = nil
	record.cancel = nil
}

func (m *Manager) removeQueuedLocked(id string) {
	for index, queuedID := range m.queue {
		if queuedID != id {
			continue
		}
		copy(m.queue[index:], m.queue[index+1:])
		m.queue = m.queue[:len(m.queue)-1]
		return
	}
}

func (m *Manager) activeCountLocked() int {
	active := 0
	for _, record := range m.jobs {
		if !terminal(record.job.Status) {
			active++
		}
	}
	return active
}

func (m *Manager) trimLocked() {
	for len(m.terminalOrder) > m.config.MaxRetained {
		id := m.terminalOrder[0]
		m.terminalOrder = m.terminalOrder[1:]
		record := m.jobs[id]
		if record == nil || !terminal(record.job.Status) {
			continue
		}
		delete(m.jobs, id)
		delete(m.subscribers, id)
		m.removeOrderLocked(id)
	}
}

func (m *Manager) removeOrderLocked(id string) {
	for index, orderedID := range m.order {
		if orderedID == id {
			copy(m.order[index:], m.order[index+1:])
			m.order = m.order[:len(m.order)-1]
			return
		}
	}
}

func (m *Manager) publishLocked(id string, status JobStatus, timestamp time.Time) {
	event := Event{ID: id, Status: status, Timestamp: timestamp}
	for _, subscription := range m.subscribers[id] {
		select {
		case subscription <- event:
		default:
			// Lifecycle streams contain only a few transitions. A stalled
			// client that fills this buffer can recover via authenticated GET.
		}
	}
}

func (m *Manager) closeSubscribersLocked(id string) {
	for subscriptionID, subscription := range m.subscribers[id] {
		close(subscription)
		delete(m.subscribers[id], subscriptionID)
	}
	delete(m.subscribers, id)
}

func cloneJob(job Job) Job {
	if job.StartedAt != nil {
		started := *job.StartedAt
		job.StartedAt = &started
	}
	if job.FinishedAt != nil {
		finished := *job.FinishedAt
		job.FinishedAt = &finished
	}
	if job.Report != nil {
		report := *job.Report
		job.Report = &report
	}
	return job
}

func terminal(status JobStatus) bool {
	switch status {
	case StatusCompleted, StatusPartial, StatusFailed, StatusCancelled:
		return true
	default:
		return false
	}
}
