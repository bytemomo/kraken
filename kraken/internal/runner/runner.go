package runner

import (
	"context"
	"fmt"
	"time"
	"strings"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/runner/contextkeys"

	"github.com/sirupsen/logrus"
)

// RegistryResolver handles lazy downloading of registry modules
type RegistryResolver interface {
	EnsureReady(ctx context.Context, mod *domain.Module) error
}

// Callbacks for live execution updates (all optional)
type Callbacks struct {
	OnTargetStart    func(target domain.Target, moduleCount int)
	OnTargetComplete func(target domain.Target, result domain.RunResult)
	OnModuleStart    func(target domain.Target, module string, timeout time.Duration)
	OnModuleComplete func(target domain.Target, module string, findings []domain.Finding, err error)
	OnFinding        func(finding domain.Finding)
	OnLog            func(level, message string)
}

// Runner executes a campaign against a set of targets.
type Runner struct {
	Log              *logrus.Entry
	Executors        []ModuleExecutor
	Store            domain.ResultRepo
	ResultDirectory  string
	Callbacks        Callbacks
	RegistryResolver RegistryResolver // Optional: for lazy downloading registry modules
}

// Execute executes the campaign. It runs all modules against all targets, in parallel.
// Targets are processed in parallel (up to MaxParallelTargets), but modules for each
// target run sequentially to avoid overwhelming OT devices.
func (r *Runner) Execute(ctx context.Context, campaign domain.Campaign, classified []domain.ClassifiedTarget) ([]domain.RunResult, error) {
	policy := campaign.EffectivePolicy()

	log := r.Log.WithFields(logrus.Fields{
		"max_parallel_targets": policy.Runner.MaxParallelTargets,
		"allow_aggressive":     policy.Safety.AllowAggressive,
		"require_max_duration": policy.Safety.RequiresMaxDuration(),
	})
	log.Info("Running campaign with safety policy")

	log.WithFields(logrus.Fields{
		"campaign": campaign.ID,
		"targets":  len(classified),
	}).Info("Starting campaign execution")

	connDefaults := policy.Runner.Defaults

	sem := make(chan struct{}, max(1, policy.Runner.MaxParallelTargets))
	out := make(chan domain.RunResult, len(classified))

	for _, ct := range classified {
		ct := ct
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			res := r.runForTarget(ctx, log, campaign, ct, connDefaults)
			if err := r.Store.Save(res.Target, res); err != nil {
				log.WithFields(logrus.Fields{
					"target": res.Target.String(),
					"error":  err,
				}).Error("Failed to save result")
			}
			out <- res
		}()
	}

	var all []domain.RunResult
	for i := 0; i < len(classified); i++ {
		all = append(all, <-out)
	}

	log.WithField("campaign", campaign.ID).Info("Campaign execution finished")
	return all, nil
}

func (r *Runner) runForTarget(ctx context.Context, log *logrus.Entry, camp domain.Campaign, ct domain.ClassifiedTarget, connDefaults domain.ConnectionDefaults) domain.RunResult {
	if connDefaults.MaxConnectionsPerTarget > 0 {
		connDefaults.ConnSem = make(chan struct{}, connDefaults.MaxConnectionsPerTarget)
	}

	// Pass campaign type to executors via context
	campType := camp.EffectiveType()
	ctx = context.WithValue(ctx, contextkeys.CampaignType, &campType)

	result := domain.RunResult{Target: ct.Target}
	plan := filterStepsByTags(camp.Tasks, ct.Tags)

	log.WithFields(logrus.Fields{
		"target": ct.Target.String(),
		"tags":   ct.Tags,
		"plan":   stepIDs(plan),
	}).Info("Running for target")

	// Callback: target started
	if r.Callbacks.OnTargetStart != nil {
		r.Callbacks.OnTargetStart(ct.Target, len(plan))
	}

	for _, mod := range plan {
		if err := ctx.Err(); err != nil {
			log.WithError(err).Info("Context cancelled, stopping execution for target")
			break
		}

		rr := r.runModuleStep(ctx, log, mod, ct.Target, connDefaults)
		result.Findings = append(result.Findings, rr.Findings...)
		result.Logs = append(result.Logs, rr.Logs...)
	}

	// Callback: target completed
	if r.Callbacks.OnTargetComplete != nil {
		r.Callbacks.OnTargetComplete(ct.Target, result)
	}

	return result
}

func (r *Runner) runModuleStep(ctx context.Context, log *logrus.Entry, mod *domain.Module, target domain.Target, connDefaults domain.ConnectionDefaults) domain.RunResult {
	result := domain.RunResult{Target: target}

	l := log.WithFields(logrus.Fields{
		"target": target.String(),
		"module": mod.ModuleID,
	})

	// Lazy download registry modules just before execution
	if mod.Registry != "" && r.RegistryResolver != nil {
		if err := r.RegistryResolver.EnsureReady(ctx, mod); err != nil {
			msg := fmt.Sprintf("download module %s: %v", mod.ModuleID, err)
			l.WithError(err).Error("Failed to download registry module")
			result.Logs = append(result.Logs, msg)
			if r.Callbacks.OnLog != nil {
				r.Callbacks.OnLog("error", msg)
			}
			return result
		}
	}

	var exec ModuleExecutor
	for _, e := range r.Executors {
		if e.Supports(mod) {
			exec = e
			break
		}
	}

	if exec == nil {
		msg := fmt.Sprintf("no executor found for module %q (type=%s)", mod.ModuleID, mod.Type)
		l.Warn(msg)
		result.Logs = append(result.Logs, msg)
		if r.Callbacks.OnLog != nil {
			r.Callbacks.OnLog("warn", msg)
		}
		return result
	}

	// Callback: module started
	if r.Callbacks.OnModuleStart != nil {
		r.Callbacks.OnModuleStart(target, mod.ModuleID, mod.MaxDuration)
	}

	ctx = context.WithValue(ctx, contextkeys.OutDir, &r.ResultDirectory)
	ctx = context.WithValue(ctx, contextkeys.ConnectionDefaults, &connDefaults)

	if mod.MaxDuration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, mod.MaxDuration)
		defer cancel()
	}

	rr, err := exec.Run(ctx, mod, mod.ExecConfig.Params, target, mod.MaxDuration)

	if err != nil {
		msg := fmt.Sprintf("run module %s: %v", mod.ModuleID, err)
		// Treat killed/timeout as warning (expected for fuzz campaigns)
		if strings.Contains(err.Error(), "signal: killed") || strings.Contains(err.Error(), "context deadline exceeded") {
			l.WithError(err).Warn("Module execution terminated")
		} else {
			l.WithError(err).Error("Module execution failed")
		}
		result.Logs = append(result.Logs, msg)
		if r.Callbacks.OnModuleComplete != nil {
			r.Callbacks.OnModuleComplete(target, mod.ModuleID, nil, err)
		}
		if r.Callbacks.OnLog != nil {
			r.Callbacks.OnLog("error", msg)
		}
		return result
	}

	l.WithFields(logrus.Fields{
		"findings": len(rr.Findings),
		"logs":     len(rr.Logs),
	}).Info("Module execution complete")

	// Callback: emit each finding
	if r.Callbacks.OnFinding != nil {
		for _, f := range rr.Findings {
			r.Callbacks.OnFinding(f)
		}
	}

	// Callback: module completed
	if r.Callbacks.OnModuleComplete != nil {
		r.Callbacks.OnModuleComplete(target, mod.ModuleID, rr.Findings, nil)
	}

	result.Findings = rr.Findings
	result.Logs = rr.Logs
	return result
}

func filterStepsByTags(steps []*domain.Module, tags []domain.Tag) []*domain.Module {
	tagset := make(map[domain.Tag]struct{})
	for _, t := range tags {
		tagset[t] = struct{}{}
	}

	var out []*domain.Module
STEP:
	for _, mod := range steps {
		for _, req := range mod.RequiredTags {
			if _, ok := tagset[domain.Tag(req)]; !ok {
				continue STEP
			}
		}
		out = append(out, mod)
	}
	return out
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func stepIDs(steps []*domain.Module) []string {
	ids := make([]string, len(steps))
	for i, mod := range steps {
		ids[i] = mod.ModuleID
	}
	return ids
}
