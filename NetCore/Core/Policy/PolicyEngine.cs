using System;
using System.Collections.Generic;
using System.Linq;

namespace Core.Policy;

/// <summary>
/// Policy-gated governance for DecisionPlans.
/// It does NOT execute actions; it classifies them as Approved/Pending/Denied
/// and optionally creates approval requests.
/// </summary>
public sealed class PolicyEngine
{
    private readonly ActionCatalog _catalog;
    private readonly ApprovalWorkflow _approvals;
    private readonly PolicyConfig _config;

    public PolicyEngine(ActionCatalog catalog, ApprovalWorkflow approvals, PolicyConfig? config = null)
    {
        _catalog = catalog ?? throw new ArgumentNullException(nameof(catalog));
        _approvals = approvals ?? throw new ArgumentNullException(nameof(approvals));
        _config = config ?? PolicyConfig.Default;
    }

    /// <summary>
    /// Classifies a single action (Approved/Pending/Denied) with reasons.
    /// </summary>
    public PolicyActionDecision EvaluateAction(
        PlannedAction action,
        ThreatAssessment assessment,
        EnrichedAlert? alert,
        PlanningContext ctx)
    {
        if (action is null) throw new ArgumentNullException(nameof(action));
        if (assessment is null) throw new ArgumentNullException(nameof(assessment));
        if (ctx is null) throw new ArgumentNullException(nameof(ctx));

        if (!_catalog.TryGet(action.Type, out var def))
        {
            return new PolicyActionDecision(
                action,
                PolicyActionStatus.Denied,
                new[] { "Unknown or unsupported action type." }
            );
        }

        // --- Hard denials (no approval path) ---
        var denialReasons = new List<string>();

        // Required parameters check (defensive; planner should already sanitize)
        if (!HasRequiredParameters(action, def))
            denialReasons.Add("Missing required parameters.");

        // Environment hard blocks
        if (_config.ForbiddenActionsByEnvironment.TryGetValue(ctx.Environment, out var forbidden) &&
            forbidden.Contains(action.Type))
        {
            denialReasons.Add($"Action '{action.Type}' is forbidden in environment '{ctx.Environment}'.");
        }

        // Confidence too low for any autonomous action except Notify/OpenTicket
        if (assessment.Confidence < _config.MinConfidenceForAutonomy &&
            !_config.SafeLowConfidenceActions.Contains(action.Type))
        {
            denialReasons.Add($"Confidence {assessment.Confidence:0.00} below minimum {_config.MinConfidenceForAutonomy:0.00} for autonomous action '{action.Type}'.");
        }

        // Privileged or critical target protection (if we have enrichment)
        var privileged = alert?.Context.Identity?.Privileged == true;
        var criticality = alert?.Context.Asset?.Criticality ?? 0;

        if (privileged && _config.ForbidActionsOnPrivilegedIdentities.Contains(action.Type))
            denialReasons.Add($"Action '{action.Type}' is forbidden on privileged identities.");

        if (criticality >= _config.CriticalAssetThreshold &&
            _config.ForbidActionsOnCriticalAssets.Contains(action.Type))
        {
            denialReasons.Add($"Action '{action.Type}' is forbidden on critical assets (criticality={criticality}).");
        }

        if (denialReasons.Count > 0)
        {
            return new PolicyActionDecision(
                action,
                PolicyActionStatus.Denied,
                denialReasons
            );
        }

        // --- Approval gating ---
        var approvalReasons = new List<string>();

        // Catalog default says approval required
        if (def.RequiresApprovalByDefault)
            approvalReasons.Add("Catalog marks this action as approval-required by default.");

        // Risk/impact thresholds
        if (action.Risk >= _config.RiskApprovalThreshold)
            approvalReasons.Add($"Risk {action.Risk} exceeds approval threshold {_config.RiskApprovalThreshold}.");

        if (action.ExpectedImpact >= _config.ImpactApprovalThreshold)
            approvalReasons.Add($"Impact {action.ExpectedImpact} exceeds approval threshold {_config.ImpactApprovalThreshold}.");

        // Extra caution in production
        if (string.Equals(ctx.Environment, "prod", StringComparison.OrdinalIgnoreCase) &&
            _config.RequireApprovalInProd.Contains(action.Type))
        {
            approvalReasons.Add($"Action '{action.Type}' requires approval in prod.");
        }

        // Higher scrutiny for privileged/critical targets (approval instead of denial)
        if (privileged && _config.RequireApprovalOnPrivilegedIdentities.Contains(action.Type))
            approvalReasons.Add("Target identity is privileged.");

        if (criticality >= _config.CriticalAssetThreshold &&
            _config.RequireApprovalOnCriticalAssets.Contains(action.Type))
        {
            approvalReasons.Add($"Target asset is critical (criticality={criticality}).");
        }

        if (approvalReasons.Count > 0)
        {
            return new PolicyActionDecision(
                action,
                PolicyActionStatus.PendingApproval,
                approvalReasons
            );
        }

        return new PolicyActionDecision(
            action,
            PolicyActionStatus.Approved,
            new[] { "Within policy limits." }
        );
    }

    private static bool HasRequiredParameters(PlannedAction action, ActionDefinition def)
    {
        var required = def.RequiredParameters;
        if (required is null || required.Count == 0)
            return true;

        return action.Type switch
        {
            ActionType.KillProcess => HasAny(action, "host_id", "hostId", "hostname") &&
                                      HasAny(action, "process_name", "processName", "pid"),
            ActionType.QuarantineFile => HasAny(action, "host_id", "hostId") &&
                                         HasAny(action, "file_hash", "fileHash", "file_path", "filePath"),
            _ => required switch
            {
                [ "username", "user_id" ] => HasAny(action, "username", "user_id"),
                [ "hostname", "host_id" ] => HasAny(action, "hostname", "host_id"),
                _ => HasAll(action, required)
            }
        };
    }

    private static bool HasAny(PlannedAction action, params string[] keys)
        => keys.Any(key => action.Parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value));

    private static bool HasAll(PlannedAction action, IEnumerable<string> keys)
        => keys.All(key => action.Parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value));

    /// <summary>
    /// Evaluate a plan and create approval requests for pending actions.
    /// </summary>
    public PolicyDecision Evaluate(DecisionPlan plan, ThreatAssessment assessment, EnrichedAlert? alert, PlanningContext ctx)
    {
        if (plan is null) throw new ArgumentNullException(nameof(plan));
        if (assessment is null) throw new ArgumentNullException(nameof(assessment));
        if (ctx is null) throw new ArgumentNullException(nameof(ctx));

        // Global plan-level guardrail: cap number of actions
        if (plan.Actions.Count > _config.MaxActionsPerPlan)
        {
            // Deny everything beyond the cap (or deny the whole plan; choose one)
            var deniedAll = plan.Actions
                .Select(a => new PolicyActionDecision(a, PolicyActionStatus.Denied,
                    new[] { $"Plan exceeds max actions {_config.MaxActionsPerPlan}." }))
                .ToList();

            return PolicyDecision.FromActionDecisions(deniedAll, notes: new[]
            {
                $"Denied: plan has {plan.Actions.Count} actions, exceeds limit {_config.MaxActionsPerPlan}.",
                $"Assessment: Severity={assessment.Severity}, Confidence={assessment.Confidence:0.00}."
            });
        }

        var perAction = plan.Actions
            .Select(a => EvaluateAction(a, assessment, alert, ctx))
            .ToList();

        var pending = perAction.Where(d => d.Status == PolicyActionStatus.PendingApproval)
            .Select(d => d.Action).ToList();

        if (pending.Count > 0)
            _approvals.CreateRequests(pending, "Policy approval required.");

        var notes = new List<string>
        {
            $"Approved={perAction.Count(d => d.Status == PolicyActionStatus.Approved)}, " +
            $"Pending={perAction.Count(d => d.Status == PolicyActionStatus.PendingApproval)}, " +
            $"Denied={perAction.Count(d => d.Status == PolicyActionStatus.Denied)}.",
            $"Assessment: Severity={assessment.Severity}, Confidence={assessment.Confidence:0.00}."
        };

        return PolicyDecision.FromActionDecisions(perAction, notes);
    }

    // Convenience overload when you don't have enrichment details available
    public PolicyDecision Evaluate(DecisionPlan plan, ThreatAssessment assessment, PlanningContext ctx)
        => Evaluate(plan, assessment, alert: null, ctx);

    public PolicyDecision Evaluate(DecisionPlan plan, PlanningContext ctx)
        => Evaluate(plan, new ThreatAssessment(0, 0, string.Empty, new List<string>()), alert: null, ctx);
}


