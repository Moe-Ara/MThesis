using System;
using System.Collections.Generic;
using Core.Planning;
using Xunit;

public sealed class PlannerTests
{
    private static Planner BuildPlanner()
        => new(
            ActionCatalogDefaults.CreateDefault(),
            new BasicStrategySelector(),
            new BasicActionSelector(),
            new BasicRiskEstimator(),
            new BasicRollbackBuilder(),
            new BasicActionNormalizer());

    private static EnrichedAlert BuildAlert(
        string? srcIp = null,
        string? hostname = null,
        string? username = null,
        int criticality = 0,
        bool privileged = false)
    {
        var alert = new NormalizedAlert(
            AlertId: "a1",
            SourceSiem: "demo",
            TimestampUtc: DateTimeOffset.UtcNow,
            AlertType: "test",
            RuleName: "rule",
            Severity: 50,
            Entities: new Entities(
                Hostname: hostname,
                HostId: null,
                Username: username,
                UserId: null,
                SrcIp: srcIp,
                DstIp: null,
                Domain: null,
                ProcessName: null,
                ProcessPath: null,
                FileHash: null
            ),
            RawPayload: default
        );

        var ctx = new EnrichmentContext(
            Asset: new AssetContext("asset-1", criticality),
            Identity: new IdentityContext("user-1", privileged),
            ThreatIntel: null,
            History: null,
            Tags: null
        );

        return new EnrichedAlert(alert, ctx, new List<EnrichmentNote>());
    }

    private static ThreatAssessment Assessment(double confidence, int severity)
        => new(confidence, severity, "hypothesis", new List<string> { "evidence" });

    private static PlanningContext Context()
        => new("prod", false, ActionCatalogDefaults.CreateDefault(), DateTimeOffset.UtcNow);

    [Fact]
    public void LowConfidence_ObserveMore_OnlyTicket()
    {
        var planner = BuildPlanner();
        var alert = BuildAlert();
        var plan = planner.Plan(alert, Assessment(0.1, 30), Context());

        Assert.Equal(PlanStrategy.ObserveMore, plan.Strategy);
        Assert.Single(plan.Actions);
        Assert.Equal(ActionType.OpenTicket, plan.Actions[0].Type);
    }

    [Fact]
    public void HighConfidence_WithSrcIp_IncludesBlockIp()
    {
        var planner = BuildPlanner();
        var alert = BuildAlert(srcIp: "10.0.0.5");
        var plan = planner.Plan(alert, Assessment(0.9, 80), Context());

        Assert.Contains(plan.Actions, action => action.Type == ActionType.BlockIp);
    }

    [Fact]
    public void CriticalAsset_EscalateToHuman()
    {
        var planner = BuildPlanner();
        var alert = BuildAlert(criticality: 5);
        var plan = planner.Plan(alert, Assessment(0.5, 60), Context());

        Assert.Equal(PlanStrategy.EscalateToHuman, plan.Strategy);
    }

    [Fact]
    public void RollbackGeneratedForContainment()
    {
        var planner = BuildPlanner();
        var alert = BuildAlert(srcIp: "10.0.0.5", hostname: "host-1", username: "alice");
        var plan = planner.Plan(alert, Assessment(0.9, 80), Context());

        Assert.Contains(plan.RollbackActions, action => action.Type == ActionType.UnblockIp);
        Assert.Contains(plan.RollbackActions, action => action.Type == ActionType.UnisolateHost);
        Assert.Contains(plan.RollbackActions, action => action.Type == ActionType.EnableUser);
    }

    [Fact]
    public void MissingEntities_SkipsContainmentActions()
    {
        var planner = BuildPlanner();
        var alert = BuildAlert();
        var plan = planner.Plan(alert, Assessment(0.9, 80), Context());

        Assert.DoesNotContain(plan.Actions, action => action.Type == ActionType.BlockIp);
        Assert.DoesNotContain(plan.Actions, action => action.Type == ActionType.DisableUser);
        Assert.DoesNotContain(plan.Actions, action => action.Type == ActionType.IsolateHost);
    }

    [Fact]
    public void Sanitizer_DropsActionsWithMissingRequiredParams()
    {
        var planner = BuildPlanner();
        var alert = BuildAlert(srcIp: "10.0.0.5");
        var assessment = new ThreatAssessment(
            Confidence: 0.9,
            Severity: 80,
            Hypothesis: "test",
            Evidence: new List<string> { "e" },
            RecommendedActions: new List<ProposedAction>
            {
                new(ActionType.BlockIp, new Dictionary<string, string>(), "missing params")
            }
        );

        var plan = planner.Plan(alert, assessment, Context());

        Assert.Contains(plan.Actions, action => action.Type == ActionType.BlockIp);
        Assert.DoesNotContain(plan.Actions, action =>
            action.Type == ActionType.BlockIp && action.Parameters.Count == 0);
    }
}
