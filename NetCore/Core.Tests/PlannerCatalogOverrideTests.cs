using System;
using System.Collections.Generic;
using Core.Planning;
using Xunit;

public sealed class PlannerCatalogOverrideTests
{
    [Fact]
    public void UsesContextCatalogAndKeepsUnknownActions()
    {
        var planner = new Planner(
            ActionCatalogDefaults.CreateDefault(),
            new BasicStrategySelector(),
            new BasicActionSelector(),
            new BasicRiskEstimator(),
            new BasicRollbackBuilder(),
            new BasicActionNormalizer());

        var alert = BuildAlert(srcIp: "10.0.0.5");
        var assessment = new ThreatAssessment(0.9, 80, "hyp", new List<string> { "e" });

        var restrictedCatalog = new ActionCatalog(new Dictionary<ActionType, ActionDefinition>());
        var ctx = new PlanningContext("dev", false, restrictedCatalog, DateTimeOffset.UtcNow);

        var plan = planner.Plan(alert, assessment, ctx);

        Assert.Contains(plan.Actions, action => action.Type == ActionType.BlockIp);
        var block = Assert.Single(plan.Actions, a => a.Type == ActionType.BlockIp);
        Assert.Equal(100, block.Risk);
        Assert.Equal(100, block.ExpectedImpact);
    }

    private static EnrichedAlert BuildAlert(string? srcIp)
    {
        var alert = new NormalizedAlert(
            AlertId: "a1",
            SourceSiem: "demo",
            TimestampUtc: DateTimeOffset.UtcNow,
            AlertType: "test",
            RuleName: "rule",
            Severity: 50,
            Entities: new Entities(
                Hostname: null,
                HostId: null,
                Username: null,
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
            Asset: new AssetContext("asset-1", 0),
            Identity: null,
            ThreatIntel: null,
            History: null,
            Tags: null
        );

        return new EnrichedAlert(alert, ctx, new List<EnrichmentNote>());
    }
}
