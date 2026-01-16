using System;
using System.Collections.Generic;
using Core.Planning;
using Core.Policy;
using Xunit;

public sealed class PolicyEngineTests
{
    [Fact]
    public void UnknownAction_IsDenied()
    {
        var emptyCatalog = new ActionCatalog(new Dictionary<ActionType, ActionDefinition>());
        var engine = new PolicyEngine(emptyCatalog, new ApprovalWorkflow());
        var action = BuildAction(ActionType.Notify, new Dictionary<string, string>());
        var decision = engine.EvaluateAction(action, Assessment(0.9), alert: null, Context());

        Assert.Equal(PolicyActionStatus.Denied, decision.Status);
        Assert.Contains("Unknown or unsupported", decision.Reasons[0], StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void HighRisk_Action_PendingApproval()
    {
        var catalog = ActionCatalogDefaults.CreateDefault();
        var engine = new PolicyEngine(catalog, new ApprovalWorkflow());
        var action = BuildAction(ActionType.BlockIp, new Dictionary<string, string> { ["src_ip"] = "1.2.3.4" }) with
        {
            Risk = 90,
            ExpectedImpact = 10
        };

        var decision = engine.EvaluateAction(action, Assessment(0.9), alert: null, Context());

        Assert.Equal(PolicyActionStatus.PendingApproval, decision.Status);
    }

    [Fact]
    public void LowConfidence_Action_Denied()
    {
        var catalog = ActionCatalogDefaults.CreateDefault();
        var engine = new PolicyEngine(catalog, new ApprovalWorkflow());
        var action = BuildAction(ActionType.BlockIp, new Dictionary<string, string> { ["src_ip"] = "1.2.3.4" });
        var decision = engine.EvaluateAction(action, Assessment(0.1), alert: null, Context());

        Assert.Equal(PolicyActionStatus.Denied, decision.Status);
    }

    private static PlannedAction BuildAction(ActionType type, IReadOnlyDictionary<string, string> parameters)
        => new(
            ActionId: ActionIdFactory.Create(type, parameters),
            Type: type,
            Risk: 10,
            ExpectedImpact: 10,
            Reversible: false,
            Duration: null,
            Parameters: new Dictionary<string, string>(parameters),
            Rationale: "test");

    private static ThreatAssessment Assessment(double confidence)
        => new(confidence, 50, "hyp", new List<string> { "e" });

    private static PlanningContext Context()
        => new("dev", false, ActionCatalogDefaults.CreateDefault(), DateTimeOffset.UtcNow);
}
