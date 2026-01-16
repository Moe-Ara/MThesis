using System;
using System.Collections.Generic;
using Core.Simulation;

namespace Core.Scoring;

public sealed class StubThreatScorer : IThreatScorer
{
    public ThreatAssessment Score(EnrichedAlert enrichedAlert)
    {
        if (enrichedAlert is null) throw new ArgumentNullException(nameof(enrichedAlert));

        var scenario = GetScenario(enrichedAlert);
        var (confidence, severity) = scenario switch
        {
            ScenarioTemplates.PortScanFromIp => (0.85, 70),
            ScenarioTemplates.BruteForceUser => (0.8, 65),
            ScenarioTemplates.MalwareHashOnHost => (0.9, 85),
            ScenarioTemplates.SuspiciousProcessOnHost => (0.75, 60),
            ScenarioTemplates.EdgeMissingParams => (0.7, 55),
            ScenarioTemplates.EdgeMalformedAlert => (0.2, 10),
            ScenarioTemplates.BenignNoise => (0.2, 15),
            _ => (0.5, 40)
        };

        var hypothesis = scenario is ScenarioTemplates.BenignNoise or ScenarioTemplates.EdgeMalformedAlert
            ? "Likely benign noise."
            : "Suspicious activity detected.";

        return new ThreatAssessment(
            Confidence: confidence,
            Severity: severity,
            Hypothesis: hypothesis,
            Evidence: new List<string> { $"scenario:{scenario}" },
            RecommendedActions: BuildRecommendations(scenario, enrichedAlert));
    }

    public Explanation Explain(EnrichedAlert enrichedAlert)
    {
        if (enrichedAlert is null) throw new ArgumentNullException(nameof(enrichedAlert));

        var scenario = GetScenario(enrichedAlert);
        return new Explanation(
            Summary: $"Stub explanation for {scenario}.",
            Details: new[] { "Deterministic stub scorer.", $"scenario={scenario}" });
    }

    private static IReadOnlyList<ProposedAction>? BuildRecommendations(string scenario, EnrichedAlert alert)
    {
        var entities = alert.Base.Entities;
        var srcIp = entities.SrcIp ?? "10.0.0.1";
        var username = entities.Username ?? "user1";
        var hostId = entities.HostId ?? "host-1";
        var processName = entities.ProcessName ?? "powershell.exe";
        var fileHash = entities.FileHash ?? "hash";

        return scenario switch
        {
            ScenarioTemplates.PortScanFromIp => new List<ProposedAction>
            {
                new(ActionType.BlockIp, new Dictionary<string, string> { ["src_ip"] = srcIp }, "Block scanning IP.")
            },
            ScenarioTemplates.BruteForceUser => new List<ProposedAction>
            {
                new(ActionType.DisableUser, new Dictionary<string, string> { ["username"] = username }, "Disable targeted user.")
            },
            ScenarioTemplates.MalwareHashOnHost => new List<ProposedAction>
            {
                new(ActionType.QuarantineFile, new Dictionary<string, string> { ["host_id"] = hostId, ["file_hash"] = fileHash }, "Quarantine malware.")
            },
            ScenarioTemplates.SuspiciousProcessOnHost => new List<ProposedAction>
            {
                new(ActionType.KillProcess, new Dictionary<string, string> { ["host_id"] = hostId, ["process_name"] = processName }, "Kill suspicious process.")
            },
            _ => null
        };
    }

    private static string GetScenario(EnrichedAlert enrichedAlert)
    {
        if (enrichedAlert.Context.Tags is not null &&
            enrichedAlert.Context.Tags.TryGetValue("scenario_type", out var scenario))
        {
            return scenario;
        }

        return enrichedAlert.Base.AlertType ?? ScenarioTemplates.BenignNoise;
    }
}
