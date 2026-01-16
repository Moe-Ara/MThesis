using System.Collections.Generic;

namespace Core.Simulation;

public sealed record GeneratedThreat(
    string ScenarioId,
    string ScenarioType,
    RawAlert Raw,
    string GroundTruth,
    IReadOnlyDictionary<string, string> ExpectedTags
);
