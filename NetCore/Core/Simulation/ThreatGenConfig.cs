using System;
using System.Collections.Generic;

namespace Core.Simulation;

public sealed record ThreatGenConfig(
    int Seed,
    int Count,
    string Environment,
    bool DryRun,
    bool IncludeEdgeCases,
    Dictionary<string, int> ScenarioWeights,
    bool UsePythonScorer,
    TimeSpan ActionTimeout,
    bool StopOnFailure
);
