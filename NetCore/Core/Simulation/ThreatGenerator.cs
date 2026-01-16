using System;
using System.Collections.Generic;
using System.Linq;

namespace Core.Simulation;

public sealed class ThreatGenerator : IThreatGenerator
{
    public IReadOnlyList<GeneratedThreat> Generate(ThreatGenConfig config)
    {
        if (config is null) throw new ArgumentNullException(nameof(config));

        var rng = new Random(config.Seed);
        var scenarios = BuildScenarioPool(config, rng);
        var threats = new List<GeneratedThreat>(config.Count);

        for (var i = 0; i < config.Count; i++)
        {
            var scenarioType = PickScenario(scenarios, rng);
            var threat = ScenarioTemplates.Create(scenarioType, rng);
            threats.Add(threat);
        }

        return threats;
    }

    private static List<string> BuildScenarioPool(ThreatGenConfig config, Random rng)
    {
        var pool = new List<string>();

        if (config.ScenarioWeights is { Count: > 0 })
        {
            foreach (var kv in config.ScenarioWeights)
            {
                var weight = Math.Max(0, kv.Value);
                for (var i = 0; i < weight; i++)
                    pool.Add(kv.Key);
            }
        }

        if (pool.Count == 0)
        {
            pool.AddRange(new[]
            {
                ScenarioTemplates.PortScanFromIp,
                ScenarioTemplates.BruteForceUser,
                ScenarioTemplates.MalwareHashOnHost,
                ScenarioTemplates.SuspiciousProcessOnHost,
                ScenarioTemplates.BenignNoise
            });
        }

        if (config.IncludeEdgeCases)
        {
            pool.Add(ScenarioTemplates.EdgeMissingParams);
            pool.Add(ScenarioTemplates.EdgeMalformedAlert);
        }

        return pool;
    }

    private static string PickScenario(IReadOnlyList<string> pool, Random rng)
        => pool[rng.Next(0, pool.Count)];
}
