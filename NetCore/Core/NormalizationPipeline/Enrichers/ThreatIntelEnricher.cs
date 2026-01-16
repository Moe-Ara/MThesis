using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Core.Interfaces;

namespace Core.NormalizationPipeline;

public sealed class ThreatIntelEnricher : IEnrichmentProvider
{
    private readonly IReadOnlyList<ThreatIntelRecord> _records;

    public string Name => "ThreatIntel";

    public ThreatIntelEnricher(string jsonPath)
    {
        if (string.IsNullOrWhiteSpace(jsonPath))
            throw new ArgumentException("Path is required.", nameof(jsonPath));

        var json = File.ReadAllText(jsonPath);
        _records = JsonSerializer.Deserialize<List<ThreatIntelRecord>>(json, new JsonSerializerOptions(JsonSerializerDefaults.Web))
                   ?? new List<ThreatIntelRecord>();
    }

    public Task<EnrichmentPatch> EnrichAsync(NormalizedAlert alert, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var e = alert.Entities;
        var intel = _records.FirstOrDefault(r =>
            Matches(r.SrcIp, e.SrcIp) ||
            Matches(r.FileHash, e.FileHash));

        if (intel is null)
            return Task.FromResult(new EnrichmentPatch());

        var ctx = new ThreatIntelContext(
            ReputationScore: intel.ReputationScore,
            Matches: intel.Tags?.ToList());

        var tags = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["ti_source"] = intel.Source ?? string.Empty
        };

        return Task.FromResult(new EnrichmentPatch(
            ThreatIntel: ctx,
            Tags: tags,
            Note: new EnrichmentNote(Name, DateTimeOffset.UtcNow, "Threat intel matched.")));
    }

    private static bool Matches(string? a, string? b)
        => !string.IsNullOrWhiteSpace(a) && !string.IsNullOrWhiteSpace(b) &&
           string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    private sealed record ThreatIntelRecord(
        string? SrcIp,
        string? FileHash,
        int ReputationScore,
        string? Source,
        IReadOnlyList<string>? Tags
    );
}
