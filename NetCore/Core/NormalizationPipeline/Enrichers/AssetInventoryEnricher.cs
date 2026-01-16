using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Core.Interfaces;

namespace Core.NormalizationPipeline;

public sealed class AssetInventoryEnricher : IEnrichmentProvider
{
    private readonly IReadOnlyList<AssetRecord> _assets;

    public string Name => "AssetInventory";

    public AssetInventoryEnricher(string jsonPath)
    {
        if (string.IsNullOrWhiteSpace(jsonPath))
            throw new ArgumentException("Path is required.", nameof(jsonPath));

        var json = File.ReadAllText(jsonPath);
        _assets = JsonSerializer.Deserialize<List<AssetRecord>>(json, new JsonSerializerOptions(JsonSerializerDefaults.Web))
                  ?? new List<AssetRecord>();
    }

    public Task<EnrichmentPatch> EnrichAsync(NormalizedAlert alert, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var e = alert.Entities;
        var asset = _assets.FirstOrDefault(a =>
            Matches(a.HostId, e.HostId) ||
            Matches(a.Hostname, e.Hostname) ||
            Matches(a.Ip, e.SrcIp));

        if (asset is null)
            return Task.FromResult(new EnrichmentPatch());

        var ctx = new AssetContext(
            AssetId: asset.HostId ?? asset.Hostname ?? "unknown",
            Criticality: asset.Criticality,
            Environment: asset.Environment,
            Roles: new[] { asset.Owner, asset.Team }.Where(s => !string.IsNullOrWhiteSpace(s)).ToList());

        var tags = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["asset_owner"] = asset.Owner ?? string.Empty,
            ["asset_team"] = asset.Team ?? string.Empty
        };

        return Task.FromResult(new EnrichmentPatch(
            Asset: ctx,
            Tags: tags,
            Note: new EnrichmentNote(Name, DateTimeOffset.UtcNow, "Asset matched.")));
    }

    private static bool Matches(string? a, string? b)
        => !string.IsNullOrWhiteSpace(a) && !string.IsNullOrWhiteSpace(b) &&
           string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    private sealed record AssetRecord(
        string? HostId,
        string? Hostname,
        string? Ip,
        int Criticality,
        string? Environment,
        string? Owner,
        string? Team
    );
}
