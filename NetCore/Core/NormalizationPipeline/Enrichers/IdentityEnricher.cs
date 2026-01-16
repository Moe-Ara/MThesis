using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Core.Interfaces;

namespace Core.NormalizationPipeline;

public sealed class IdentityEnricher : IEnrichmentProvider
{
    private readonly IReadOnlyList<IdentityRecord> _identities;

    public string Name => "Identity";

    public IdentityEnricher(string jsonPath)
    {
        if (string.IsNullOrWhiteSpace(jsonPath))
            throw new ArgumentException("Path is required.", nameof(jsonPath));

        var json = File.ReadAllText(jsonPath);
        _identities = JsonSerializer.Deserialize<List<IdentityRecord>>(json, new JsonSerializerOptions(JsonSerializerDefaults.Web))
                      ?? new List<IdentityRecord>();
    }

    public Task<EnrichmentPatch> EnrichAsync(NormalizedAlert alert, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var e = alert.Entities;
        var identity = _identities.FirstOrDefault(i =>
            Matches(i.UserId, e.UserId) ||
            Matches(i.Username, e.Username));

        if (identity is null)
            return Task.FromResult(new EnrichmentPatch());

        var ctx = new IdentityContext(
            UserId: identity.UserId ?? identity.Username,
            Privileged: identity.Privileged,
            Department: identity.Department,
            Groups: identity.IsServiceAccount ? new[] { "service_account" } : null);

        var tags = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["department"] = identity.Department ?? string.Empty,
            ["is_service_account"] = identity.IsServiceAccount.ToString()
        };

        return Task.FromResult(new EnrichmentPatch(
            Identity: ctx,
            Tags: tags,
            Note: new EnrichmentNote(Name, DateTimeOffset.UtcNow, "Identity matched.")));
    }

    private static bool Matches(string? a, string? b)
        => !string.IsNullOrWhiteSpace(a) && !string.IsNullOrWhiteSpace(b) &&
           string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    private sealed record IdentityRecord(
        string? UserId,
        string? Username,
        bool Privileged,
        string? Department,
        bool IsServiceAccount
    );
}
