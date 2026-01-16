using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Core.Auditing;

public sealed class JsonlAuditPipeline : IAuditPipeline
{
    private readonly string _path;
    private readonly JsonSerializerOptions _options = new(JsonSerializerDefaults.Web);

    public JsonlAuditPipeline(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("Path is required.", nameof(path));

        _path = path;
    }

    public Task<AuditReport> BuildReportAsync(AuditQuery query, CancellationToken ct)
    {
        var entries = new List<AuditEntry>();
        if (File.Exists(_path))
        {
            foreach (var line in File.ReadLines(_path))
            {
                ct.ThrowIfCancellationRequested();
                if (string.IsNullOrWhiteSpace(line))
                    continue;

                try
                {
                    var entry = JsonSerializer.Deserialize<AuditEntry>(line, _options);
                    if (entry is null)
                        continue;

                    if (!Matches(entry, query))
                        continue;

                    entries.Add(entry);
                }
                catch
                {
                    // Skip malformed lines.
                }
            }
        }

        var summary = BuildSummary(entries);
        var report = new AuditReport(
            ReportId: Guid.NewGuid().ToString("N"),
            GeneratedAtUtc: DateTimeOffset.UtcNow,
            Query: query,
            Entries: entries,
            Summary: summary);

        return Task.FromResult(report);
    }

    private static bool Matches(AuditEntry entry, AuditQuery query)
    {
        if (!string.IsNullOrWhiteSpace(query.CorrelationId) &&
            !string.Equals(entry.CorrelationId, query.CorrelationId, StringComparison.Ordinal))
            return false;

        if (query.FromUtc.HasValue && entry.TimestampUtc < query.FromUtc.Value)
            return false;

        if (query.ToUtc.HasValue && entry.TimestampUtc > query.ToUtc.Value)
            return false;

        return true;
    }

    private static IReadOnlyList<string> BuildSummary(IReadOnlyList<AuditEntry> entries)
    {
        var total = entries.Count;
        var actionEvents = entries.Count(e => string.Equals(e.EventType, "ActionResult", StringComparison.OrdinalIgnoreCase));
        var failures = entries.Count(e =>
            string.Equals(e.EventType, "ActionResult", StringComparison.OrdinalIgnoreCase) &&
            e.Data is not null &&
            e.Data.TryGetValue("status", out var status) &&
            string.Equals(status, "Failed", StringComparison.OrdinalIgnoreCase));

        return new[]
        {
            $"Total events: {total}",
            $"Action executions: {actionEvents}",
            $"Failures: {failures}"
        };
    }
}
