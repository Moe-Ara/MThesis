using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

using Core.Auditing;

namespace Core.Demo;

public sealed class JsonDemoTraceWriter : IDemoTraceWriter
{
    private readonly string _latestPath;
    private readonly string? _jsonlPath;
    private readonly bool _onlyOnCompleted;
    private readonly string? _auditPath;
    private readonly int _maxAuditEntries;
    private readonly JsonSerializerOptions _pretty = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };
    private readonly JsonSerializerOptions _line = new(JsonSerializerDefaults.Web);

    public JsonDemoTraceWriter(
        string latestPath,
        string? jsonlPath = null,
        bool onlyOnCompleted = false,
        string? auditPath = null,
        int maxAuditEntries = 50)
    {
        if (string.IsNullOrWhiteSpace(latestPath))
            throw new ArgumentException("latestPath is required.", nameof(latestPath));
        _latestPath = latestPath;
        _jsonlPath = jsonlPath;
        _onlyOnCompleted = onlyOnCompleted;
        _auditPath = auditPath;
        _maxAuditEntries = Math.Max(1, maxAuditEntries);
    }

    public void Write(DemoTrace trace)
    {
        var latestDir = Path.GetDirectoryName(_latestPath);
        if (!string.IsNullOrWhiteSpace(latestDir))
            Directory.CreateDirectory(latestDir);

        var withAudit = trace;
        var auditEntries = LoadAuditEntries(trace);
        if (auditEntries is { Count: > 0 })
            withAudit = trace with { AuditEntries = auditEntries };

        if (!_onlyOnCompleted || string.Equals(trace.Stage, "Completed", StringComparison.OrdinalIgnoreCase))
            File.WriteAllText(_latestPath, JsonSerializer.Serialize(withAudit, _pretty));

        if (!string.IsNullOrWhiteSpace(_jsonlPath))
        {
            var jsonlDir = Path.GetDirectoryName(_jsonlPath);
            if (!string.IsNullOrWhiteSpace(jsonlDir))
                Directory.CreateDirectory(jsonlDir);
            File.AppendAllText(_jsonlPath, JsonSerializer.Serialize(withAudit, _line) + Environment.NewLine);
        }
    }

    private IReadOnlyList<AuditEntry> LoadAuditEntries(DemoTrace trace)
    {
        if (string.IsNullOrWhiteSpace(_auditPath))
            return Array.Empty<AuditEntry>();
        if (!File.Exists(_auditPath))
            return Array.Empty<AuditEntry>();

        var correlationId = trace.Execution?.CorrelationId;
        if (string.IsNullOrWhiteSpace(correlationId))
            correlationId = trace.CorrelationId;

        var lines = File.ReadAllLines(_auditPath);
        if (lines.Length == 0)
            return Array.Empty<AuditEntry>();

        var entries = new List<AuditEntry>();
        for (var i = Math.Max(0, lines.Length - _maxAuditEntries * 5); i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            if (line.Length == 0)
                continue;
            try
            {
                var entry = JsonSerializer.Deserialize<AuditEntry>(line, _line);
                if (entry is null)
                    continue;
                if (!string.IsNullOrWhiteSpace(correlationId) && entry.CorrelationId != correlationId)
                    continue;
                entries.Add(entry);
            }
            catch
            {
                // ignore malformed lines
            }
        }

        if (entries.Count == 0)
            return Array.Empty<AuditEntry>();

        return entries.TakeLast(_maxAuditEntries).ToList();
    }
}
