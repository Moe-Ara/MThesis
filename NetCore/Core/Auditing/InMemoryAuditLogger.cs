using System;
using System.Collections.Generic;

namespace Core.Auditing;

public sealed class InMemoryAuditLogger : IAuditLogger
{
    private readonly List<AuditEntry> _entries = new();
    private readonly object _lock = new();

    public IReadOnlyList<AuditEntry> Entries
    {
        get
        {
            lock (_lock)
            {
                return _entries.ToArray();
            }
        }
    }

    public string Log(AuditEntry entry)
    {
        try
        {
            var normalized = Normalize(entry);
            lock (_lock)
            {
                _entries.Add(normalized);
            }
            return normalized.EntryId;
        }
        catch
        {
            return string.Empty;
        }
    }

    private static AuditEntry Normalize(AuditEntry entry)
    {
        var id = string.IsNullOrWhiteSpace(entry.EntryId)
            ? Guid.NewGuid().ToString("N")
            : entry.EntryId;

        return entry with { EntryId = id };
    }
}
