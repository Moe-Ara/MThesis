namespace Core.Auditing;

public sealed class NullAuditLogger : IAuditLogger
{
    public string Log(AuditEntry entry)
        => string.IsNullOrWhiteSpace(entry.EntryId) ? "null" : entry.EntryId;
}
