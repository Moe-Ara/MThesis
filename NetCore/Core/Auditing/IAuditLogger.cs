namespace Core.Auditing;

public interface IAuditLogger
{
    string Log(AuditEntry entry);
}
