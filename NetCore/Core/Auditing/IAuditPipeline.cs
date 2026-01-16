using System.Threading;
using System.Threading.Tasks;

namespace Core.Auditing;

public interface IAuditPipeline
{
    Task<AuditReport> BuildReportAsync(
        AuditQuery query,
        CancellationToken ct);
}
