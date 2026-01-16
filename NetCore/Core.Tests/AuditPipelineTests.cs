using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Core.Auditing;
using Xunit;

public sealed class AuditPipelineTests
{
    [Fact]
    public async Task BuildReportAsync_FiltersByCorrelationId_AndSummarizes()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "core-audit-pipeline-tests");
        Directory.CreateDirectory(tempDir);
        var path = Path.Combine(tempDir, $"audit-{Guid.NewGuid():N}.jsonl");

        var logger = new JsonlFileAuditLogger(path);
        var correlationId = Guid.NewGuid().ToString("N");
        var otherCorrelationId = Guid.NewGuid().ToString("N");

        logger.Log(BuildEntry(correlationId, "Execution", "ExecutionStart", "start"));
        logger.Log(BuildActionResult(correlationId, "Succeeded"));
        logger.Log(BuildActionResult(correlationId, "Failed"));
        logger.Log(BuildEntry(otherCorrelationId, "Execution", "ExecutionEnd", "end"));

        var pipeline = new JsonlAuditPipeline(path);
        var report = await pipeline.BuildReportAsync(
            new AuditQuery(CorrelationId: correlationId),
            CancellationToken.None);

        Assert.Equal(correlationId, report.Query.CorrelationId);
        Assert.Equal(3, report.Entries.Count);
        Assert.Contains(report.Summary, s => s.Contains("Total events: 3", StringComparison.Ordinal));
        Assert.Contains(report.Summary, s => s.Contains("Action executions: 2", StringComparison.Ordinal));
        Assert.Contains(report.Summary, s => s.Contains("Failures: 1", StringComparison.Ordinal));
    }

    [Fact]
    public async Task BuildReportAsync_FiltersByTimeRange()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "core-audit-pipeline-tests");
        Directory.CreateDirectory(tempDir);
        var path = Path.Combine(tempDir, $"audit-{Guid.NewGuid():N}.jsonl");

        var logger = new JsonlFileAuditLogger(path);
        var correlationId = Guid.NewGuid().ToString("N");

        var early = DateTimeOffset.UtcNow.AddMinutes(-10);
        var late = DateTimeOffset.UtcNow.AddMinutes(-1);

        logger.Log(BuildEntry(correlationId, "Planner", "PlanCreated", "early", early));
        logger.Log(BuildEntry(correlationId, "Execution", "ExecutionStart", "late", late));

        var pipeline = new JsonlAuditPipeline(path);
        var report = await pipeline.BuildReportAsync(
            new AuditQuery(FromUtc: DateTimeOffset.UtcNow.AddMinutes(-5), ToUtc: DateTimeOffset.UtcNow),
            CancellationToken.None);

        Assert.Single(report.Entries);
        Assert.Equal("ExecutionStart", report.Entries[0].EventType);
    }

    private static AuditEntry BuildEntry(
        string correlationId,
        string component,
        string eventType,
        string message,
        DateTimeOffset? timestamp = null)
    {
        return new AuditEntry(
            EntryId: string.Empty,
            TimestampUtc: timestamp ?? DateTimeOffset.UtcNow,
            CorrelationId: correlationId,
            Component: component,
            EventType: eventType,
            Message: message,
            Data: new Dictionary<string, string>());
    }

    private static AuditEntry BuildActionResult(string correlationId, string status)
    {
        return new AuditEntry(
            EntryId: string.Empty,
            TimestampUtc: DateTimeOffset.UtcNow,
            CorrelationId: correlationId,
            Component: "Execution",
            EventType: "ActionResult",
            Message: "action",
            Data: new Dictionary<string, string> { ["status"] = status });
    }
}
