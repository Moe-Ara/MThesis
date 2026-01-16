using System;
using System.Collections.Generic;
using System.Data;
using System.Text.Json;
using Core.Policy;
using Microsoft.Data.Sqlite;

namespace Core.CaseManagement;

public sealed class SqliteCaseManager : ICaseManager
{
    private readonly string _connectionString;

    public SqliteCaseManager(string dbPath)
    {
        if (string.IsNullOrWhiteSpace(dbPath))
            throw new ArgumentException("Db path is required.", nameof(dbPath));

        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = dbPath
        }.ToString();

        InitializeSchema();
    }

    public CaseRecord OpenOrUpdate(ThreatAssessment assessment, DecisionPlan plan, PolicyDecision decision)
    {
        if (assessment is null) throw new ArgumentNullException(nameof(assessment));
        if (plan is null) throw new ArgumentNullException(nameof(plan));
        if (decision is null) throw new ArgumentNullException(nameof(decision));

        var now = DateTimeOffset.UtcNow;
        var caseId = ResolveCaseId(plan);
        var summary = $"{plan.Summary} | Approved={decision.Approved.Count}, Pending={decision.PendingApproval.Count}, Denied={decision.Denied.Count}";
        var severity = assessment.Severity.ToString();
        var correlationId = plan.Tags is not null && plan.Tags.TryGetValue("correlation_id", out var c) ? c : null;
        var alertKey = BuildAlertKey(plan);

        using var conn = new SqliteConnection(_connectionString);
        conn.Open();

        using var tx = conn.BeginTransaction();
        if (CaseExists(conn, caseId))
        {
            UpdateCase(conn, caseId, now, summary, severity, correlationId, alertKey, decision);
            AppendEvent(conn, caseId, "CaseUpdated", $"Case updated for plan {plan.PlanId}.", decision);
        }
        else
        {
            InsertCase(conn, caseId, now, summary, severity, correlationId, alertKey);
            AppendEvent(conn, caseId, "CaseCreated", $"Case created for plan {plan.PlanId}.", decision);
        }
        tx.Commit();

        return GetCase(conn, caseId);
    }

    public void AddEvidence(string caseId, EvidenceItem item)
    {
        if (string.IsNullOrWhiteSpace(caseId))
            throw new ArgumentException("CaseId is required.", nameof(caseId));
        if (item is null) throw new ArgumentNullException(nameof(item));

        using var conn = new SqliteConnection(_connectionString);
        conn.Open();

        using var tx = conn.BeginTransaction();
        if (!CaseExists(conn, caseId))
            return;

        AppendEvent(conn, caseId, "EvidenceAdded", item.Description, item);
        UpdateCaseTimestamp(conn, caseId, DateTimeOffset.UtcNow);
        tx.Commit();
    }

    public void Close(string caseId, CaseStatus status)
    {
        if (string.IsNullOrWhiteSpace(caseId))
            throw new ArgumentException("CaseId is required.", nameof(caseId));

        if (status is not (CaseStatus.Closed or CaseStatus.FalsePositive))
            throw new ArgumentException("Close status must be Closed or FalsePositive.", nameof(status));

        using var conn = new SqliteConnection(_connectionString);
        conn.Open();

        using var tx = conn.BeginTransaction();
        if (!CaseExists(conn, caseId))
            return;

        UpdateStatus(conn, caseId, status, DateTimeOffset.UtcNow);
        AppendEvent(conn, caseId, "CaseClosed", $"Case closed as {status}.", new { status = status.ToString() });
        tx.Commit();
    }

    private void InitializeSchema()
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
CREATE TABLE IF NOT EXISTS Cases (
    CaseId TEXT PRIMARY KEY,
    CreatedAtUtc TEXT NOT NULL,
    UpdatedAtUtc TEXT NOT NULL,
    Status TEXT NOT NULL,
    Severity TEXT NOT NULL,
    Summary TEXT NOT NULL,
    CorrelationId TEXT NULL,
    AlertKey TEXT NULL
);
CREATE TABLE IF NOT EXISTS CaseEvents (
    EventId TEXT PRIMARY KEY,
    CaseId TEXT NOT NULL,
    TimestampUtc TEXT NOT NULL,
    Type TEXT NOT NULL,
    Message TEXT NOT NULL,
    DataJson TEXT NULL,
    FOREIGN KEY (CaseId) REFERENCES Cases(CaseId)
);
CREATE INDEX IF NOT EXISTS idx_cases_alertkey ON Cases(AlertKey);
CREATE INDEX IF NOT EXISTS idx_cases_updated ON Cases(UpdatedAtUtc);
CREATE INDEX IF NOT EXISTS idx_cases_correlation ON Cases(CorrelationId);
CREATE INDEX IF NOT EXISTS idx_events_caseid_time ON CaseEvents(CaseId, TimestampUtc);
""";
        cmd.ExecuteNonQuery();
    }

    private static void InsertCase(
        SqliteConnection conn,
        string caseId,
        DateTimeOffset now,
        string summary,
        string severity,
        string? correlationId,
        string? alertKey)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
INSERT INTO Cases (CaseId, CreatedAtUtc, UpdatedAtUtc, Status, Severity, Summary, CorrelationId, AlertKey)
VALUES ($id, $created, $updated, $status, $severity, $summary, $corr, $alertKey);
""";
        cmd.Parameters.AddWithValue("$id", caseId);
        cmd.Parameters.AddWithValue("$created", now.ToString("O"));
        cmd.Parameters.AddWithValue("$updated", now.ToString("O"));
        cmd.Parameters.AddWithValue("$status", CaseStatus.Open.ToString());
        cmd.Parameters.AddWithValue("$severity", severity);
        cmd.Parameters.AddWithValue("$summary", summary);
        cmd.Parameters.AddWithValue("$corr", (object?)correlationId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$alertKey", (object?)alertKey ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    private static void UpdateCase(
        SqliteConnection conn,
        string caseId,
        DateTimeOffset now,
        string summary,
        string severity,
        string? correlationId,
        string? alertKey,
        PolicyDecision decision)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
UPDATE Cases SET UpdatedAtUtc = $updated, Summary = $summary, Severity = $severity, CorrelationId = $corr, AlertKey = $alertKey
WHERE CaseId = $id;
""";
        cmd.Parameters.AddWithValue("$updated", now.ToString("O"));
        cmd.Parameters.AddWithValue("$summary", summary);
        cmd.Parameters.AddWithValue("$severity", severity);
        cmd.Parameters.AddWithValue("$corr", (object?)correlationId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$alertKey", (object?)alertKey ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$id", caseId);
        cmd.ExecuteNonQuery();
    }

    private static void UpdateCaseTimestamp(SqliteConnection conn, string caseId, DateTimeOffset now)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE Cases SET UpdatedAtUtc = $updated WHERE CaseId = $id;";
        cmd.Parameters.AddWithValue("$updated", now.ToString("O"));
        cmd.Parameters.AddWithValue("$id", caseId);
        cmd.ExecuteNonQuery();
    }

    private static void UpdateStatus(SqliteConnection conn, string caseId, CaseStatus status, DateTimeOffset now)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE Cases SET Status = $status, UpdatedAtUtc = $updated WHERE CaseId = $id;";
        cmd.Parameters.AddWithValue("$status", status.ToString());
        cmd.Parameters.AddWithValue("$updated", now.ToString("O"));
        cmd.Parameters.AddWithValue("$id", caseId);
        cmd.ExecuteNonQuery();
    }

    private static bool CaseExists(SqliteConnection conn, string caseId)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT 1 FROM Cases WHERE CaseId = $id LIMIT 1;";
        cmd.Parameters.AddWithValue("$id", caseId);
        using var reader = cmd.ExecuteReader();
        return reader.Read();
    }

    private static void AppendEvent(SqliteConnection conn, string caseId, string type, string message, object data)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
INSERT INTO CaseEvents (EventId, CaseId, TimestampUtc, Type, Message, DataJson)
VALUES ($id, $caseId, $ts, $type, $message, $data);
""";
        cmd.Parameters.AddWithValue("$id", Guid.NewGuid().ToString("N"));
        cmd.Parameters.AddWithValue("$caseId", caseId);
        cmd.Parameters.AddWithValue("$ts", DateTimeOffset.UtcNow.ToString("O"));
        cmd.Parameters.AddWithValue("$type", type);
        cmd.Parameters.AddWithValue("$message", message);
        cmd.Parameters.AddWithValue("$data", JsonSerializer.Serialize(data, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        cmd.ExecuteNonQuery();
    }

    private static string ResolveCaseId(DecisionPlan plan)
        => plan.PlanId;

    private static string? BuildAlertKey(DecisionPlan plan)
    {
        if (plan.Tags is null)
            return null;

        if (!plan.Tags.TryGetValue("siem", out var siem) || !plan.Tags.TryGetValue("alert_id", out var alertId))
            return null;

        return $"{siem}:{alertId}";
    }

    private static CaseRecord GetCase(SqliteConnection conn, string caseId)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT CaseId, CreatedAtUtc, UpdatedAtUtc, Status, Severity, Summary FROM Cases WHERE CaseId = $id;";
        cmd.Parameters.AddWithValue("$id", caseId);
        using var reader = cmd.ExecuteReader(CommandBehavior.SingleRow);
        if (!reader.Read())
        {
            return new CaseRecord(caseId, string.Empty, "unknown", CaseStatus.Open, DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow, Array.Empty<EvidenceItem>());
        }

        var status = Enum.TryParse<CaseStatus>(reader.GetString(3), out var s) ? s : CaseStatus.Open;
        return new CaseRecord(
            CaseId: reader.GetString(0),
            PlanId: string.Empty,
            Summary: reader.GetString(5),
            Status: status,
            CreatedAtUtc: DateTimeOffset.Parse(reader.GetString(1)),
            UpdatedAtUtc: DateTimeOffset.Parse(reader.GetString(2)),
            Evidence: Array.Empty<EvidenceItem>());
    }
}
