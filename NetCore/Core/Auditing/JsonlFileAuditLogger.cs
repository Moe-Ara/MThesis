using System;
using System.IO;
using System.Text.Json;

namespace Core.Auditing;

public sealed class JsonlFileAuditLogger : IAuditLogger
{
    private readonly string _path;
    private readonly object _lock = new();
    private readonly JsonSerializerOptions _options = new(JsonSerializerDefaults.Web);

    public JsonlFileAuditLogger(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("Path is required.", nameof(path));

        _path = path;
        var dir = Path.GetDirectoryName(_path);
        if (!string.IsNullOrWhiteSpace(dir))
            Directory.CreateDirectory(dir);
    }

    public string Log(AuditEntry entry)
    {
        try
        {
            var normalized = Normalize(entry);
            var json = JsonSerializer.Serialize(normalized, _options);

            lock (_lock)
            {
                File.AppendAllText(_path, json + Environment.NewLine);
            }

            return normalized.EntryId;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Audit log write failed: {ex.Message}");
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
