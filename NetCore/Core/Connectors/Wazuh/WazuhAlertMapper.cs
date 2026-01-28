using System;
using System.Collections.Generic;
using System.Text.Json;
using Core.Interfaces;

namespace Core.Connectors.Wazuh;

public sealed class WazuhAlertMapper : IAlertMapper
{
    public bool CanMap(RawAlert raw)
        => string.Equals(raw.SiemName, "wazuh", StringComparison.OrdinalIgnoreCase);

    public NormalizedAlert Map(RawAlert raw)
    {
        if (raw is null) throw new ArgumentNullException(nameof(raw));

        var payload = raw.Payload;
        var entities = ExtractEntities(payload);
        var severity = NormalizeSeverity(raw.OriginalSeverity, payload);

        return new NormalizedAlert(
            AlertId: raw.AlertId,
            SourceSiem: raw.SiemName,
            TimestampUtc: raw.TimestampUtc,
            AlertType: raw.AlertType,
            RuleName: raw.RuleName,
            Severity: severity,
            Entities: entities,
            RawPayload: payload);
    }

    private static Entities ExtractEntities(JsonElement payload)
    {
        var srcIp = Get(payload, "data.srcip") ??
                    Get(payload, "data.src_ip") ??
                    Get(payload, "srcip") ??
                    Get(payload, "src_ip") ??
                    Get(payload, "agent.ip");

        var dstIp = Get(payload, "data.dstip") ??
                    Get(payload, "data.dst_ip") ??
                    Get(payload, "dstip") ??
                    Get(payload, "dst_ip");

        var hostname = Get(payload, "agent.name") ??
                       Get(payload, "agent.hostname") ??
                       Get(payload, "manager.name") ??
                       Get(payload, "hostname");

        var hostId = Get(payload, "agent.id") ??
                     Get(payload, "agent_id") ??
                     Get(payload, "data.host_id") ??
                     Get(payload, "data.hostId");

        var username = Get(payload, "data.user") ??
                       Get(payload, "data.username") ??
                       Get(payload, "data.srcuser") ??
                       Get(payload, "data.dstuser") ??
                       Get(payload, "data.account") ??
                       Get(payload, "username");

        var userId = Get(payload, "data.user_id") ??
                     Get(payload, "data.userid") ??
                     Get(payload, "user_id");

        var domain = Get(payload, "data.domain") ??
                     Get(payload, "domain");

        var processName = Get(payload, "data.process_name") ??
                          Get(payload, "data.process") ??
                          Get(payload, "data.command") ??
                          Get(payload, "data.image");

        var processPath = Get(payload, "data.process_path") ??
                          Get(payload, "data.path") ??
                          Get(payload, "data.image_path");

        var fileHash = Get(payload, "data.file_hash") ??
                       Get(payload, "data.hash") ??
                       Get(payload, "data.sha256") ??
                       Get(payload, "data.md5") ??
                       Get(payload, "file_hash");

        return new Entities(
            Hostname: hostname,
            HostId: hostId,
            Username: username,
            UserId: userId,
            SrcIp: srcIp,
            DstIp: dstIp,
            Domain: domain,
            ProcessName: processName,
            ProcessPath: processPath,
            FileHash: fileHash
        );
    }

    private static int NormalizeSeverity(int? originalSeverity, JsonElement payload)
    {
        if (originalSeverity.HasValue)
            return Clamp(NormalizeWazuhRuleLevel(originalSeverity.Value));

        var ruleLevel = GetInt(payload, "rule.level");
        if (ruleLevel.HasValue)
            return Clamp(NormalizeWazuhRuleLevel(ruleLevel.Value));

        return 50;
    }

    private static int NormalizeWazuhRuleLevel(int level)
    {
        if (level <= 0)
            return 0;
        if (level <= 15)
            return (int)Math.Round(level * (100.0 / 15.0));
        return Clamp(level);
    }

    private static int Clamp(int value)
        => value < 0 ? 0 : value > 100 ? 100 : value;

    private static string? Get(JsonElement root, string path)
    {
        if (!TryGetPath(root, path, out var value))
            return null;

        return value.ValueKind == JsonValueKind.String ? value.GetString() : value.ToString();
    }

    private static int? GetInt(JsonElement root, string path)
    {
        if (!TryGetPath(root, path, out var value))
            return null;

        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var parsed))
            return parsed;

        if (int.TryParse(value.ToString(), out parsed))
            return parsed;

        return null;
    }

    private static bool TryGetPath(JsonElement root, string path, out JsonElement value)
    {
        value = root;
        var segments = path.Split('.', StringSplitOptions.RemoveEmptyEntries);
        foreach (var segment in segments)
        {
            if (value.ValueKind != JsonValueKind.Object)
                return false;

            if (!TryGetPropertyIgnoreCase(value, segment, out value))
                return false;
        }

        return true;
    }

    private static bool TryGetPropertyIgnoreCase(JsonElement element, string name, out JsonElement value)
    {
        foreach (var prop in element.EnumerateObject())
        {
            if (string.Equals(prop.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                value = prop.Value;
                return true;
            }
        }

        value = default;
        return false;
    }
}
