using System;
using System.Collections.Generic;
using System.Text.Json;
using Core.Interfaces;

namespace Core.Simulation;

public sealed class SimulationAlertMapper : IAlertMapper
{
    public bool CanMap(RawAlert raw)
        => raw.SiemName == "simulator";

    public NormalizedAlert Map(RawAlert raw)
    {
        if (raw is null) throw new ArgumentNullException(nameof(raw));

        var entities = ExtractEntities(raw.Payload);

        return new NormalizedAlert(
            AlertId: raw.AlertId,
            SourceSiem: raw.SiemName,
            TimestampUtc: raw.TimestampUtc,
            AlertType: raw.AlertType,
            RuleName: raw.RuleName,
            Severity: raw.OriginalSeverity ?? 50,
            Entities: entities,
            RawPayload: raw.Payload);
    }

    private static Entities ExtractEntities(JsonElement payload)
    {
        var dict = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        if (payload.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in payload.EnumerateObject())
                dict[prop.Name] = prop.Value.ValueKind == JsonValueKind.String
                    ? prop.Value.GetString()
                    : prop.Value.ToString();
        }

        return new Entities(
            Hostname: Get(dict, "hostname"),
            HostId: Get(dict, "host_id"),
            Username: Get(dict, "username"),
            UserId: Get(dict, "user_id"),
            SrcIp: Get(dict, "src_ip"),
            DstIp: Get(dict, "dst_ip"),
            Domain: Get(dict, "domain"),
            ProcessName: Get(dict, "process_name"),
            ProcessPath: Get(dict, "process_path"),
            FileHash: Get(dict, "file_hash")
        );
    }

    private static string? Get(IReadOnlyDictionary<string, string?> dict, string key)
        => dict.TryGetValue(key, out var value) ? value : null;
}
