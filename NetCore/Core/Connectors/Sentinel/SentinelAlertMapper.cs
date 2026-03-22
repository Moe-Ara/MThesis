using System;
using System.Collections.Generic;
using System.Text.Json;
using Core.Interfaces;

namespace Core.Connectors.Sentinel;

/// <summary>
/// Maps Microsoft Sentinel alert/incident webhook payloads to NormalizedAlert.
/// Supports both Sentinel Incident format (with properties nesting) and
/// flat SecurityAlert format (LogAnalytics schema).
/// </summary>
public sealed class SentinelAlertMapper : IAlertMapper
{
    public bool CanMap(RawAlert raw)
        => raw.SiemName.Equals("sentinel", StringComparison.OrdinalIgnoreCase)
           || raw.SiemName.Equals("microsoft-sentinel", StringComparison.OrdinalIgnoreCase)
           || raw.SiemName.Equals("azure-sentinel", StringComparison.OrdinalIgnoreCase);

    public NormalizedAlert Map(RawAlert raw)
    {
        if (raw is null) throw new ArgumentNullException(nameof(raw));

        var payload = raw.Payload;

        // Sentinel incidents wrap fields under "properties"
        var root = payload.ValueKind == JsonValueKind.Object
                   && payload.TryGetProperty("properties", out var props)
            ? props
            : payload;

        var entities = ExtractEntities(root, payload);
        var severity = NormalizeSeverity(root, payload);
        var alertType = MapAlertType(root, payload, raw.RuleName, raw.AlertType);

        return new NormalizedAlert(
            AlertId: raw.AlertId,
            SourceSiem: raw.SiemName,
            TimestampUtc: raw.TimestampUtc,
            AlertType: alertType,
            RuleName: raw.RuleName,
            Severity: severity,
            Entities: entities,
            RawPayload: payload);
    }

    private static Entities ExtractEntities(JsonElement root, JsonElement payload)
    {
        string? srcIp = null, hostname = null, username = null,
                processName = null, fileHash = null, hostId = null;

        // Sentinel structured entities array
        var entitiesEl = TryGet(root, "entities", out var e1) ? e1
                       : TryGet(payload, "entities", out var e2) ? e2
                       : (JsonElement?)null;

        if (entitiesEl.HasValue && entitiesEl.Value.ValueKind == JsonValueKind.Array)
        {
            foreach (var ent in entitiesEl.Value.EnumerateArray())
            {
                var kind = GetString(ent, "kind") ?? "";
                if (!ent.TryGetProperty("properties", out var ep)) continue;

                switch (kind.ToLowerInvariant())
                {
                    case "ip":
                        srcIp ??= GetString(ep, "address");
                        break;
                    case "host":
                        hostname ??= GetString(ep, "hostName") ?? GetString(ep, "netBiosName");
                        hostId ??= GetString(ep, "azureID") ?? GetString(ep, "omsAgentId");
                        break;
                    case "account":
                        username ??= GetString(ep, "accountName");
                        break;
                    case "process":
                        processName ??= GetString(ep, "commandLine") ?? GetString(ep, "imagefile");
                        break;
                    case "filehash":
                        fileHash ??= GetString(ep, "hashValue");
                        break;
                }
            }
        }

        // ExtendedProperties fallback (flat SecurityAlert format)
        var extEl = TryGet(root, "extendedProperties", out var ex1) ? ex1
                  : TryGet(payload, "ExtendedProperties", out var ex2) ? ex2
                  : (JsonElement?)null;

        if (extEl.HasValue && extEl.Value.ValueKind == JsonValueKind.Object)
        {
            srcIp ??= GetString(extEl.Value, "SrcIpAddr") ?? GetString(extEl.Value, "src_ip");
            hostname ??= GetString(extEl.Value, "CompromisedEntity") ?? GetString(extEl.Value, "host");
            username ??= GetString(extEl.Value, "UserName") ?? GetString(extEl.Value, "AccountName");
            processName ??= GetString(extEl.Value, "ProcessName");
            fileHash ??= GetString(extEl.Value, "FileHash") ?? GetString(extEl.Value, "SHA256");
        }

        // Top-level flat fields
        hostname ??= GetString(root, "compromisedEntity") ?? GetString(payload, "CompromisedEntity");

        return new Entities(
            Hostname: hostname,
            HostId: hostId,
            Username: username,
            UserId: null,
            SrcIp: srcIp,
            DstIp: null,
            Domain: null,
            ProcessName: processName,
            ProcessPath: null,
            FileHash: fileHash);
    }

    /// <summary>
    /// Maps Sentinel incident title and MITRE tactics to a recognized alert type.
    /// </summary>
    private static string? MapAlertType(JsonElement root, JsonElement payload, string? ruleName, string? rawAlertType)
    {
        var title = (ruleName ?? GetString(root, "title") ?? GetString(payload, "AlertDisplayName") ?? "").ToLowerInvariant();

        // Collect tactics from additionalData
        var tactics = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (TryGet(root, "additionalData", out var ad) && ad.ValueKind == JsonValueKind.Object)
        {
            if (ad.TryGetProperty("tactics", out var t) && t.ValueKind == JsonValueKind.Array)
                foreach (var tactic in t.EnumerateArray())
                    if (tactic.ValueKind == JsonValueKind.String)
                        tactics.Add(tactic.GetString() ?? "");
        }

        // Brute-force / credential-based attacks
        if (title.Contains("brute force") || title.Contains("credential") || title.Contains("sign-in") ||
            title.Contains("password spray") || title.Contains("failed login") ||
            tactics.Contains("CredentialAccess"))
            return "BruteForceUser";

        // Malware / ransomware
        if (title.Contains("malware") || title.Contains("ransomware") || title.Contains("trojan") ||
            title.Contains("virus") || title.Contains("hash detected") || title.Contains("malicious file"))
            return "MalwareHashOnHost";

        // Suspicious process / execution anomalies
        if (title.Contains("powershell") || title.Contains("encoded command") || title.Contains("suspicious process") ||
            title.Contains("script") || title.Contains("execution") || title.Contains("lateral movement") ||
            tactics.Overlaps(new[] { "Execution", "LateralMovement", "DefenseEvasion" }))
            return "SuspiciousProcessOnHost";

        // Port scan / network scan
        if (title.Contains("port scan") || title.Contains("network scan") || title.Contains("reconnaissance") ||
            tactics.Contains("Reconnaissance") || tactics.Contains("Discovery"))
            return "PortScanFromIp";

        // Phishing
        if (title.Contains("phishing") || title.Contains("email") || title.Contains("spear"))
            return "PhishingEmailReceived";

        return rawAlertType;
    }

    private static int NormalizeSeverity(JsonElement root, JsonElement payload)
    {
        var raw = GetString(root, "severity")
                  ?? GetString(payload, "Severity")
                  ?? GetString(payload, "severity")
                  ?? "";

        return raw.ToLowerInvariant() switch
        {
            "critical" => 95,
            "high" => 80,
            "medium" or "moderate" => 55,
            "low" => 30,
            "informational" or "info" => 15,
            _ => 50
        };
    }

    private static bool TryGet(JsonElement el, string key, out JsonElement value)
    {
        if (el.ValueKind != JsonValueKind.Object)
        {
            value = default;
            return false;
        }
        foreach (var prop in el.EnumerateObject())
        {
            if (string.Equals(prop.Name, key, StringComparison.OrdinalIgnoreCase))
            {
                value = prop.Value;
                return true;
            }
        }
        value = default;
        return false;
    }

    private static string? GetString(JsonElement el, string key)
        => TryGet(el, key, out var val)
            ? (val.ValueKind == JsonValueKind.String ? val.GetString() : val.ToString())
            : null;
}
