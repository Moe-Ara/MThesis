using System;
using System.Collections.Generic;
using System.Text.Json;

namespace Core.Simulation;

public static class ScenarioTemplates
{
    public const string PortScanFromIp = "PortScanFromIp";
    public const string BruteForceUser = "BruteForceUser";
    public const string MalwareHashOnHost = "MalwareHashOnHost";
    public const string SuspiciousProcessOnHost = "SuspiciousProcessOnHost";
    public const string BenignNoise = "BenignNoise";
    public const string EdgeMissingParams = "EdgeMissingParams";
    public const string EdgeMalformedAlert = "EdgeMalformedAlert";

    public static GeneratedThreat Create(string scenarioType, Random rng)
    {
        var scenarioId = Guid.NewGuid().ToString("N");
        return scenarioType switch
        {
            PortScanFromIp => BuildPortScan(scenarioId, rng),
            BruteForceUser => BuildBruteForce(scenarioId, rng),
            MalwareHashOnHost => BuildMalwareHash(scenarioId, rng),
            SuspiciousProcessOnHost => BuildSuspiciousProcess(scenarioId, rng),
            BenignNoise => BuildBenignNoise(scenarioId, rng),
            EdgeMissingParams => BuildEdgeMissingParams(scenarioId, rng),
            EdgeMalformedAlert => BuildEdgeMalformedAlert(scenarioId),
            _ => BuildBenignNoise(scenarioId, rng)
        };
    }

    private static GeneratedThreat BuildPortScan(string id, Random rng)
    {
        var srcIp = $"10.0.{rng.Next(1, 255)}.{rng.Next(1, 255)}";
        var payload = new Dictionary<string, object?>
        {
            ["src_ip"] = srcIp,
            ["dst_port_start"] = 20,
            ["dst_port_end"] = 1024,
            ["attempts"] = rng.Next(50, 200)
        };

        return BuildThreat(id, PortScanFromIp, "malicious", payload, expected: new Dictionary<string, string>
        {
            ["scenario_type"] = PortScanFromIp
        });
    }

    private static GeneratedThreat BuildBruteForce(string id, Random rng)
    {
        var username = $"user{rng.Next(1, 50)}";
        var payload = new Dictionary<string, object?>
        {
            ["username"] = username,
            ["user_id"] = $"u-{rng.Next(1000, 9999)}",
            ["src_ip"] = $"172.16.{rng.Next(1, 255)}.{rng.Next(1, 255)}",
            ["failed_logins"] = rng.Next(10, 80)
        };

        return BuildThreat(id, BruteForceUser, "malicious", payload, expected: new Dictionary<string, string>
        {
            ["scenario_type"] = BruteForceUser
        });
    }

    private static GeneratedThreat BuildMalwareHash(string id, Random rng)
    {
        var payload = new Dictionary<string, object?>
        {
            ["host_id"] = $"host-{rng.Next(100, 999)}",
            ["file_hash"] = Guid.NewGuid().ToString("N"),
            ["file_path"] = @"C:\temp\evil.exe"
        };

        return BuildThreat(id, MalwareHashOnHost, "malicious", payload, expected: new Dictionary<string, string>
        {
            ["scenario_type"] = MalwareHashOnHost
        });
    }

    private static GeneratedThreat BuildSuspiciousProcess(string id, Random rng)
    {
        var payload = new Dictionary<string, object?>
        {
            ["host_id"] = $"host-{rng.Next(100, 999)}",
            ["process_name"] = "powershell.exe",
            ["pid"] = rng.Next(1000, 9999)
        };

        return BuildThreat(id, SuspiciousProcessOnHost, "malicious", payload, expected: new Dictionary<string, string>
        {
            ["scenario_type"] = SuspiciousProcessOnHost
        });
    }

    private static GeneratedThreat BuildBenignNoise(string id, Random rng)
    {
        var payload = new Dictionary<string, object?>
        {
            ["src_ip"] = $"192.168.{rng.Next(1, 255)}.{rng.Next(1, 255)}",
            ["attempts"] = rng.Next(1, 3)
        };

        return BuildThreat(id, BenignNoise, "benign", payload, expected: new Dictionary<string, string>
        {
            ["scenario_type"] = BenignNoise
        });
    }

    private static GeneratedThreat BuildEdgeMissingParams(string id, Random rng)
    {
        var payload = new Dictionary<string, object?>
        {
            ["host_id"] = $"host-{rng.Next(100, 999)}"
        };

        return BuildThreat(id, EdgeMissingParams, "malicious", payload, expected: new Dictionary<string, string>
        {
            ["scenario_type"] = EdgeMissingParams
        });
    }

    private static GeneratedThreat BuildEdgeMalformedAlert(string id)
    {
        var payload = new Dictionary<string, object?>
        {
            ["note"] = "missing entities"
        };

        return BuildThreat(id, EdgeMalformedAlert, "benign", payload, expected: new Dictionary<string, string>
        {
            ["scenario_type"] = EdgeMalformedAlert
        });
    }

    private static GeneratedThreat BuildThreat(
        string id,
        string type,
        string groundTruth,
        Dictionary<string, object?> payload,
        Dictionary<string, string> expected)
    {
        var raw = new RawAlert
        {
            AlertId = id,
            SiemName = "simulator",
            TimestampUtc = DateTimeOffset.UtcNow,
            AlertType = type,
            RuleName = type,
            OriginalSeverity = null,
            Payload = JsonSerializer.SerializeToElement(payload)
        };

        return new GeneratedThreat(id, type, raw, groundTruth, expected);
    }
}
