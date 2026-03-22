using System;
using System.Collections.Generic;

namespace Core;

internal static class ProgramHelpers
{
    public static int GetIntEnv(string key, int fallback)
    {
        var raw = Environment.GetEnvironmentVariable(key);
        return int.TryParse(raw, out var value) ? value : fallback;
    }

    public static bool GetBoolEnv(string key, bool fallback)
    {
        var raw = Environment.GetEnvironmentVariable(key);
        if (string.IsNullOrWhiteSpace(raw))
            return fallback;
        return raw.Trim().Equals("true", StringComparison.OrdinalIgnoreCase)
               || raw.Trim().Equals("1", StringComparison.OrdinalIgnoreCase)
               || raw.Trim().Equals("yes", StringComparison.OrdinalIgnoreCase);
    }

    public static void PrintStartupBanner(
        string mode,
        string? webhookUrl,
        string? intelligenceUrl,
        string? modelProfile,
        int enrichmentProviders,
        bool dryRun,
        string date)
    {
        var wide   = Ansi.C(new string('═', 72), Ansi.Cyan);
        var thin   = Ansi.C(new string('─', 72), Ansi.DimWhite);
        var title  = "SOAR ENGINE  —  Autonomous Threat Response System";
        var sub    = $"Thesis Demo  |  {date}";
        var pad1   = (72 - 2 - title.Length) / 2;
        var pad2   = (72 - 2 - sub.Length) / 2;

        Console.WriteLine();
        Console.WriteLine(wide);
        Console.WriteLine(Ansi.C($"║{new string(' ', pad1)}{title}{new string(' ', 72 - 2 - pad1 - title.Length)}║", Ansi.Cyan));
        Console.WriteLine(Ansi.C($"║{new string(' ', pad2)}{sub}{new string(' ', 72 - 2 - pad2 - sub.Length)}║", Ansi.Cyan));
        Console.WriteLine(wide);
        Console.WriteLine();

        var profile = string.IsNullOrWhiteSpace(modelProfile) ? "default" : modelProfile;
        Console.WriteLine($"  Intelligence    : {Ansi.C(intelligenceUrl ?? "(local)", Ansi.BrightWhite)}  profile={Ansi.C(profile, Ansi.Yellow)}");
        Console.WriteLine($"  Enrichment      : {Ansi.C($"{enrichmentProviders} provider(s) loaded", enrichmentProviders > 0 ? Ansi.Green : Ansi.Yellow)}  (assets, threat_intel, identities)");

        if (!string.IsNullOrWhiteSpace(webhookUrl))
            Console.WriteLine($"  Webhook         : {Ansi.C(webhookUrl, Ansi.BrightWhite)}");

        var dryTag = dryRun ? Ansi.C("DRY-RUN (no real actions)", Ansi.Yellow) : Ansi.C("LIVE", Ansi.BrightRed);
        Console.WriteLine($"  Mode            : {Ansi.C(mode.ToUpper(), Ansi.Bold)}  |  {dryTag}");
        Console.WriteLine();
        Console.WriteLine(thin);
        Console.WriteLine();
    }
}
