using System;
using System.IO;

namespace Core;

/// <summary>
/// Loads key=value pairs from a .env file into the current process environment.
/// Existing environment variables are NOT overwritten.
/// </summary>
internal static class EnvFileLoader
{
    public static void Load(string? path = null)
    {
        path ??= FindEnvFile();
        if (path is null || !File.Exists(path))
            return;

        foreach (var line in File.ReadAllLines(path))
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed.StartsWith('#'))
                continue;

            var eqIndex = trimmed.IndexOf('=');
            if (eqIndex <= 0)
                continue;

            var key = trimmed[..eqIndex].Trim();
            var value = trimmed[(eqIndex + 1)..].Trim();

            // Don't overwrite existing env vars (explicit env takes precedence)
            if (Environment.GetEnvironmentVariable(key) is null)
                Environment.SetEnvironmentVariable(key, value);
        }
    }

    private static string? FindEnvFile()
    {
        // Walk up from the current directory looking for .env
        var dir = Directory.GetCurrentDirectory();
        for (var i = 0; i < 5; i++)
        {
            var candidate = Path.Combine(dir, ".env");
            if (File.Exists(candidate))
                return candidate;

            var parent = Directory.GetParent(dir);
            if (parent is null) break;
            dir = parent.FullName;
        }

        return null;
    }
}
