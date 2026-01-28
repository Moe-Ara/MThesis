using System;

namespace Core;

internal static class ProgramHelpers
{
    public static int GetIntEnv(string key, int fallback)
    {
        var raw = Environment.GetEnvironmentVariable(key);
        return int.TryParse(raw, out var value) ? value : fallback;
    }
}
