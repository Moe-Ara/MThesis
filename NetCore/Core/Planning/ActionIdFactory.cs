using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Core.Planning;

/// <summary>
/// Deterministic action identifier generator.
/// </summary>
public static class ActionIdFactory
{
    public static string Create(ActionType type, IReadOnlyDictionary<string, string> parameters)
    {
        var signature = BuildSignature(type, parameters);
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(signature));
        return Convert.ToHexString(hash).ToLowerInvariant()[..16];
    }

    public static string BuildSignature(ActionType type, IReadOnlyDictionary<string, string> parameters)
    {
        var sorted = parameters
            .OrderBy(kv => kv.Key, StringComparer.Ordinal)
            .Select(kv => $"{kv.Key}={kv.Value}");
        return $"{type}:{string.Join("|", sorted)}";
    }
}
