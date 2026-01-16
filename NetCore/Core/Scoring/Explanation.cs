using System.Collections.Generic;

namespace Core.Scoring;

public sealed record Explanation(
    string Summary,
    IReadOnlyList<string> Details
);
