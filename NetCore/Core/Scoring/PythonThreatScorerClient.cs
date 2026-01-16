using System;
using System.Collections.Generic;

namespace Core.Scoring;

/// <summary>
/// Stub client for a Python-based threat scoring module.
/// </summary>
public sealed class PythonThreatScorerClient
{
    public ThreatAssessment Score(EnrichedEvent enrichedEvent)
    {
        if (enrichedEvent is null) throw new ArgumentNullException(nameof(enrichedEvent));

        return new ThreatAssessment(
            Confidence: 0.0,
            Severity: 0,
            Hypothesis: "No scoring available (stub).",
            Evidence: new List<string>()
        );
    }

    public Explanation Explain(EnrichedEvent enrichedEvent)
    {
        if (enrichedEvent is null) throw new ArgumentNullException(nameof(enrichedEvent));

        return new Explanation(
            Summary: "No explanation available (stub).",
            Details: Array.Empty<string>()
        );
    }
}
