using System;

namespace Core.Scoring;

public sealed class PythonThreatScorerAdapter : IThreatScorer
{
    private readonly PythonThreatScorerClient _client;

    public PythonThreatScorerAdapter(PythonThreatScorerClient client)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
    }

    public ThreatAssessment Score(EnrichedAlert enrichedAlert)
    {
        if (enrichedAlert is null) throw new ArgumentNullException(nameof(enrichedAlert));
        var evt = new EnrichedEvent(enrichedAlert);
        return _client.Score(evt);
    }

    public Explanation Explain(EnrichedAlert enrichedAlert)
    {
        if (enrichedAlert is null) throw new ArgumentNullException(nameof(enrichedAlert));
        var evt = new EnrichedEvent(enrichedAlert);
        return _client.Explain(evt);
    }
}
