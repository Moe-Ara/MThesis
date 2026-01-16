namespace Core.Scoring;

public interface IThreatScorer
{
    ThreatAssessment Score(EnrichedAlert enrichedAlert);
    Explanation Explain(EnrichedAlert enrichedAlert);
}
