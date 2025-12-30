namespace Core.Interfaces;

public interface IEnrichmentPipeline
{
    Task<EnrichedAlert> RunAsync(
        NormalizedAlert alert,
        CancellationToken ct);
}