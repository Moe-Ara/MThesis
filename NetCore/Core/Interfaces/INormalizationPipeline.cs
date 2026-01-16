namespace Core.Interfaces;

public interface INormalizationPipeline
{
    NormalizedAlert Normalize(RawAlert raw);
    Task<EnrichedAlert> EnrichAsync(NormalizedAlert alert, CancellationToken ct);
    Task<EnrichedAlert> ProcessAsync(RawAlert raw, CancellationToken ct = default);
}
