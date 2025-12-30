namespace Core.Interfaces;

public interface IEnrichmentProvider
{
    string Name { get; }

    /// <summary>
    /// Returns a partial enrichment patch based on the normalized alert.
    /// Must never mutate the input alert.
    /// </summary>
    Task<EnrichmentPatch> EnrichAsync(
        NormalizedAlert alert,
        CancellationToken ct);
}