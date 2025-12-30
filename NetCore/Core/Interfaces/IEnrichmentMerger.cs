namespace Core.Interfaces;

public interface IEnrichmentMerger
{
    EnrichmentContext Apply(
        EnrichmentContext current,
        EnrichmentPatch patch);
}