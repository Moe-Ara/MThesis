using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Core.Interfaces;

namespace Core.NormalizationPipeline
{
    /// <summary>
    /// End-to-end normalization pipeline:
    /// RawAlert -> NormalizedAlert -> EnrichedAlert (via enrichment providers).
    ///
    /// Responsibilities:
    /// - Select correct mapper (via registry)
    /// - Map to canonical NormalizedAlert
    /// - Validate normalized alert (fail fast)
    /// - Apply enrichment providers (patch-based)
    /// - Collect provenance notes
    ///
    /// Non-responsibilities:
    /// - ML scoring / inference
    /// - Policy decisions
    /// - Action execution
    /// </summary>
    public sealed class NormalizationPipeline : INormalizationPipeline
    {
        private readonly IMappingRegistry _mappingRegistry;
        private readonly IAlertValidator _validator;
        private readonly IReadOnlyList<IEnrichmentProvider> _enrichers;
        private readonly IEnrichmentMerger _merger;

        private readonly bool _failOnEnrichmentError;

        public NormalizationPipeline(
            IMappingRegistry mappingRegistry,
            IAlertValidator validator,
            IEnumerable<IEnrichmentProvider> enrichers,
            IEnrichmentMerger merger,
            bool failOnEnrichmentError = false)
        {
            _mappingRegistry = mappingRegistry ?? throw new ArgumentNullException(nameof(mappingRegistry));
            _validator = validator ?? throw new ArgumentNullException(nameof(validator));
            _enrichers = (enrichers ?? Enumerable.Empty<IEnrichmentProvider>()).ToList();
            _merger = merger ?? throw new ArgumentNullException(nameof(merger));
            _failOnEnrichmentError = failOnEnrichmentError;
        }

        public NormalizedAlert Normalize(RawAlert raw)
        {
            if (raw is null) throw new ArgumentNullException(nameof(raw));

            var mapper = _mappingRegistry.Resolve(raw);
            if (mapper is null)
                throw new InvalidOperationException("No mapper could be resolved for the provided RawAlert.");

            var normalized = mapper.Map(raw);
            if (normalized is null)
                throw new InvalidOperationException($"Mapper '{mapper.GetType().Name}' returned null NormalizedAlert.");

            var result = _validator.Validate(normalized);
            if (!result.IsValid)
            {
                var msg = $"NormalizedAlert validation failed: {string.Join("; ", result.Errors)}";
                throw new InvalidOperationException(msg);
            }

            return normalized;
        }

        public async Task<EnrichedAlert> ProcessAsync(RawAlert raw, CancellationToken ct = default)
        {
            if (raw is null) throw new ArgumentNullException(nameof(raw));
            ct.ThrowIfCancellationRequested();

            var normalized = Normalize(raw);
            return await EnrichAsync(normalized, ct).ConfigureAwait(false);
        }

        public async Task<EnrichedAlert> EnrichAsync(NormalizedAlert normalized, CancellationToken ct)
        {
            if (normalized is null) throw new ArgumentNullException(nameof(normalized));
            ct.ThrowIfCancellationRequested();

            var ctx = new EnrichmentContext(
                Asset: null,
                Identity: null,
                ThreatIntel: null,
                History: null,
                Tags: new Dictionary<string, string>()
            );

            var provenance = new List<EnrichmentNote>(capacity: Math.Max(4, _enrichers.Count));

            foreach (var enricher in _enrichers)
            {
                ct.ThrowIfCancellationRequested();
                if (enricher is null) continue;

                try
                {
                    var patch = await enricher.EnrichAsync(normalized, ct).ConfigureAwait(false);
                    if (patch is null) continue;

                    ctx = _merger.Apply(ctx, patch);

                    if (patch.Note is not null)
                        provenance.Add(patch.Note);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {

                    provenance.Add(new EnrichmentNote(
                        ProviderName: enricher.Name,
                        TimestampUtc: DateTimeOffset.UtcNow,
                        Summary: $"Enrichment failed: {ex.GetType().Name}: {ex.Message}"
                    ));

                    if (_failOnEnrichmentError)
                        throw;
                }
            }

            return new EnrichedAlert(normalized, ctx, provenance);
        }
    }
}
