using System.Collections.Generic;
using Core.Interfaces;

namespace Core.NormalizationPipeline
{
    public sealed class DefaultEnrichmentMerger : IEnrichmentMerger
    {
        public EnrichmentContext Apply(EnrichmentContext current, EnrichmentPatch patch)
        {
            var mergedTags = MergeTags(current.Tags, patch.Tags);

            return current with
            {
                Asset = patch.Asset ?? current.Asset,
                Identity = patch.Identity ?? current.Identity,
                ThreatIntel = patch.ThreatIntel ?? current.ThreatIntel,
                History = patch.History ?? current.History,
                Tags = mergedTags
            };
        }

        private static IReadOnlyDictionary<string, string>? MergeTags(
            IReadOnlyDictionary<string, string>? a,
            IReadOnlyDictionary<string, string>? b)
        {
            if (a is null && b is null) return null;
            if (a is null) return new Dictionary<string, string>(b!);
            if (b is null) return new Dictionary<string, string>(a);

            var result = new Dictionary<string, string>(a);
            foreach (var kv in b)
                result[kv.Key] = kv.Value;
            return result;
        }
    }
}
