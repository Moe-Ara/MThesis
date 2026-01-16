using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Core.Interfaces;
using Core.NormalizationPipeline;
using Xunit;

public sealed class NormalizationPipelineTests
{
    [Fact]
    public void Normalize_ValidAlert_ReturnsNormalized()
    {
        var mapper = new StubMapper(canMap: true);
        var registry = new StubRegistry(mapper);
        var pipeline = new NormalizationPipeline(
            registry,
            new BasicAlertValidator(),
            Array.Empty<IEnrichmentProvider>(),
            new DefaultEnrichmentMerger());

        var normalized = pipeline.Normalize(StubRawAlert());

        Assert.Equal("a1", normalized.AlertId);
        Assert.Equal("siem", normalized.SourceSiem);
    }

    [Fact]
    public void Normalize_InvalidAlert_Throws()
    {
        var mapper = new StubMapper(canMap: true, includeEntities: false);
        var registry = new StubRegistry(mapper);
        var pipeline = new NormalizationPipeline(
            registry,
            new BasicAlertValidator(),
            Array.Empty<IEnrichmentProvider>(),
            new DefaultEnrichmentMerger());

        var ex = Assert.Throws<InvalidOperationException>(() => pipeline.Normalize(StubRawAlert()));
        Assert.Contains("validation failed", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task EnrichAsync_MergesPatch()
    {
        var mapper = new StubMapper(canMap: true);
        var registry = new StubRegistry(mapper);
        var enrichers = new IEnrichmentProvider[] { new StubEnricher() };
        var pipeline = new NormalizationPipeline(
            registry,
            new BasicAlertValidator(),
            enrichers,
            new DefaultEnrichmentMerger());

        var normalized = pipeline.Normalize(StubRawAlert());
        var enriched = await pipeline.EnrichAsync(normalized, CancellationToken.None);

        Assert.NotNull(enriched.Context.Asset);
        Assert.Equal(3, enriched.Context.Asset!.Criticality);
        Assert.NotNull(enriched.Context.Tags);
        Assert.Equal("lab", enriched.Context.Tags!["environment"]);
    }

    private static RawAlert StubRawAlert()
        => new()
        {
            AlertId = "a1",
            SiemName = "siem",
            TimestampUtc = DateTimeOffset.UtcNow,
            Payload = default
        };

    private sealed class StubMapper : IAlertMapper
    {
        private readonly bool _canMap;
        private readonly bool _includeEntities;

        public StubMapper(bool canMap, bool includeEntities = true)
        {
            _canMap = canMap;
            _includeEntities = includeEntities;
        }

        public bool CanMap(RawAlert raw) => _canMap;

        public NormalizedAlert Map(RawAlert raw)
        {
            var entities = _includeEntities
                ? new Entities("host", null, null, null, "1.2.3.4", null, null, null, null, null)
                : new Entities(null, null, null, null, null, null, null, null, null, null);

            return new NormalizedAlert(
                raw.AlertId,
                raw.SiemName,
                raw.TimestampUtc,
                "type",
                "rule",
                50,
                entities,
                raw.Payload);
        }
    }

    private sealed class StubRegistry : IMappingRegistry
    {
        private readonly IAlertMapper _mapper;

        public StubRegistry(IAlertMapper mapper) => _mapper = mapper;

        public IAlertMapper Resolve(RawAlert raw)
            => _mapper.CanMap(raw) ? _mapper : null!;
    }

    private sealed class StubEnricher : IEnrichmentProvider
    {
        public string Name => "stub";

        public Task<EnrichmentPatch> EnrichAsync(NormalizedAlert alert, CancellationToken ct)
        {
            var patch = new EnrichmentPatch(
                Asset: new AssetContext("asset-1", 3),
                Tags: new Dictionary<string, string> { ["environment"] = "lab" },
                Note: new EnrichmentNote("stub", DateTimeOffset.UtcNow, "ok"));

            return Task.FromResult(patch);
        }
    }
}
