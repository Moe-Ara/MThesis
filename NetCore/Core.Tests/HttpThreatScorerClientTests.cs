using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Core.NormalizationPipeline;
using Core.Scoring;
using Xunit;

public sealed class HttpThreatScorerClientTests
{
    [Fact]
    public void Score_Fallbacks_OnHttpFailure()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.InternalServerError));
        var http = new HttpClient(handler);
        var options = new ThreatScorerApiOptions("http://localhost", "", 5, "test");
        var client = new HttpThreatScorerClient(options, http);

        var assessment = client.Score(BuildAlert());

        Assert.Equal(0.3, assessment.Confidence);
        Assert.Equal(30, assessment.Severity);
    }

    [Fact]
    public void Score_UsesCorrelationId_FromTags()
    {
        var handler = new StubHandler(request =>
        {
            var payload = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
            handler.LastBody = payload;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"severity\":50,\"confidence\":0.7}", Encoding.UTF8, "application/json")
            };
        });
        var http = new HttpClient(handler);
        var options = new ThreatScorerApiOptions("http://localhost", "", 5, "test");
        var client = new HttpThreatScorerClient(options, http);

        var alert = BuildAlert(tags: new Dictionary<string, string> { ["correlation_id"] = "corr-123" });
        client.Score(alert);

        using var doc = JsonDocument.Parse(handler.LastBody ?? "{}");
        var correlationId = doc.RootElement.GetProperty("correlationId").GetString();
        Assert.Equal("corr-123", correlationId);
    }

    [Fact]
    public void Score_Respects_BaseUrl_EnvOverride()
    {
        var previous = Environment.GetEnvironmentVariable("THREAT_SCORER_BASEURL");
        Environment.SetEnvironmentVariable("THREAT_SCORER_BASEURL", "http://override");
        try
        {
            var handler = new StubHandler(request =>
            {
                handler.LastUrl = request.RequestUri!.ToString();
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{\"severity\":50,\"confidence\":0.7}", Encoding.UTF8, "application/json")
                };
            });
            var http = new HttpClient(handler);
            var options = new ThreatScorerApiOptions("http://localhost", "", 5, "test");
            var client = new HttpThreatScorerClient(options, http);

            client.Score(BuildAlert());

            Assert.StartsWith("http://override", handler.LastUrl, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Environment.SetEnvironmentVariable("THREAT_SCORER_BASEURL", previous);
        }
    }

    private static EnrichedAlert BuildAlert(IReadOnlyDictionary<string, string>? tags = null)
    {
        var raw = JsonDocument.Parse("{}").RootElement;
        var normalized = new NormalizedAlert(
            AlertId: "a1",
            SourceSiem: "demo",
            TimestampUtc: DateTimeOffset.UtcNow,
            AlertType: "test",
            RuleName: "rule",
            Severity: 50,
            Entities: new Entities("host", "host-1", "user", "u1", "10.0.0.5", null, null, null, null, null),
            RawPayload: raw);

        var context = new EnrichmentContext(
            Asset: new AssetContext("asset-1", 3, "prod"),
            Identity: new IdentityContext("user-1", true),
            ThreatIntel: new ThreatIntelContext(10),
            History: null,
            Tags: tags);

        return new EnrichedAlert(normalized, context, new List<EnrichmentNote>());
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _handler;
        public string? LastBody { get; set; }
        public string? LastUrl { get; set; }

        public StubHandler(Func<HttpRequestMessage, HttpResponseMessage> handler)
        {
            _handler = handler;
        }

        protected override System.Threading.Tasks.Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, System.Threading.CancellationToken cancellationToken)
            => System.Threading.Tasks.Task.FromResult(_handler(request));
    }
}
