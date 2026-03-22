using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using Core.NormalizationPipeline;
using Core.Planning;
using Core.Scoring;
using Xunit;

public sealed class HttpPlannerClientTests
{
    [Fact]
    public void Plan_Throws_WhenBaseUrlMissing()
    {
        var options = new HttpPlannerOptions(string.Empty, null);
        var client = new HttpPlannerClient(options, new HttpClient(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK))));

        Assert.Throws<InvalidOperationException>(() => client.Plan(BuildAlert(), BuildAssessment(), BuildContext()));
    }

    [Fact]
    public void Plan_ParsesPlan_And_AttachesRawAndReasoning()
    {
        var json = @"{
  \"plan\": {
    \"planId\": \"plan-1\",
    \"strategy\": \"Contain\",
    \"priority\": 80,
    \"summary\": \"test\",
    \"actions\": [
      {
        \"type\": \"Notify\",
        \"parameters\": {\"channel\": \"secops\"},
        \"risk\": 10,
        \"expectedImpact\": 5,
        \"reversible\": false,
        \"rationale\": \"notify\"
      }
    ],
    \"rollbackActions\": [],
    \"rationale\": [\"reason1\"],
    \"tags\": {\"source\": \"test\"},
    \"reasoning\": {\"why\": \"demo\"}
  }
}";
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var http = new HttpClient(handler);
        var options = new HttpPlannerOptions("http://localhost", null, "/v1/plan");
        var client = new HttpPlannerClient(options, http);

        var plan = client.Plan(BuildAlert(), BuildAssessment(), BuildContext());

        Assert.NotNull(plan);
        Assert.Single(plan!.Actions);
        Assert.Equal(ActionType.Notify, plan.Actions[0].Type);
        Assert.True(plan.Tags!.ContainsKey("planner_raw"));
        Assert.True(plan.Tags.ContainsKey("planner_reasoning"));
    }

    [Fact]
    public void Plan_ReturnsNull_WhenHttpFails()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.InternalServerError));
        var http = new HttpClient(handler);
        var options = new HttpPlannerOptions("http://localhost", null, "/v1/plan");
        var client = new HttpPlannerClient(options, http);

        var plan = client.Plan(BuildAlert(), BuildAssessment(), BuildContext());

        Assert.Null(plan);
    }

    private static EnrichedAlert BuildAlert()
    {
        var raw = System.Text.Json.JsonDocument.Parse("{}").RootElement;
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
            Tags: null);

        return new EnrichedAlert(normalized, context, new List<EnrichmentNote>());
    }

    private static ThreatAssessment BuildAssessment()
        => new(0.7, 60, "hyp", new List<string> { "e" });

    private static PlanningContext BuildContext()
        => new("dev", false, new ActionCatalog(new Dictionary<ActionType, ActionDefinition>()), DateTimeOffset.UtcNow);

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _handler;

        public StubHandler(Func<HttpRequestMessage, HttpResponseMessage> handler)
        {
            _handler = handler;
        }

        protected override System.Threading.Tasks.Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, System.Threading.CancellationToken cancellationToken)
            => System.Threading.Tasks.Task.FromResult(_handler(request));
    }
}
