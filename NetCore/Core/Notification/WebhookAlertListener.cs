using System;
using System.IO;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Core.Notification;

public sealed class WebhookAlertListener
{
    private readonly string _prefix;

    public WebhookAlertListener(string prefix)
    {
        if (string.IsNullOrWhiteSpace(prefix))
            throw new ArgumentException("Prefix is required.", nameof(prefix));
        _prefix = prefix.EndsWith("/", StringComparison.Ordinal) ? prefix : prefix + "/";
    }

    public async Task RunAsync(Func<RawAlert, Task> handler, CancellationToken ct)
    {
        if (handler is null) throw new ArgumentNullException(nameof(handler));

        using var listener = new HttpListener();
        listener.Prefixes.Add(_prefix);
        listener.Start();

        try
        {
            while (!ct.IsCancellationRequested)
            {
                var contextTask = listener.GetContextAsync();
                var completed = await Task.WhenAny(contextTask, Task.Delay(Timeout.Infinite, ct))
                    .ConfigureAwait(false);
                if (completed != contextTask)
                    break;

                var context = await contextTask.ConfigureAwait(false);
                _ = Task.Run(() => HandleRequestAsync(context, handler, ct), ct);
            }
        }
        finally
        {
            listener.Stop();
        }
    }

    private static async Task HandleRequestAsync(HttpListenerContext context, Func<RawAlert, Task> handler, CancellationToken ct)
    {
        try
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                context.Response.StatusCode = (int)HttpStatusCode.MethodNotAllowed;
                context.Response.Close();
                return;
            }

            string body;
            using (var reader = new StreamReader(context.Request.InputStream, context.Request.ContentEncoding ?? Encoding.UTF8))
            {
                body = await reader.ReadToEndAsync().ConfigureAwait(false);
            }

            if (string.IsNullOrWhiteSpace(body))
            {
                context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                context.Response.Close();
                return;
            }

            JsonElement payload;
            try
            {
                payload = JsonSerializer.Deserialize<JsonElement>(body);
            }
            catch (JsonException)
            {
                context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                context.Response.Close();
                return;
            }

            var siemName = context.Request.Headers["X-Siem-Name"] ?? "wazuh";
            var alerts = ExtractAlertElements(payload);
            var any = false;

            foreach (var alert in alerts)
            {
                var raw = BuildRawAlert(alert, siemName);
                await handler(raw).ConfigureAwait(false);
                any = true;
            }

            if (!any)
            {
                context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                context.Response.Close();
                return;
            }

            context.Response.StatusCode = (int)HttpStatusCode.OK;
            context.Response.Close();
        }
        catch
        {
            try
            {
                context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                context.Response.Close();
            }
            catch
            {
                // ignore
            }
        }
    }

    private static string? TryGetString(JsonElement element, string property)
    {
        if (element.ValueKind != JsonValueKind.Object)
            return null;
        if (!element.TryGetProperty(property, out var value))
            return null;
        return value.ValueKind == JsonValueKind.String ? value.GetString() : value.ToString();
    }

    private static string? TryGetNestedString(JsonElement element, string parent, string property)
    {
        if (element.ValueKind != JsonValueKind.Object)
            return null;
        if (!element.TryGetProperty(parent, out var obj))
            return null;
        return TryGetString(obj, property);
    }

    private static int? TryGetNestedInt(JsonElement element, string parent, string property)
    {
        if (element.ValueKind != JsonValueKind.Object)
            return null;
        if (!element.TryGetProperty(parent, out var obj))
            return null;
        if (!obj.TryGetProperty(property, out var value))
            return null;
        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var parsed))
            return parsed;
        if (int.TryParse(value.ToString(), out parsed))
            return parsed;
        return null;
    }

    private static DateTimeOffset? TryGetDateTime(JsonElement element, string property)
    {
        var raw = TryGetString(element, property);
        if (string.IsNullOrWhiteSpace(raw))
            return null;
        if (DateTimeOffset.TryParse(raw, out var parsed))
            return parsed;
        return null;
    }

    private static IEnumerable<JsonElement> ExtractAlertElements(JsonElement payload)
    {
        if (payload.ValueKind == JsonValueKind.Array)
            return payload.EnumerateArray();

        if (payload.ValueKind != JsonValueKind.Object)
            return Array.Empty<JsonElement>();

        if (payload.TryGetProperty("data", out var data))
        {
            if (data.ValueKind == JsonValueKind.Object)
            {
                if (data.TryGetProperty("alert", out var alert))
                    return ExtractAlertElements(alert);

                if (data.TryGetProperty("alerts", out var alerts))
                    return ExtractAlertElements(alerts);

                if (data.TryGetProperty("affected_items", out var affected) &&
                    affected.ValueKind == JsonValueKind.Array)
                {
                    return affected.EnumerateArray();
                }

                if (data.TryGetProperty("items", out var items) &&
                    items.ValueKind == JsonValueKind.Array)
                {
                    return items.EnumerateArray();
                }
            }

            if (data.ValueKind == JsonValueKind.Array)
                return data.EnumerateArray();
        }

        if (payload.TryGetProperty("alert", out var singleAlert))
            return ExtractAlertElements(singleAlert);

        if (payload.TryGetProperty("alerts", out var alertArray))
            return ExtractAlertElements(alertArray);

        if (payload.TryGetProperty("events", out var eventsArray))
            return ExtractAlertElements(eventsArray);

        return new[] { payload };
    }

    private static RawAlert BuildRawAlert(JsonElement element, string siemName)
    {
        var alertId = TryGetString(element, "id")
                      ?? TryGetString(element, "_id")
                      ?? TryGetString(element, "alert_id")
                      ?? Guid.NewGuid().ToString("N");

        var timestamp = TryGetDateTime(element, "timestamp")
                        ?? TryGetDateTime(element, "@timestamp")
                        ?? DateTimeOffset.UtcNow;

        var ruleName = TryGetNestedString(element, "rule", "description")
                       ?? TryGetNestedString(element, "rule", "name")
                       // Sentinel incident: properties.title
                       ?? TryGetNestedString(element, "properties", "title")
                       // Sentinel flat: AlertDisplayName
                       ?? TryGetString(element, "AlertDisplayName")
                       ?? TryGetString(element, "title");

        var ruleId = TryGetNestedString(element, "rule", "id")
                     // Sentinel: incidentNumber or name
                     ?? TryGetNestedString(element, "properties", "incidentNumber")
                     ?? TryGetString(element, "AlertType");
        var alertType = TryGetString(element, "alert_type")
                        ?? ruleId
                        ?? TryGetString(element, "name");

        // Wazuh uses rule.level (0-15); Sentinel uses properties.severity string
        var severity = TryGetNestedInt(element, "rule", "level");
        if (!severity.HasValue)
        {
            var sentinelSev = TryGetNestedString(element, "properties", "severity")
                              ?? TryGetString(element, "Severity");
            severity = sentinelSev?.ToLowerInvariant() switch
            {
                "critical" => 15,
                "high" => 12,
                "medium" or "moderate" => 8,
                "low" => 5,
                "informational" or "info" => 2,
                _ => null
            };
        }

        return new RawAlert
        {
            AlertId = alertId,
            SiemName = siemName,
            TimestampUtc = timestamp,
            RuleName = ruleName,
            AlertType = alertType,
            OriginalSeverity = severity,
            Payload = element.Clone()
        };
    }
}
