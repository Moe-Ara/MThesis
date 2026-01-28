using System;
using System.IO;
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
            var alertId = TryGetString(payload, "id") ?? Guid.NewGuid().ToString("N");
            var timestamp = TryGetDateTime(payload, "timestamp") ?? DateTimeOffset.UtcNow;
            var ruleName = TryGetNestedString(payload, "rule", "description");
            var alertType = TryGetString(payload, "alert_type") ?? TryGetNestedString(payload, "rule", "id");
            var severity = TryGetNestedInt(payload, "rule", "level");

            var raw = new RawAlert
            {
                AlertId = alertId,
                SiemName = siemName,
                TimestampUtc = timestamp,
                RuleName = ruleName,
                AlertType = alertType,
                OriginalSeverity = severity,
                Payload = payload
            };

            await handler(raw).ConfigureAwait(false);

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
}
