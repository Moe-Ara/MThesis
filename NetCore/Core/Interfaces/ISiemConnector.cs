namespace Core.Interfaces;

public interface ISiemConnector
{
    string Name { get; }
    bool IsConnected { get; }

    // Optional metadata: capabilities differ between SIEMs
    SiemConnectorCapabilities Capabilities { get; }

    Task ConnectAsync(CancellationToken ct);
    Task DisconnectAsync(CancellationToken ct);

    // Polling: fetch alerts since a cursor (timestamp, ID, search_after...)
    Task<PullResult<RawAlert>> PullAlertsAsync(
        PullRequest request,
        CancellationToken ct);

    // Ack a specific alert (if SIEM supports it)
    Task AckAsync(string alertId, AckStatus status, CancellationToken ct);

    // Optional subscription support (webhook registration, streaming, etc.)
    Task SubscribeAsync(SubscriptionRequest request, CancellationToken ct);
    Task UnsubscribeAsync(string subscriptionId, CancellationToken ct);

    // Quick check / used by health monitor
    Task<ConnectorHealth> GetHealthAsync(CancellationToken ct);
}