using System;

namespace Core;

public sealed class EnrichedEvent
{
    public EnrichedAlert Alert { get; }

    public EnrichedEvent(EnrichedAlert alert)
    {
        Alert = alert ?? throw new ArgumentNullException(nameof(alert));
    }
}
