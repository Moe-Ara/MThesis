using System.Collections.Generic;
using System.Linq;
using Core.Connectors.Sentinel;
using Core.Connectors.Wazuh;
using Core.Interfaces;

namespace Core.Connectors;

/// <summary>
/// Mapping registry that supports multiple SIEM sources.
/// Routes to the appropriate mapper based on SiemName.
/// Used in webhook mode to handle alerts from Wazuh, Sentinel, and others.
/// </summary>
public sealed class MultiSiemMappingRegistry : IMappingRegistry
{
    private readonly IReadOnlyList<IAlertMapper> _mappers = new IAlertMapper[]
    {
        new WazuhAlertMapper(),
        new SentinelAlertMapper(),
    };

    public IAlertMapper Resolve(RawAlert raw)
        => _mappers.FirstOrDefault(m => m.CanMap(raw))!;
}
