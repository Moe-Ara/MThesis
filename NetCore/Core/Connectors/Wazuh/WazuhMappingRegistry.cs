using Core.Interfaces;

namespace Core.Connectors.Wazuh;

public sealed class WazuhMappingRegistry : IMappingRegistry
{
    private readonly IAlertMapper _mapper = new WazuhAlertMapper();

    public IAlertMapper Resolve(RawAlert raw)
        => _mapper.CanMap(raw) ? _mapper : null!;
}
