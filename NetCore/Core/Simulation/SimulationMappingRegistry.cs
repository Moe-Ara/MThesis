using Core.Interfaces;

namespace Core.Simulation;

public sealed class SimulationMappingRegistry : IMappingRegistry
{
    private readonly IAlertMapper _mapper = new SimulationAlertMapper();

    public IAlertMapper Resolve(RawAlert raw)
        => _mapper.CanMap(raw) ? _mapper : null!;
}
