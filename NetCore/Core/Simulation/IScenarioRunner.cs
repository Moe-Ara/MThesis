using System.Threading;
using System.Threading.Tasks;

namespace Core.Simulation;

public interface IScenarioRunner
{
    Task<SimulationReport> RunAsync(ThreatGenConfig config, CancellationToken ct = default);
}
