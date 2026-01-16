using System.Collections.Generic;

namespace Core.Simulation;

public interface IThreatGenerator
{
    IReadOnlyList<GeneratedThreat> Generate(ThreatGenConfig config);
}
