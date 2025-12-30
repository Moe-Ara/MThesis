namespace Core.Interfaces;

public interface IMappingRegistry
{
    IAlertMapper Resolve(RawAlert raw);
}