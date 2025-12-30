namespace Core.Interfaces;

public interface IAlertMapper
{
    /// <summary>
    /// Returns true if this mapper can handle the given raw alert.
    /// </summary>
    bool CanMap(RawAlert raw);

    /// <summary>
    /// Maps a raw SIEM alert into the canonical normalized format.
    /// </summary>
    NormalizedAlert Map(RawAlert raw);
}