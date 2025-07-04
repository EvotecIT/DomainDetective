namespace DomainDetective;

/// <summary>
/// Represents a single DNS tunneling alert.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class DnsTunnelingAlert
{
    /// <summary>Domain observed in the DNS log.</summary>
    public string Domain { get; init; } = string.Empty;
    /// <summary>Reason the query was flagged.</summary>
    public string Reason { get; init; } = string.Empty;
}
