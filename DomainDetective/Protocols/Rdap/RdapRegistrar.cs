namespace DomainDetective
{
/// <summary>
/// Represents registrar details extracted from an RDAP entity.
/// </summary>
public sealed class RdapRegistrar
{
    /// <summary>Registrar identifier.</summary>
    public string? Handle { get; set; }

    /// <summary>Registrar display name.</summary>
    public string? Name { get; set; }
}
}
