namespace DomainDetective
{
using System.Text.Json.Serialization;

/// <summary>
/// RDAP event action types.
/// </summary>
[JsonConverter(typeof(RdapEventActionConverter))]
public enum RdapEventAction
{
    /// <summary>Unknown or unsupported action.</summary>
    Unknown,
    /// <summary>The object was registered.</summary>
    Registration,
    /// <summary>The object was re-registered.</summary>
    Reregistration,
    /// <summary>The object was last modified.</summary>
    LastChanged,
    /// <summary>The object expires.</summary>
    Expiration,
    /// <summary>The object was deleted.</summary>
    Deletion,
    /// <summary>The object was reinstated.</summary>
    Reinstantiation,
    /// <summary>The object was transferred.</summary>
    Transfer,
    /// <summary>The object was locked.</summary>
    Locked,
    /// <summary>The object was unlocked.</summary>
    Unlocked,
    /// <summary>Registrar expiration occurred.</summary>
    RegistrarExpiration
}
}
