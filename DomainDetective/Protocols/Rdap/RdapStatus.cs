namespace DomainDetective
{
using System.Text.Json.Serialization;

/// <summary>
/// RDAP status values defined in RFC 9083.
/// </summary>
[JsonConverter(typeof(RdapStatusConverter))]
public enum RdapStatus
{
    /// <summary>Unknown or unmapped status.</summary>
    Unknown,
    /// <summary>The object is active.</summary>
    Active,
    /// <summary>The object is inactive.</summary>
    Inactive,
    /// <summary>The object is locked.</summary>
    Locked,
    /// <summary>Creation is pending.</summary>
    PendingCreate,
    /// <summary>Deletion is pending.</summary>
    PendingDelete,
    /// <summary>Renewal is pending.</summary>
    PendingRenew,
    /// <summary>Transfer is pending.</summary>
    PendingTransfer,
    /// <summary>Update is pending.</summary>
    PendingUpdate,
    /// <summary>Client hold is active.</summary>
    ClientHold,
    /// <summary>Client renewal prohibited.</summary>
    ClientRenewProhibited,
    /// <summary>Client transfer prohibited.</summary>
    ClientTransferProhibited,
    /// <summary>Client update prohibited.</summary>
    ClientUpdateProhibited,
    /// <summary>Client deletion prohibited.</summary>
    ClientDeleteProhibited,
    /// <summary>Server hold is active.</summary>
    ServerHold,
    /// <summary>Server renewal prohibited.</summary>
    ServerRenewProhibited,
    /// <summary>Server transfer prohibited.</summary>
    ServerTransferProhibited,
    /// <summary>Server update prohibited.</summary>
    ServerUpdateProhibited,
    /// <summary>Server deletion prohibited.</summary>
    ServerDeleteProhibited,
    /// <summary>The object has been validated.</summary>
    Validated
}
}
