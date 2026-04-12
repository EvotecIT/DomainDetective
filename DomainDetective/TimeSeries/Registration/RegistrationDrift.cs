using System;
using System.Collections.Generic;

namespace DomainDetective.TimeSeries.Registration;

/// <summary>Provides registration drift functionality.</summary>
public sealed class RegistrationDrift
{
    /// <summary>Gets or sets the domain value.</summary>
    public string Domain { get; set; } = string.Empty;
    /// <summary>Gets or sets the from captured at utc value.</summary>
    public DateTimeOffset FromCapturedAtUtc { get; set; }
    /// <summary>Gets or sets the to captured at utc value.</summary>
    public DateTimeOffset ToCapturedAtUtc { get; set; }

    /// <summary>Gets or sets the changes value.</summary>
    public List<RegistrationChange> Changes { get; set; } = new();
}

/// <summary>Defines values for registration change kind.</summary>
public enum RegistrationChangeKind
{
    /// <summary>Provides registration change functionality.</summary>
    Unknown = 0,
    /// <summary>Provides registration change functionality.</summary>
    RegistrarChanged,
    /// <summary>Provides registration change functionality.</summary>
    RegistrarIdChanged,
    /// <summary>Provides registration change functionality.</summary>
    CreatedAtChanged,
    /// <summary>Provides registration change functionality.</summary>
    UpdatedAtChanged,
    /// <summary>Provides registration change functionality.</summary>
    ExpiresAtChanged,
    /// <summary>Provides registration change functionality.</summary>
    NameServersChanged,
    /// <summary>Provides registration change functionality.</summary>
    StatusChanged,
    /// <summary>Provides registration change functionality.</summary>
    PrivacyProtectedChanged,
    /// <summary>Provides registration change functionality.</summary>
    RegistrarLockedChanged,
    /// <summary>Provides registration change functionality.</summary>
    RdapAvailabilityChanged,
    /// <summary>Provides registration change functionality.</summary>
    WhoisAvailabilityChanged
}

/// <summary>Provides registration change functionality.</summary>
public sealed class RegistrationChange
{
    /// <summary>Gets or sets the kind value.</summary>
    public RegistrationChangeKind Kind { get; set; }
    /// <summary>Gets or sets the before value.</summary>
    public string? Before { get; set; }
    /// <summary>Gets or sets the after value.</summary>
    public string? After { get; set; }
    /// <summary>Gets or sets the added value.</summary>
    public List<string> Added { get; set; } = new();
    /// <summary>Gets or sets the removed value.</summary>
    public List<string> Removed { get; set; } = new();
}

