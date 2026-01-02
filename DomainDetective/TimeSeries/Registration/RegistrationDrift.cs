using System;
using System.Collections.Generic;

namespace DomainDetective.TimeSeries.Registration;

public sealed class RegistrationDrift
{
    public string Domain { get; set; } = string.Empty;
    public DateTimeOffset FromCapturedAtUtc { get; set; }
    public DateTimeOffset ToCapturedAtUtc { get; set; }

    public List<RegistrationChange> Changes { get; set; } = new();
}

public enum RegistrationChangeKind
{
    Unknown = 0,
    RegistrarChanged,
    RegistrarIdChanged,
    CreatedAtChanged,
    UpdatedAtChanged,
    ExpiresAtChanged,
    NameServersChanged,
    StatusChanged,
    PrivacyProtectedChanged,
    RegistrarLockedChanged,
    RdapAvailabilityChanged,
    WhoisAvailabilityChanged
}

public sealed class RegistrationChange
{
    public RegistrationChangeKind Kind { get; set; }
    public string? Before { get; set; }
    public string? After { get; set; }
    public List<string> Added { get; set; } = new();
    public List<string> Removed { get; set; } = new();
}

