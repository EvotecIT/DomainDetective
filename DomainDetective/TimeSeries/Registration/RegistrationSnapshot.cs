using System;
using System.Collections.Generic;

namespace DomainDetective.TimeSeries.Registration;

/// <summary>Provides registration snapshot functionality.</summary>
public sealed class RegistrationSnapshot
{
    /// <summary>Gets or sets the domain value.</summary>
    public string Domain { get; set; } = string.Empty;
    /// <summary>Gets or sets the captured at utc value.</summary>
    public DateTimeOffset CapturedAtUtc { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Gets or sets the has rdap value.</summary>
    public bool HasRdap { get; set; }
    /// <summary>Gets or sets the has whois value.</summary>
    public bool HasWhois { get; set; }
    /// <summary>Gets or sets the whois server used value.</summary>
    public string? WhoisServerUsed { get; set; }
    /// <summary>Gets or sets the whois lookup source value.</summary>
    public string? WhoisLookupSource { get; set; }

    /// <summary>Gets or sets the registrar value.</summary>
    public string? Registrar { get; set; }
    /// <summary>Gets or sets the registrar id value.</summary>
    public string? RegistrarId { get; set; }

    /// <summary>Gets or sets the created at raw value.</summary>
    public string? CreatedAtRaw { get; set; }
    /// <summary>Gets or sets the created at utc value.</summary>
    public DateTimeOffset? CreatedAtUtc { get; set; }
    /// <summary>Gets or sets the updated at raw value.</summary>
    public string? UpdatedAtRaw { get; set; }
    /// <summary>Gets or sets the updated at utc value.</summary>
    public DateTimeOffset? UpdatedAtUtc { get; set; }
    /// <summary>Gets or sets the expires at raw value.</summary>
    public string? ExpiresAtRaw { get; set; }
    /// <summary>Gets or sets the expires at utc value.</summary>
    public DateTimeOffset? ExpiresAtUtc { get; set; }

    /// <summary>Gets or sets the privacy protected value.</summary>
    public bool? PrivacyProtected { get; set; }
    /// <summary>Gets or sets the registrar locked value.</summary>
    public bool? RegistrarLocked { get; set; }

    /// <summary>Gets or sets the name servers value.</summary>
    public List<string> NameServers { get; set; } = new();
    /// <summary>Gets or sets the status value.</summary>
    public List<string> Status { get; set; } = new();
}

