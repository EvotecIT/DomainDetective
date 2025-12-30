using System;
using System.Collections.Generic;

namespace DomainDetective.TimeSeries.Registration;

public sealed class RegistrationSnapshot
{
    public string Domain { get; set; } = string.Empty;
    public DateTimeOffset CapturedAtUtc { get; set; } = DateTimeOffset.UtcNow;

    public bool HasRdap { get; set; }
    public bool HasWhois { get; set; }
    public string? WhoisServerUsed { get; set; }
    public string? WhoisLookupSource { get; set; }

    public string? Registrar { get; set; }
    public string? RegistrarId { get; set; }

    public string? CreatedAtRaw { get; set; }
    public DateTimeOffset? CreatedAtUtc { get; set; }
    public string? UpdatedAtRaw { get; set; }
    public DateTimeOffset? UpdatedAtUtc { get; set; }
    public string? ExpiresAtRaw { get; set; }
    public DateTimeOffset? ExpiresAtUtc { get; set; }

    public bool? PrivacyProtected { get; set; }
    public bool? RegistrarLocked { get; set; }

    public List<string> NameServers { get; set; } = new();
    public List<string> Status { get; set; } = new();
}

