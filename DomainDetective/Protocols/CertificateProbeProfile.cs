using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace DomainDetective;

/// <summary>Protocol negotiation required before collecting a certificate.</summary>
[System.Text.Json.Serialization.JsonConverter(typeof(CertificateProbeTransportJsonConverter))]
public enum CertificateProbeTransport {
    /// <summary>TLS starts immediately, including HTTPS and LDAPS.</summary>
    DirectTls,
    /// <summary>SMTP greeting, EHLO and STARTTLS precede TLS.</summary>
    SmtpStartTls,
    /// <summary>FTP greeting and AUTH TLS precede TLS.</summary>
    FtpExplicitTls,
    /// <summary>FTP over an immediate TLS connection.</summary>
    FtpImplicitTls
}

/// <summary>A portable protocol profile; a port alone never selects STARTTLS behavior.</summary>
public sealed class CertificateProbeProfile {
    /// <summary>Stable deployment profile identifier.</summary>
    public string Id { get; set; } = string.Empty;
    /// <summary>Whether the deployment schedules this profile.</summary>
    public bool Enabled { get; set; } = true;
    /// <summary>Logical endpoint service, such as https, smtp, ftp or ldaps.</summary>
    public string Service { get; set; } = "tls";
    /// <summary>TCP port.</summary>
    public int Port { get; set; } = 443;
    /// <summary>Protocol negotiation mode.</summary>
    public CertificateProbeTransport Transport { get; set; }
    /// <summary>Collection location label persisted independently of endpoint identity.</summary>
    public string Vantage { get; set; } = "default";

    /// <summary>Checks a profile before scheduling or opening a socket.</summary>
    public void Validate() {
        if (!Regex.IsMatch(Id ?? string.Empty, "^[a-z][a-z0-9-]{0,79}$", RegexOptions.CultureInvariant)) throw new ArgumentException("A profile needs a stable lower-case id.");
        if (Port < 1 || Port > 65535) throw new ArgumentOutOfRangeException(nameof(Port));
        if (!Enum.IsDefined(typeof(CertificateProbeTransport), Transport)) throw new ArgumentOutOfRangeException(nameof(Transport));
        if (string.IsNullOrWhiteSpace(Service) || string.IsNullOrWhiteSpace(Vantage)) throw new ArgumentException("Profile service and vantage are required.");
        if (Transport == CertificateProbeTransport.SmtpStartTls && Port == 465) throw new ArgumentException("SMTP port 465 uses implicit TLS; select DirectTls.");
    }

    /// <summary>Returns fresh standard profiles; only the 443 baseline is enabled by default.</summary>
    public static IReadOnlyList<CertificateProbeProfile> StandardProfiles() => new[] {
        Create("https-443", 443, "tls", CertificateProbeTransport.DirectTls, true),
        Create("tls-8443", 8443, "tls", CertificateProbeTransport.DirectTls),
        Create("smtp-starttls-25", 25, "smtp", CertificateProbeTransport.SmtpStartTls),
        Create("ftp-explicit-21", 21, "ftp", CertificateProbeTransport.FtpExplicitTls),
        Create("ftps-implicit-990", 990, "ftp", CertificateProbeTransport.FtpImplicitTls),
        Create("ldaps-636", 636, "ldaps", CertificateProbeTransport.DirectTls)
    };

    /// <summary>Validates uniqueness and returns independent enabled scheduling snapshots.</summary>
    public static IReadOnlyList<CertificateProbeProfile> Resolve(IEnumerable<CertificateProbeProfile> profiles) {
        if (profiles == null) throw new ArgumentNullException(nameof(profiles));
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var result = new List<CertificateProbeProfile>();
        foreach (CertificateProbeProfile profile in profiles) {
            if (profile == null) throw new ArgumentException("A profile cannot be null.");
            profile.Validate();
            if (!ids.Add(profile.Id)) throw new ArgumentException("Profile ids must be unique.");
            if (profile.Enabled) result.Add(new() { Id = profile.Id, Port = profile.Port, Service = profile.Service.Trim().ToLowerInvariant(), Transport = profile.Transport, Vantage = profile.Vantage.Trim() });
        }
        return result;
    }

    private static CertificateProbeProfile Create(string id, int port, string service, CertificateProbeTransport transport, bool enabled = false)
        => new() { Id = id, Port = port, Service = service, Transport = transport, Enabled = enabled };
}
