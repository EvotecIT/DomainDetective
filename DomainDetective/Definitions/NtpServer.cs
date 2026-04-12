using System;

namespace DomainDetective;

/// <summary>
/// Commonly used public NTP servers.
/// </summary>
[AttributeUsage(AttributeTargets.Field)]
internal sealed class NtpHostAttribute : Attribute {
    public string Host { get; }
    public NtpHostAttribute(string host) => Host = host;
}

/// <summary>Defines values for ntp server.</summary>
public enum NtpServer {
    /// <summary>Pool.ntp.org service.</summary>
    [NtpHost("pool.ntp.org")]
    Pool,
    /// <summary>Google public NTP.</summary>
    [NtpHost("time.google.com")]
    Google,
    /// <summary>Cloudflare public NTP.</summary>
    [NtpHost("time.cloudflare.com")]
    Cloudflare,
    /// <summary>NIST time service.</summary>
    [NtpHost("time.nist.gov")]
    Nist,
    /// <summary>Windows time service.</summary>
    [NtpHost("time.windows.com")]
    Windows
}

/// <summary>Extension methods for <see cref="NtpServer"/>.</summary>
public static class NtpServerExtensions {
    /// <summary>Gets the host name for the server.</summary>
    public static string ToHost(this NtpServer server) {
        var field = typeof(NtpServer).GetField(server.ToString());
        if (field != null && Attribute.GetCustomAttribute(field, typeof(NtpHostAttribute)) is NtpHostAttribute attr) {
            return attr.Host;
        }
        return server.ToString().ToLowerInvariant();
    }

    /// <summary>Tries to parse a server name.</summary>
    public static bool TryParse(string? value, out NtpServer server) {
        if (!string.IsNullOrWhiteSpace(value) && Enum.TryParse<NtpServer>(value, true, out var result)) {
            server = result;
            return true;
        }
        server = default;
        return false;
    }
}
