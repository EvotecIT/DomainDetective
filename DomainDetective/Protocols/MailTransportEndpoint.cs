using System;
using System.Net;

namespace DomainDetective;

/// <summary>
/// Describes a mail endpoint whose logical hostname can differ from the address used for the TCP connection.
/// </summary>
/// <remarks>
/// <see cref="HostName"/> remains the protocol and TLS identity. Set <see cref="ConnectAddress"/> to pin the
/// socket to a specific backend address without changing SNI or certificate hostname validation.
/// </remarks>
public sealed class MailTransportEndpoint {
    private string _hostName = string.Empty;

    /// <summary>Creates an empty endpoint for serializers and object initializers.</summary>
    public MailTransportEndpoint() {
    }

    /// <summary>Creates an endpoint for a logical mail host and port.</summary>
    public MailTransportEndpoint(string hostName, int port) {
        HostName = hostName;
        Port = port;
    }

    /// <summary>Logical mail hostname used for protocol identity, SNI, and certificate validation.</summary>
    public string HostName {
        get => _hostName;
        set => _hostName = EndpointHostNormalizer.Normalize(value);
    }

    /// <summary>TCP port used by the probe.</summary>
    public int Port { get; set; }

    /// <summary>Optional concrete address used for the TCP connection.</summary>
    public IPAddress? ConnectAddress { get; set; }

    /// <summary>Requested network address family.</summary>
    public MailTransportAddressFamily AddressFamily { get; set; } = MailTransportAddressFamily.Any;

    /// <summary>Stable result key based on the logical hostname and port.</summary>
    public string Key => $"{HostName}:{Port}";

    internal void Validate() {
        if (string.IsNullOrWhiteSpace(HostName)) {
            throw new ArgumentException("A logical mail hostname is required.", nameof(HostName));
        }
        if (Port < 1 || Port > 65535) {
            throw new ArgumentOutOfRangeException(nameof(Port), "Port must be between 1 and 65535.");
        }
        if (ConnectAddress != null && !MailTransportConnector.Matches(ConnectAddress, AddressFamily)) {
            throw new ArgumentException(
                $"Connect address '{ConnectAddress}' does not match requested address family '{AddressFamily}'.",
                nameof(ConnectAddress));
        }
    }
}
