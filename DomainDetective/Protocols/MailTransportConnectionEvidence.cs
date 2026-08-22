using System.Net;
using System.Net.Sockets;

namespace DomainDetective;

/// <summary>
/// Records the requested and observed endpoint of a mail transport connection.
/// </summary>
public sealed class MailTransportConnectionEvidence {
    /// <summary>Logical hostname used by the protocol and TLS layers.</summary>
    public string HostName { get; set; } = string.Empty;

    /// <summary>TCP port used by the probe.</summary>
    public int Port { get; set; }

    /// <summary>Concrete address requested by the caller, when the connection was pinned.</summary>
    public string? ConnectAddress { get; set; }

    /// <summary>Address-family selection requested by the caller.</summary>
    public MailTransportAddressFamily RequestedAddressFamily { get; set; }

    /// <summary>Remote address observed after the TCP connection succeeded.</summary>
    public string? RemoteAddress { get; set; }

    /// <summary>Address family observed after the TCP connection succeeded.</summary>
    public MailTransportAddressFamily? RemoteAddressFamily { get; set; }

    internal static MailTransportConnectionEvidence FromTarget(MailTransportEndpoint endpoint) => new() {
        HostName = endpoint.HostName,
        Port = endpoint.Port,
        ConnectAddress = endpoint.ConnectAddress?.ToString(),
        RequestedAddressFamily = endpoint.AddressFamily
    };

    internal void Capture(TcpClient client) {
        if (client.Client.RemoteEndPoint is not IPEndPoint remote) {
            return;
        }

        RemoteAddress = remote.Address.ToString();
        RemoteAddressFamily = MailTransportConnector.ToMailAddressFamily(remote.Address);
    }
}
