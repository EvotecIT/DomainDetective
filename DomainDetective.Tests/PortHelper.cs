namespace DomainDetective.Tests;

using System.Net;
using System.Net.Sockets;

internal static class PortHelper
{
    private static readonly object PortLock = new();

    public static int GetFreePort()
    {
        lock (PortLock)
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }
    }
}
