namespace DomainDetective.Tests;

using System.Net;
using System.Net.Sockets;

internal static class PortHelper {
    private static readonly object PortLock = new();
    private static readonly HashSet<int> UsedPorts = new();

    public static int GetFreePort() {
        lock (PortLock) {
            int port;
            do {
                var listener = new TcpListener(IPAddress.Loopback, 0);
                listener.Start();
                port = ((IPEndPoint)listener.LocalEndpoint).Port;
                listener.Stop();
            } while (!UsedPorts.Add(port));

            return port;
        }
    }

    public static void ReservePort(int port) {
        lock (PortLock) {
            UsedPorts.Add(port);
        }
    }
}