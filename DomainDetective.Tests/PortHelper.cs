namespace DomainDetective.Tests;

using System.Net;
using System.Net.Sockets;
using System.Collections.Generic;
using System.Threading;

internal sealed class PortReservation {
    public Mutex Mutex { get; }
    public SynchronizationContext? Context { get; }
    public int ThreadId { get; }

    public PortReservation(Mutex mutex, SynchronizationContext? context, int threadId) {
        Mutex = mutex;
        Context = context;
        ThreadId = threadId;
    }
}

internal static class PortHelper {
    private static readonly object PortLock = new();
    private static readonly HashSet<int> UsedPorts = new();
    private static readonly Dictionary<int, PortReservation> Reservations = new();

    public static int GetFreePort() {
        lock (PortLock) {
            while (true) {
                var listener = new TcpListener(IPAddress.Loopback, 0);
                listener.Start();
                var port = ((IPEndPoint)listener.LocalEndpoint).Port;

                var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                try {
                    udp.Bind(new IPEndPoint(IPAddress.Loopback, port));
                } catch (SocketException) {
                    listener.Stop();
                    udp.Dispose();
                    continue;
                }

                listener.Stop();
                udp.Dispose();

                if (!UsedPorts.Add(port)) {
                    continue;
                }

                var mutex = new Mutex(false, $"DomainDetective_{port}");
                if (!mutex.WaitOne(0)) {
                    mutex.Dispose();
                    UsedPorts.Remove(port);
                    continue;
                }

                Reservations[port] = new PortReservation(
                    mutex,
                    SynchronizationContext.Current,
                    Environment.CurrentManagedThreadId);
                return port;
            }
        }
    }

    public static void ReleasePort(int port) {
        lock (PortLock) {
            if (Reservations.TryGetValue(port, out var reservation)) {
                try {
                    if (reservation.ThreadId == Environment.CurrentManagedThreadId) {
                        reservation.Mutex.ReleaseMutex();
                    } else if (reservation.Context != null && reservation.Context != SynchronizationContext.Current) {
                        reservation.Context.Send(_ => reservation.Mutex.ReleaseMutex(), null);
                    } else if (reservation.Context != null) {
                        reservation.Context.Post(_ => reservation.Mutex.ReleaseMutex(), null);
                    }
                } catch (ApplicationException) {
                    // Ignore if mutex ownership has been lost
                }

                reservation.Mutex.Dispose();
                Reservations.Remove(port);
            }

            UsedPorts.Remove(port);
        }
    }
}