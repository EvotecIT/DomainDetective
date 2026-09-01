using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests.Fixtures;

public sealed class TcpListenerFixture : IAsyncLifetime
{
    private readonly Func<TcpListener, CancellationToken, Task> _server;
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private Task? _serverTask;

    public int Port { get; private set; }

    public TcpListenerFixture(Func<TcpListener, CancellationToken, Task> server)
    {
        _server = server;
        _listener = new TcpListener(IPAddress.Loopback, 0);
    }

    public Task InitializeAsync()
    {
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _serverTask = _server(_listener, _cts.Token);
        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        _cts.Cancel();
        _listener.Stop();
        if (_serverTask != null)
        {
            try { await _serverTask; } catch { }
        }

        _cts.Dispose();
    }
}
