using System;
using System.Net;
using System.Net.Sockets;

namespace DomainDetective.Tests;

internal sealed class DisposableTcpListener : TcpListener, IDisposable
{
    public DisposableTcpListener(IPAddress localaddr, int port)
        : base(localaddr, port)
    {
    }

    public new void Dispose()
    {
        Stop();
        GC.SuppressFinalize(this);
    }
}
