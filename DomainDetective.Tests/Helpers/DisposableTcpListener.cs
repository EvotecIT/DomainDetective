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

#if NET8_0_OR_GREATER
    public new void Dispose()
#else
    public void Dispose()
#endif
    {
        Stop();
        GC.SuppressFinalize(this);
    }
}
