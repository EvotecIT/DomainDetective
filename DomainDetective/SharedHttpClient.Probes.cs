using System;
using System.Net.Http;

namespace DomainDetective;

public sealed partial class SharedHttpClient {
    // Only default anonymous probes use this pool. Cookies belong to each operation,
    // and custom headers, credentials, proxies and certificate policies use owned handlers.
    private static readonly Lazy<HttpMessageHandler> _anonymousProbeHandler = new(() => {
#if NET8_0_OR_GREATER
        HttpMessageHandler handler = new SocketsHttpHandler {
            AllowAutoRedirect = false,
            UseCookies = false,
            MaxConnectionsPerServer = 8,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            PooledConnectionIdleTimeout = TimeSpan.FromMinutes(1)
        };
#else
        HttpMessageHandler handler = new HttpClientHandler {
            AllowAutoRedirect = false,
            UseCookies = false,
            MaxConnectionsPerServer = 8
        };
#endif
        AppDomain.CurrentDomain.ProcessExit += (_, _) => handler.Dispose();
        return handler;
    });

    internal static HttpMessageHandler AnonymousProbeHandler => _anonymousProbeHandler.Value;
}
