using System;
using System.Net.Http;
using System.Net.Security;

namespace DomainDetective;

public partial class CertificateAnalysis {
    private bool _tlsDetailsReusable;
    private string? _tlsProtocolProbeRoute;

    private static string? ConfiguredTlsProxy =>
        Environment.GetEnvironmentVariable("HTTPS_PROXY") ?? Environment.GetEnvironmentVariable("https_proxy") ??
        Environment.GetEnvironmentVariable("HTTP_PROXY") ?? Environment.GetEnvironmentVariable("http_proxy");

    private static string ProtocolProbeRoute(Uri uri, int port) =>
        uri.IdnHost.ToLowerInvariant() + ":" + port + "|" + ConfiguredTlsProxy;

    private void CaptureHttpTlsNegotiation(SslStream stream, Uri uri, int port) {
        CaptureTlsNegotiation(stream);
        if (!CaptureTlsDetails) { return; }
        // These details belong to the actual HTTP connection. Auxiliary probes use
        // an explicit environment-proxy route, so reuse only a proven direct match.
        _tlsDetailsReusable = true;
        if (!string.IsNullOrEmpty(ConfiguredTlsProxy)) { return; }
#if NET8_0_OR_GREATER
        try {
            if (HttpClient.DefaultProxy.IsBypassed(uri)) { _tlsProtocolProbeRoute = ProtocolProbeRoute(uri, port); }
        } catch (Exception) {
            // Unknown proxy policy requires an independent protocol probe.
        }
#endif
    }
}
