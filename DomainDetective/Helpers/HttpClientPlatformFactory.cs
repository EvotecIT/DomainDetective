using System;
using System.Net.Http;

namespace DomainDetective.Helpers;

internal static class HttpClientPlatformFactory {
    internal static HttpClient CreateRedirectClient(int maxAutomaticRedirections = 10, string? userAgent = null) {
        NetFrameworkTls.EnsureEnabled();

        HttpClient client;
        if (IsBrowserRuntime()) {
            client = new HttpClient();
        } else {
            var handler = new HttpClientHandler {
                AllowAutoRedirect = true,
                MaxAutomaticRedirections = maxAutomaticRedirections
            };
            client = new HttpClient(handler, disposeHandler: true);
        }

        if (!string.IsNullOrWhiteSpace(userAgent)) {
            try {
                client.DefaultRequestHeaders.UserAgent.ParseAdd(userAgent);
            } catch {
                // Ignore invalid user agent formats in restricted runtimes.
            }
        }

        return client;
    }

    private static bool IsBrowserRuntime() {
#if NET5_0_OR_GREATER
        return OperatingSystem.IsBrowser();
#else
        return false;
#endif
    }
}
