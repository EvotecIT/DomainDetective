using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>Owns visible redirects and the origin boundary for explicit HTTP customization.</summary>
internal static class HttpRequestBoundary {
    internal static bool IsSameOrigin(Uri left, Uri right) =>
        left.Scheme.Equals(right.Scheme, StringComparison.OrdinalIgnoreCase)
        && left.IdnHost.Equals(right.IdnHost, StringComparison.OrdinalIgnoreCase)
        && left.Port == right.Port;

    internal static void DisableAutoRedirect(HttpMessageHandler handler) {
        // Reflection also covers platform-specific handlers without adding a runtime dependency.
        var property = handler.GetType().GetProperty("AllowAutoRedirect");
        if (property != null && property.CanWrite && property.PropertyType == typeof(bool)) {
            property.SetValue(handler, false, null);
        }
        if (handler is DelegatingHandler wrapper && wrapper.InnerHandler != null) {
            DisableAutoRedirect(wrapper.InnerHandler);
        }
    }

    internal static CookieContainer? PrepareHandler(HttpMessageHandler handler) {
        DisableAutoRedirect(handler);
        if (handler is DelegatingHandler wrapper && wrapper.InnerHandler != null) {
            return PrepareHandler(wrapper.InnerHandler);
        }
        // Framework HttpClientHandler replaces an explicit Cookie header when its cookie
        // container is enabled. Own cookie handling at the visible redirect boundary so
        // raw customization stays origin-scoped while server cookies retain normal rules.
        var useCookies = handler.GetType().GetProperty("UseCookies");
        var cookieContainer = handler.GetType().GetProperty("CookieContainer");
        if (useCookies?.CanWrite == true && useCookies.PropertyType == typeof(bool)
            && useCookies.GetValue(handler, null) is true
            && cookieContainer?.GetValue(handler, null) is CookieContainer cookies) {
            useCookies.SetValue(handler, false, null);
            return cookies;
        }
        return null;
    }

    internal static async Task<HttpResponseMessage> SendAsync(
        HttpClient client, Uri initialUri, Uri customizationOrigin, HttpMethod method,
        HttpRequestOptions options, int maxRedirects, CancellationToken cancellationToken,
        Version? requestVersion = null, List<string>? visitedUrls = null, List<string>? headerNames = null,
        CookieContainer? cookies = null) {
        var currentUri = initialUri;
        var visited = new HashSet<string>(StringComparer.Ordinal);
        for (var redirects = 0; ; redirects++) {
            cancellationToken.ThrowIfCancellationRequested();
            if (!currentUri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                && !currentUri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)) {
                throw new HttpRequestException("Only HTTP and HTTPS URLs are supported.");
            }
            if (!visited.Add(currentUri.AbsoluteUri)) {
                throw new InvalidOperationException("Redirect loop detected.");
            }
            visitedUrls?.Add(currentUri.AbsoluteUri);
            using var request = new HttpRequestMessage(method, currentUri);
            if (requestVersion != null) {
                request.Version = requestVersion;
#if NET8_0_OR_GREATER
                request.VersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
#endif
            }
            if (IsSameOrigin(customizationOrigin, currentUri)) {
                if (!string.IsNullOrWhiteSpace(options.Cookie)) AddHeader(request, "Cookie", options.Cookie, headerNames);
                foreach (var header in options.Headers) {
                    AddHeader(request, header.Key, header.Value, headerNames);
                }
            }
            AddServerCookies(request, currentUri, cookies);
            var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            StoreServerCookies(response, currentUri, cookies);
            if ((int)response.StatusCode < 300 || (int)response.StatusCode >= 400 || response.Headers.Location == null) {
                response.RequestMessage ??= request;
                return response; // Caller owns the final response, including its unread body.
            }
            try {
                if (redirects >= maxRedirects) {
                    throw new InvalidOperationException($"Maximum number of redirects ({maxRedirects}) exceeded.");
                }
                var next = response.Headers.Location.IsAbsoluteUri
                    ? response.Headers.Location : new Uri(currentUri, response.Headers.Location);
                if (currentUri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
                    && next.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)) {
                    throw new HttpRequestException("HTTPS to HTTP redirects are not allowed.");
                }
                method = GetRedirectMethod(method, response.StatusCode);
                currentUri = next;
            } finally {
                response.Dispose();
            }
        }
    }

    private static void AddServerCookies(HttpRequestMessage request, Uri uri, CookieContainer? cookies) {
        if (cookies == null) return;
        string serverCookies = cookies.GetCookieHeader(uri);
        if (string.IsNullOrEmpty(serverCookies)) return;
        string value = request.Headers.TryGetValues("Cookie", out var explicitValues)
            ? string.Join("; ", explicitValues) + "; " + serverCookies : serverCookies;
        request.Headers.Remove("Cookie");
        request.Headers.TryAddWithoutValidation("Cookie", value);
    }

    // Modern Set-Cookie is the supported server-cookie contract; RFC2965 Set-Cookie2 is not imported.
    private static void StoreServerCookies(HttpResponseMessage response, Uri uri, CookieContainer? cookies) {
        if (cookies == null || !response.Headers.TryGetValues("Set-Cookie", out var values)) return;
        foreach (string value in values) {
            try { cookies.SetCookies(uri, value); }
            catch (CookieException) { /* Malformed server cookies do not invalidate the HTTP response. */ }
        }
    }

    internal static HttpMethod GetRedirectMethod(HttpMethod method, HttpStatusCode statusCode) {
        if (statusCode == HttpStatusCode.SeeOther && method != HttpMethod.Head) {
            return HttpMethod.Get;
        }
        if ((statusCode == HttpStatusCode.MovedPermanently || statusCode == HttpStatusCode.Found) && method == HttpMethod.Post) {
            return HttpMethod.Get;
        }
        return method;
    }

    private static void AddHeader(HttpRequestMessage request, string name, string? value, List<string>? names) {
        if (string.IsNullOrWhiteSpace(name)) return;
        try {
            if (request.Headers.TryAddWithoutValidation(name, value ?? string.Empty) && names != null
                && !names.Exists(existing => existing.Equals(name, StringComparison.OrdinalIgnoreCase))) {
                names.Add(name);
            }
        } catch (ArgumentException) { /* Invalid customization remains best-effort. */ }
        catch (FormatException) { }
        catch (InvalidOperationException) { }
    }
}
