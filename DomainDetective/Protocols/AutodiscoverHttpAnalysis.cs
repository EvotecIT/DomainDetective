using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace DomainDetective {

/// <summary>
/// Performs Autodiscover endpoint checks over HTTP/HTTPS.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class AutodiscoverHttpAnalysis : IHasAssessments {
    /// <summary>HTTP request timeout.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);
    /// <summary>Maximum redirects to follow.</summary>
    public int MaxRedirects { get; set; } = 5;

    /// <summary>Optional SRV target host for fallback POST attempt.</summary>
    public string? SrvTarget { get; set; }
    /// <summary>Optional SRV target port for fallback POST attempt (default 443).</summary>
    public int? SrvPort { get; set; }
    /// <summary>Optional autodiscover CNAME target for fallback POST attempt.</summary>
    public string? CnameTarget { get; set; }
    /// <summary>Email address used in POST payload; if null, uses autodiscover@domain.</summary>
    public string? EmailForPost { get; set; }

    private readonly List<AutodiscoverEndpointResult> _endpoints = new();
    /// <summary>Results of attempted endpoints.</summary>
    public IReadOnlyList<AutodiscoverEndpointResult> Endpoints => _endpoints;

    /// <summary>Factory for creating custom HTTP handlers.</summary>
    internal Func<HttpMessageHandler>? HttpHandlerFactory { get; set; }

    /// <summary>
    /// Checks common Autodiscover URLs in sequence.
    /// </summary>
    /// <param name="domain">Domain to test.</param>
    /// <param name="logger">Logger for debug output.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <summary>
    /// Runs an Autodiscover HTTP flow similar to Outlook clients.
    /// </summary>
    /// <remarks>
    /// Order of attempts:
    /// 1) GET then POST https://autodiscover.&lt;domain&gt;/autodiscover/autodiscover.xml
    /// 2) GET then POST https://&lt;domain&gt;/autodiscover/autodiscover.xml
    /// 3) GET http://autodiscover.&lt;domain&gt;/autodiscover/autodiscover.xml (follow redirects)
    /// 4) GET http://&lt;domain&gt;/autodiscover/autodiscover.xml (follow redirects)
    /// 5) GET Outlook v2 JSON discovery: https://autodiscover-s.outlook.com/autodiscover/autodiscover.json/v1.0/&lt;domain&gt;?Protocol=AutodiscoverV1
    ///    If a Url is returned, a follow-up POST is performed to that endpoint.
    /// 6) If provided, GET then POST https://&lt;CNAME target&gt;/autodiscover/autodiscover.xml
    /// 7) If provided, GET then POST https://&lt;SRV target&gt;:&lt;port&gt;/autodiscover/autodiscover.xml
    ///
    /// For HTTPS endpoints, a POST with a minimal Autodiscover XML body is executed when the GET does not yield
    /// a valid XML document, to emulate Outlook behavior where servers require POST.
    /// </remarks>
    public async Task Analyze(string domain, InternalLogger logger, CancellationToken cancellationToken = default) {
        using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "AUTODISC", target: domain);
        if (string.IsNullOrWhiteSpace(domain)) {
            throw new ArgumentNullException(nameof(domain));
        }

        _endpoints.Clear();
        var attempts = new List<(string Url, AutodiscoverMethod Method, bool TryPost)> {
            ($"https://autodiscover.{domain}/autodiscover/autodiscover.xml", AutodiscoverMethod.AutodiscoverSubdomainHttps, true),
            ($"https://{domain}/autodiscover/autodiscover.xml", AutodiscoverMethod.RootDomainHttps, true),
            ($"http://autodiscover.{domain}/autodiscover/autodiscover.xml", AutodiscoverMethod.HttpRedirect, false),
            ($"http://{domain}/autodiscover/autodiscover.xml", AutodiscoverMethod.HttpRedirect, false)
        };

        // Try Outlook v2 JSON domain discovery as a late fallback to emulate Outlook behavior
        attempts.Add(($"https://autodiscover-s.outlook.com/autodiscover/autodiscover.json/v1.0/{domain}?Protocol=AutodiscoverV1", AutodiscoverMethod.OutlookV2Json, false));

        if (!string.IsNullOrWhiteSpace(CnameTarget)) {
            attempts.Add(($"https://{CnameTarget}/autodiscover/autodiscover.xml", AutodiscoverMethod.CnameTargetHttps, true));
        }
        if (!string.IsNullOrWhiteSpace(SrvTarget)) {
            var port = SrvPort.GetValueOrDefault(443);
            attempts.Add(($"https://{SrvTarget}:{port}/autodiscover/autodiscover.xml", AutodiscoverMethod.SrvTargetHttps, true));
        }

        foreach (var attempt in attempts) {
            AutodiscoverEndpointResult result;
            if (attempt.Method == AutodiscoverMethod.OutlookV2Json) {
                result = await CheckJsonEndpoint(attempt.Url, attempt.Method, logger, cancellationToken);
                _endpoints.Add(result);
                if (result.JsonValid && !string.IsNullOrWhiteSpace(result.JsonEndpointUrl)) {
                    // Follow up with POST to the discovered endpoint
                    var follow = await CheckEndpoint(result.JsonEndpointUrl!, AutodiscoverMethod.OutlookV2JsonPost, tryPost: true, domainForEmail: domain, logger, cancellationToken);
                    _endpoints.Add(follow);
                    if (follow.XmlValid) break; // success
                    // else continue to other fallbacks
                    continue;
                }
            } else {
                result = await CheckEndpoint(attempt.Url, attempt.Method, attempt.TryPost, domain, logger, cancellationToken);
                _endpoints.Add(result);
                if (result.XmlValid) break;
            }
        }
    }

    private (HttpClient client, bool dispose) CreateClient() {
        if (HttpHandlerFactory != null) {
            var handler = HttpHandlerFactory();
            var client = new HttpClient(handler, disposeHandler: true) { Timeout = Timeout };
            return (client, true);
        }
        var h = new HttpClientHandler { AllowAutoRedirect = false };
        var c = new HttpClient(h, disposeHandler: true) { Timeout = Timeout };
        return (c, true);
    }

    private static (bool valid, string? ns, bool nsValid) ValidateXmlAndNamespace(string content) {
        try {
            var doc = XDocument.Parse(content);
            var local = doc.Root?.Name.LocalName;
            var ns = doc.Root?.Name.NamespaceName;
            if (!string.Equals(local, "Autodiscover", StringComparison.OrdinalIgnoreCase)) {
                return (false, ns, false);
            }
            bool nsValid = false;
            if (!string.IsNullOrWhiteSpace(ns)) {
                // Accept common Exchange autodiscover namespaces
                nsValid = ns.IndexOf("autodiscover", StringComparison.OrdinalIgnoreCase) >= 0
                          || ns.IndexOf("schemas.microsoft.com/exchange/autodiscover", StringComparison.OrdinalIgnoreCase) >= 0
                          || ns.IndexOf("schemas.microsoft.com/exchange/autodiscover/outlook", StringComparison.OrdinalIgnoreCase) >= 0;
            }
            return (true, ns, nsValid);
        } catch {
            return (false, null, false);
        }
    }

    private async Task<AutodiscoverEndpointResult> CheckEndpoint(string url, AutodiscoverMethod method, bool tryPost, string domainForEmail, InternalLogger logger, CancellationToken cancellationToken) {
        var redirects = new List<string>();
        int status = 0;
        bool valid = false;
        string? finalUrl = null;
        string? finalHost = null;
        string? contentType = null;
        string? contentSnippet = null;
        bool looksHtml = false;
        string? xmlNs = null;
        bool xmlNsValid = false;
        var tuple = CreateClient();
        var client = tuple.client;
        try {
            var current = new Uri(url);
            while (true) {
                redirects.Add(current.AbsoluteUri);
                using var response = await client.GetAsync(current, cancellationToken);
                status = (int)response.StatusCode;
                contentType = response.Content?.Headers?.ContentType?.MediaType;
                if ((int)response.StatusCode >= 300 && (int)response.StatusCode < 400 && response.Headers.Location != null) {
                    if (redirects.Count > MaxRedirects) {
                        throw new InvalidOperationException($"Maximum number of redirects ({MaxRedirects}) exceeded.");
                    }
                    current = response.Headers.Location.IsAbsoluteUri ? response.Headers.Location : new Uri(current, response.Headers.Location);
                    continue;
                }
                if (response.IsSuccessStatusCode) {
                    var body = await response.Content.ReadAsStringAsync();
                    if (!string.IsNullOrEmpty(body)) {
                        contentSnippet = body.Length > 512 ? body.Substring(0, 512) : body;
                        var trimmed = body.TrimStart();
                        looksHtml = trimmed.StartsWith("<html", StringComparison.OrdinalIgnoreCase) || (contentType?.IndexOf("html", StringComparison.OrdinalIgnoreCase) >= 0);
                        var vr = ValidateXmlAndNamespace(body);
                        valid = vr.valid;
                        xmlNs = vr.ns;
                        xmlNsValid = vr.nsValid;
                    }
                }
                finalUrl = current.AbsoluteUri;
                finalHost = current.Host;

                // If GET did not yield valid XML and POST is desired, attempt a POST to the final URL (typically HTTPS)
                if (!valid && tryPost && finalUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) {
                    try {
                        var email = string.IsNullOrWhiteSpace(EmailForPost) ? $"autodiscover@{domainForEmail}" : EmailForPost!;
                        using var post = new HttpRequestMessage(HttpMethod.Post, current);
                        var xml = BuildAutodiscoverRequestXml(email);
                        post.Content = new StringContent(xml);
                        post.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("text/xml");
                        using var postResp = await client.SendAsync(post, cancellationToken);
                        status = (int)postResp.StatusCode; // prefer POST status if attempted
                        contentType = postResp.Content?.Headers?.ContentType?.MediaType ?? contentType;
                        if (postResp.Content != null) {
                            var body = await postResp.Content.ReadAsStringAsync();
                            if (!string.IsNullOrEmpty(body)) {
                                contentSnippet = (body.Length > 512 ? body.Substring(0, 512) : body) ?? contentSnippet;
                                var vr2 = ValidateXmlAndNamespace(body);
                                valid = vr2.valid;
                                xmlNs = vr2.ns ?? xmlNs;
                                xmlNsValid = vr2.nsValid || xmlNsValid;
                            }
                        }
                    } catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException) {
                        // swallow POST failure, GET outcome stands
                        logger?.WriteVerbose("POST attempt failed for {0}: {1}", finalUrl, ex.Message);
                    }
                }
                break;
            }
        } catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidOperationException) {
            logger?.WriteErrorCode(AutodiscoverCodes.CheckFailed, "Autodiscover HTTP check failed for {0}: {1}", url, ex.Message);
        } finally {
            if (tuple.dispose) {
                client.Dispose();
            }
        }

        var result = new AutodiscoverEndpointResult {
            Method = method,
            Url = url,
            StatusCode = status,
            RedirectChain = redirects,
            XmlValid = valid,
            FinalUrl = finalUrl,
            FinalHost = finalHost,
            ContentType = contentType,
            ContentSnippet = contentSnippet,
            ContentLooksHtml = looksHtml,
            XmlNamespace = xmlNs,
            XmlNamespaceValid = xmlNsValid,
            JsonValid = false,
            JsonEndpointUrl = null
        };
        if (valid) {
            var host = result.FinalHost ?? result.FinalUrl ?? url;
            logger?.WriteInformationCode(AutodiscoverCodes.XmlValid, "Autodiscover endpoint {0} returned valid XML", host);
            logger?.WriteInformationCode(AutodiscoverCodes.EndpointDiscovered, "Autodiscover endpoint discovered at {0}", host);
        }
        return result;
    }

    private static string BuildAutodiscoverRequestXml(string email) {
        // Minimal Outlook Autodiscover request
        return "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
               "<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006\">" +
               "<Request>" +
               $"<EMailAddress>{System.Security.SecurityElement.Escape(email)}</EMailAddress>" +
               "<AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>" +
               "</Request>" +
               "</Autodiscover>";
    }

    private async Task<AutodiscoverEndpointResult> CheckJsonEndpoint(string url, AutodiscoverMethod method, InternalLogger logger, CancellationToken cancellationToken) {
        var redirects = new List<string>();
        int status = 0;
        string? finalUrl = null;
        string? finalHost = null;
        string? contentType = null;
        string? contentSnippet = null;
        string? jsonEndpoint = null;
        var tuple = CreateClient();
        var client = tuple.client;
        try {
            var current = new Uri(url);
            while (true) {
                redirects.Add(current.AbsoluteUri);
                using var request = new HttpRequestMessage(HttpMethod.Get, current);
                request.Headers.Accept.ParseAdd("application/json");
                using var response = await client.SendAsync(request, cancellationToken);
                status = (int)response.StatusCode;
                contentType = response.Content?.Headers?.ContentType?.MediaType;
                if ((int)response.StatusCode >= 300 && (int)response.StatusCode < 400 && response.Headers.Location != null) {
                    if (redirects.Count > MaxRedirects) {
                        throw new InvalidOperationException($"Maximum number of redirects ({MaxRedirects}) exceeded.");
                    }
                    current = response.Headers.Location.IsAbsoluteUri ? response.Headers.Location : new Uri(current, response.Headers.Location);
                    continue;
                }
                if (response.Content != null) {
                    var body = await response.Content.ReadAsStringAsync();
                    if (!string.IsNullOrEmpty(body)) {
                        contentSnippet = body.Length > 512 ? body.Substring(0, 512) : body;
                        // naive JSON parsing for Url property
                        try {
                            void ParseForUrl(System.Text.Json.JsonDocument doc) {
                                if (doc.RootElement.ValueKind == System.Text.Json.JsonValueKind.Object) {
                                    if (doc.RootElement.TryGetProperty("Url", out var urlProp) && urlProp.ValueKind == System.Text.Json.JsonValueKind.String) {
                                        var u = urlProp.GetString();
                                        if (!string.IsNullOrWhiteSpace(u) && (u!.StartsWith("http://") || u.StartsWith("https://"))) {
                                            jsonEndpoint = u;
                                        }
                                    }
                                } else if (doc.RootElement.ValueKind == System.Text.Json.JsonValueKind.Array) {
                                    foreach (var el in doc.RootElement.EnumerateArray()) {
                                        if (el.ValueKind == System.Text.Json.JsonValueKind.Object && el.TryGetProperty("Url", out var urlEl) && urlEl.ValueKind == System.Text.Json.JsonValueKind.String) {
                                            var u = urlEl.GetString();
                                            if (!string.IsNullOrWhiteSpace(u) && (u!.StartsWith("http://") || u.StartsWith("https://"))) {
                                                jsonEndpoint = u;
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            try {
                                using var doc = System.Text.Json.JsonDocument.Parse(body);
                                ParseForUrl(doc);
                            } catch {
                                // Fallback: attempt to unescape common over-escaped JSON bodies (e.g. with \" quotes)
                                try {
                                    var alt = body.Replace("\\\"", "\"");
                                    alt = alt.Replace("\\\\", "\\");
                                    alt = alt.Trim();
                                    if (alt.Length > 2 && alt[0] == '"' && alt[alt.Length - 1] == '"') {
                                        alt = alt.Substring(1, alt.Length - 2);
                                    }
                                    using var altDoc = System.Text.Json.JsonDocument.Parse(alt);
                                    ParseForUrl(altDoc);
                                } catch { /* ignore if still invalid */ }
                            }
                        } catch { /* ignore JSON parse errors */ }
                    }
                }
                finalUrl = current.AbsoluteUri;
                finalHost = current.Host;
                break;
            }
        } catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidOperationException) {
            logger?.WriteErrorCode(AutodiscoverCodes.CheckFailed, "Autodiscover JSON check failed for {0}: {1}", url, ex.Message);
        } finally {
            if (tuple.dispose) client.Dispose();
        }

        var res = new AutodiscoverEndpointResult {
            Method = method,
            Url = url,
            StatusCode = status,
            RedirectChain = redirects,
            XmlValid = false,
            FinalUrl = finalUrl,
            FinalHost = finalHost,
            ContentType = contentType,
            ContentSnippet = contentSnippet,
            ContentLooksHtml = false,
            XmlNamespace = null,
            XmlNamespaceValid = false,
            JsonValid = !string.IsNullOrWhiteSpace(jsonEndpoint),
            JsonEndpointUrl = jsonEndpoint
        };
        if (res.JsonValid) {
            logger?.WriteInformationCode(AutodiscoverCodes.JsonValid, "Autodiscover JSON discovery returned {0}", jsonEndpoint);
            logger?.WriteInformationCode(AutodiscoverCodes.EndpointDiscovered, "Autodiscover endpoint discovered via JSON: {0}", jsonEndpoint);
        }
        return res;
    }

    public List<Assessment> Assessments { get; } = new();
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);
}
}
