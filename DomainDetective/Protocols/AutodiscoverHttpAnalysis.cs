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
    public async Task Analyze(string domain, InternalLogger logger, CancellationToken cancellationToken = default) {
        using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "AUTODISC", target: domain);
        if (string.IsNullOrWhiteSpace(domain)) {
            throw new ArgumentNullException(nameof(domain));
        }

        _endpoints.Clear();
        var attempts = new[] {
            (Url: $"https://autodiscover.{domain}/autodiscover/autodiscover.xml", Method: AutodiscoverMethod.AutodiscoverSubdomainHttps),
            (Url: $"https://{domain}/autodiscover/autodiscover.xml", Method: AutodiscoverMethod.RootDomainHttps),
            (Url: $"http://autodiscover.{domain}/autodiscover/autodiscover.xml", Method: AutodiscoverMethod.HttpRedirect),
            (Url: $"http://{domain}/autodiscover/autodiscover.xml", Method: AutodiscoverMethod.HttpRedirect)
        };

        foreach (var attempt in attempts) {
            var result = await CheckEndpoint(attempt.Url, attempt.Method, logger, cancellationToken);
            _endpoints.Add(result);
            if (result.XmlValid) {
                break;
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

    private static bool ValidateXml(string content) {
        try {
            var doc = XDocument.Parse(content);
            return string.Equals(doc.Root?.Name.LocalName, "Autodiscover", StringComparison.OrdinalIgnoreCase);
        } catch {
            return false;
        }
    }

    private async Task<AutodiscoverEndpointResult> CheckEndpoint(string url, AutodiscoverMethod method, InternalLogger logger, CancellationToken cancellationToken) {
        var redirects = new List<string>();
        int status = 0;
        bool valid = false;
        var tuple = CreateClient();
        var client = tuple.client;
        try {
            var current = new Uri(url);
            while (true) {
                redirects.Add(current.AbsoluteUri);
                using var response = await client.GetAsync(current, cancellationToken);
                status = (int)response.StatusCode;
                if ((int)response.StatusCode >= 300 && (int)response.StatusCode < 400 && response.Headers.Location != null) {
                    if (redirects.Count > MaxRedirects) {
                        throw new InvalidOperationException($"Maximum number of redirects ({MaxRedirects}) exceeded.");
                    }
                    current = response.Headers.Location.IsAbsoluteUri ? response.Headers.Location : new Uri(current, response.Headers.Location);
                    continue;
                }
                if (response.IsSuccessStatusCode) {
                    var body = await response.Content.ReadAsStringAsync();
                    valid = ValidateXml(body);
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

        return new AutodiscoverEndpointResult {
            Method = method,
            Url = url,
            StatusCode = status,
            RedirectChain = redirects,
            XmlValid = valid
        };
    }

    public List<Assessment> Assessments { get; } = new();
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);
}
}
