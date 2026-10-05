using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>Checks anonymous Autodiscover HTTP responses using bounded, ordered fallbacks similar to Outlook clients.</summary>
public partial class AutodiscoverHttpAnalysis : IHasAssessments {
    /// <summary>Deadline for one endpoint, including redirects, GET, POST and response bodies.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(5);
    /// <summary>Connection-establishment deadline on modern .NET. Framework uses the whole-endpoint deadline.</summary>
    public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(2);
    /// <summary>Total deadline for the ordered HTTP flow.</summary>
    public TimeSpan AnalysisTimeout { get; set; } = TimeSpan.FromSeconds(15);
    /// <summary>Maximum response bytes accepted before XML or JSON parsing.</summary>
    public int MaxResponseBodyBytes { get; set; } = 512 * 1024;
    /// <summary>Maximum redirects to follow within one endpoint.</summary>
    public int MaxRedirects { get; set; } = 5;
    /// <summary>Optional SRV target host for fallback.</summary>
    public string? SrvTarget { get; set; }
    /// <summary>Optional SRV target port, default443.</summary>
    public int? SrvPort { get; set; }
    /// <summary>Optional CNAME target host for fallback.</summary>
    public string? CnameTarget { get; set; }
    /// <summary>Email used in the anonymous POST request, default autodiscover@domain.</summary>
    public string? EmailForPost { get; set; }
    private readonly List<AutodiscoverEndpointResult> _endpoints = new();
    /// <summary>Gets attempted endpoints and their request/phase evidence.</summary>
    public IReadOnlyList<AutodiscoverEndpointResult> Endpoints => _endpoints;
    /// <summary>Gets whether the total flow deadline prevented remaining fallbacks.</summary>
    public bool BudgetExhausted { get; private set; }
    internal Func<HttpMessageHandler>? HttpHandlerFactory { get; set; }
    /// <summary>Gets per-analysis assessments.</summary>
    public List<Assessment> Assessments { get; } = new();
    /// <summary>Gets recommendations derived from assessments.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

    /// <summary>Runs ordered HTTPS, HTTP redirect, Outlook JSON, CNAME and SRV attempts.</summary>
    /// <remarks>A recognized settings, redirect or error response establishes service discovery. It does not prove authenticated mailbox settings.
    /// On net472, Timeout bounds the entire endpoint; ConnectTimeout is not a separate connection-only timer.</remarks>
    public async Task Analyze(string domain, InternalLogger logger, CancellationToken cancellationToken = default) {
        if (string.IsNullOrWhiteSpace(domain)) throw new ArgumentNullException(nameof(domain));
        if (Timeout <= TimeSpan.Zero || AnalysisTimeout <= TimeSpan.Zero || ConnectTimeout <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(Timeout), "Deadlines must be positive.");
        if (MaxResponseBodyBytes <= 0) throw new ArgumentOutOfRangeException(nameof(MaxResponseBodyBytes));
        if (MaxRedirects < 0) throw new ArgumentOutOfRangeException(nameof(MaxRedirects));
        Assessments.Clear(); _endpoints.Clear(); BudgetExhausted = false;
        using var collector = AssessmentCollector.ForAnalysis(logger, this, category: "AUTODISC", target: domain);
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        budget.CancelAfter(AnalysisTimeout);
        var attempts = new List<(string Url, AutodiscoverMethod Method, bool Post)> {
            ($"https://autodiscover.{domain}/autodiscover/autodiscover.xml", AutodiscoverMethod.AutodiscoverSubdomainHttps, true),
            ($"https://{domain}/autodiscover/autodiscover.xml", AutodiscoverMethod.RootDomainHttps, true),
            ($"http://autodiscover.{domain}/autodiscover/autodiscover.xml", AutodiscoverMethod.HttpRedirect, false),
            ($"http://{domain}/autodiscover/autodiscover.xml", AutodiscoverMethod.HttpRedirect, false),
            ($"https://autodiscover-s.outlook.com/autodiscover/autodiscover.json/v1.0/{domain}?Protocol=AutodiscoverV1", AutodiscoverMethod.OutlookV2Json, false)
        };
        if (!string.IsNullOrWhiteSpace(CnameTarget)) attempts.Add(($"https://{CnameTarget}/autodiscover/autodiscover.xml", AutodiscoverMethod.CnameTargetHttps, true));
        if (!string.IsNullOrWhiteSpace(SrvTarget)) attempts.Add(($"https://{SrvTarget}:{SrvPort.GetValueOrDefault(443)}/autodiscover/autodiscover.xml", AutodiscoverMethod.SrvTargetHttps, true));
        foreach (var attempt in attempts) {
            cancellationToken.ThrowIfCancellationRequested();
            if (budget.IsCancellationRequested) break;
            bool json = attempt.Method == AutodiscoverMethod.OutlookV2Json;
            var result = await CheckEndpointAsync(attempt.Url, attempt.Method, attempt.Post, json, domain, logger, budget.Token, cancellationToken).ConfigureAwait(false);
            _endpoints.Add(result);
            if (result.DiscoverySucceeded) break;
            if (json && result.JsonValid && !budget.IsCancellationRequested) {
                var follow = await CheckEndpointAsync(result.JsonEndpointUrl!, AutodiscoverMethod.OutlookV2JsonPost,
                    true, false, domain, logger, budget.Token, cancellationToken).ConfigureAwait(false);
                _endpoints.Add(follow);
                if (follow.DiscoverySucceeded) break;
            }
        }
        cancellationToken.ThrowIfCancellationRequested();
        BudgetExhausted = budget.IsCancellationRequested;
        if (BudgetExhausted) logger.WriteWarningCode(AutodiscoverCodes.BudgetExhausted, "Autodiscover HTTP flow exhausted its overall deadline; remaining fallbacks were not attempted.");
    }

    private HttpClient CreateClient() {
        HttpMessageHandler handler;
        if (HttpHandlerFactory != null) handler = HttpHandlerFactory();
#if NET8_0_OR_GREATER
        else handler = new SocketsHttpHandler { AllowAutoRedirect = false, ConnectTimeout = ConnectTimeout };
#else
        else handler = new HttpClientHandler { AllowAutoRedirect = false };
#endif
        return new HttpClient(handler, disposeHandler: true) { Timeout = System.Threading.Timeout.InfiniteTimeSpan };
    }
}
