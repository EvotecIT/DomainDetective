using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using DomainDetective.Views;

namespace DomainDetective.Toolbox.Services;

public sealed class HostedAnalysisService {
    private static readonly JsonSerializerOptions _jsonOptions = new() {
        PropertyNameCaseInsensitive = true
    };

    private readonly HttpClient _httpClient;

    public HostedAnalysisService(HttpClient httpClient) {
        _httpClient = httpClient;
    }

    public Task<HttpInfo> AnalyzeHttpHeadersAsync(string domainName, bool forceRefresh = false, CancellationToken cancellationToken = default) {
        return PostAsync<HttpInfo>("/tool-api/http-headers", domainName, forceRefresh, cancellationToken);
    }

    public Task<SecurityTxtInfo> AnalyzeSecurityTxtAsync(string domainName, bool forceRefresh = false, CancellationToken cancellationToken = default) {
        return PostAsync<SecurityTxtInfo>("/tool-api/security-txt", domainName, forceRefresh, cancellationToken);
    }

    public Task<CertificateInfo> AnalyzeCertificateAsync(string domainName, bool forceRefresh = false, CancellationToken cancellationToken = default) {
        return PostAsync<CertificateInfo>("/tool-api/cert-check", domainName, forceRefresh, cancellationToken);
    }

    public Task<BimiRecordInfo> AnalyzeBimiAsync(string domainName, bool forceRefresh = false, CancellationToken cancellationToken = default) {
        return PostAsync<BimiRecordInfo>("/tool-api/bimi", domainName, forceRefresh, cancellationToken);
    }

    public Task<MtastsInfo> AnalyzeMtastsAsync(string domainName, bool forceRefresh = false, CancellationToken cancellationToken = default) {
        return PostAsync<MtastsInfo>("/tool-api/mta-sts", domainName, forceRefresh, cancellationToken);
    }

    public Task<RdapInfo> AnalyzeRdapAsync(string domainName, bool forceRefresh = false, CancellationToken cancellationToken = default) {
        return PostAsync<RdapInfo>("/tool-api/rdap", domainName, forceRefresh, cancellationToken);
    }

    public Task<DnsPropagationSetInfo> AnalyzeDnsPropagationAsync(string domainName, bool forceRefresh = false, CancellationToken cancellationToken = default) {
        return PostAsync<DnsPropagationSetInfo>("/tool-api/dns-propagation", domainName, forceRefresh, cancellationToken);
    }

    public Task<SubdomainsInfo> AnalyzeCtSubdomainsAsync(string domainName, bool forceRefresh = false, CancellationToken cancellationToken = default) {
        return PostAsync<SubdomainsInfo>("/tool-api/ct-subdomains", domainName, forceRefresh, cancellationToken);
    }

    public Task<Microsoft365OverviewInfo> AnalyzeMicrosoft365OverviewAsync(string domainName, bool forceRefresh = false, CancellationToken cancellationToken = default) {
        return PostAsync<Microsoft365OverviewInfo>("/tool-api/m365-overview", domainName, forceRefresh, cancellationToken);
    }

    public Task<Microsoft365OverviewInfo> AnalyzeMicrosoft365OverviewQuickAsync(string domainName, bool forceRefresh = false, CancellationToken cancellationToken = default) {
        return PostAsync<Microsoft365OverviewInfo>("/tool-api/m365-overview/quick", domainName, forceRefresh, cancellationToken);
    }

    public Task<DomainOverviewInfo> AnalyzeDomainOverviewAsync(string domainName, bool forceRefresh = false, CancellationToken cancellationToken = default) {
        return PostAsync<DomainOverviewInfo>("/tool-api/domain-overview", domainName, forceRefresh, cancellationToken);
    }

    public Task<DomainOverviewInfo> AnalyzeDomainOverviewQuickAsync(string domainName, bool forceRefresh = false, CancellationToken cancellationToken = default) {
        return PostAsync<DomainOverviewInfo>("/tool-api/domain-overview/quick", domainName, forceRefresh, cancellationToken);
    }

    private async Task<T> PostAsync<T>(string requestPath, string domainName, bool forceRefresh, CancellationToken cancellationToken) {
        if (string.IsNullOrWhiteSpace(domainName)) {
            throw new ArgumentNullException(nameof(domainName));
        }

        using var response = await _httpClient.PostAsJsonAsync(
            requestPath,
            new AnalyzeDomainRequest {
                Domain = domainName.Trim(),
                ForceRefresh = forceRefresh
            },
            _jsonOptions,
            cancellationToken).ConfigureAwait(false);

        if (response.StatusCode == HttpStatusCode.NotFound) {
            throw new HostedAnalysisUnavailableException("This online check requires the hosted DomainDetective analysis API.");
        }

        if (!response.IsSuccessStatusCode) {
            var message = await TryReadErrorAsync(response, cancellationToken).ConfigureAwait(false);
            throw new HostedAnalysisException(message);
        }

        var payload = await response.Content.ReadFromJsonAsync<T>(_jsonOptions, cancellationToken).ConfigureAwait(false);
        if (payload == null) {
            throw new HostedAnalysisException("The hosted analysis API returned an empty response.");
        }

        return payload;
    }

    private static async Task<string> TryReadErrorAsync(HttpResponseMessage response, CancellationToken cancellationToken) {
        try {
            var problem = await response.Content.ReadFromJsonAsync<HostedProblemDetails>(_jsonOptions, cancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(problem?.Detail)) {
                return problem.Detail;
            }
        } catch {
            // Best effort only.
        }

        return $"Hosted analysis failed with {(int)response.StatusCode} {response.ReasonPhrase}.";
    }

    private sealed class AnalyzeDomainRequest {
        public string Domain { get; set; } = string.Empty;
        public bool ForceRefresh { get; set; }
    }

    private sealed class HostedProblemDetails {
        public string? Detail { get; set; }
    }
}

public class HostedAnalysisException : Exception {
    public HostedAnalysisException(string message) : base(message) {
    }
}

public sealed class HostedAnalysisUnavailableException : HostedAnalysisException {
    public HostedAnalysisUnavailableException(string message) : base(message) {
    }
}
