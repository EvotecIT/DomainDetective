using System;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public sealed partial class SitemapAnalysis {
    private async Task ProbeSitemapUrlsAsync(HttpClient client, SitemapAnalysisOptions options, CancellationToken cancellationToken) {
        var probeLimit = Math.Max(0, Math.Min(options.MaxUrlProbes, Entries.Count));
        if (Entries.Count > probeLimit) {
            AddAssessment(AssessmentSeverity.Warning, SitemapCodes.LimitReached, "URL probe limit reached; checked " + probeLimit.ToString(CultureInfo.InvariantCulture) + " of " + Entries.Count.ToString(CultureInfo.InvariantCulture) + " sitemap entries.", Subject);
        }

        var entries = Entries.Where(entry => entry.LocationValid).Take(probeLimit).ToArray();
        var probes = new SitemapUrlProbe?[entries.Length];
        try {
            await Helpers.AuthoritativeDnsProbes.RunAsync(Enumerable.Range(0, entries.Length), async index => {
                var entry = entries[index];
                if (options.RestrictRemoteFetchesToOriginHost &&
                    Uri.TryCreate(entry.Location, UriKind.Absolute, out var entryUri) &&
                    !IsTrustedRemoteUri(entryUri, options)) {
                    return index;
                }
                probes[index] = await ProbeUrlAsync(client, entry.Location, options, cancellationToken).ConfigureAwait(false);
                return index;
            }, options.MaxUrlProbeParallelism, cancellationToken).ConfigureAwait(false);
        } finally {
            for (int index = 0; index < entries.Length; index++) {
                var probe = probes[index];
                if (probe != null) {
                    UrlProbes.Add(probe);
                    AddProbeAssessment(probe);
                } else if (options.RestrictRemoteFetchesToOriginHost &&
                    Uri.TryCreate(entries[index].Location, UriKind.Absolute, out var entryUri) &&
                    !IsTrustedRemoteUri(entryUri, options)) {
                    AddAssessment(AssessmentSeverity.Warning, SitemapCodes.UrlFetchFailed, "Skipped sitemap URL probe outside the analyzed origin host.", entries[index].Location);
                }
            }
        }
    }

    private async Task<SitemapUrlProbe> ProbeUrlAsync(HttpClient client, string url, SitemapAnalysisOptions options, CancellationToken cancellationToken) {
        var probe = new SitemapUrlProbe {
            Url = url
        };

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) {
            probe.Error = "Invalid URL.";
            return probe;
        }

        var response = await SendFollowingRedirectsAsync(client, uri, options, readBody: options.CheckCanonical, cancellationToken).ConfigureAwait(false);
        probe.StatusCode = response.StatusCode;
        probe.ContentType = response.ContentType;
        probe.FinalUrl = response.FinalUri?.AbsoluteUri;
        probe.Error = response.Error;
        probe.WasRedirected = response.WasRedirected;
        probe.RedirectLoop = response.RedirectLoop;
        probe.RedirectHopCount = response.RedirectChain.Count > 0 ? Math.Max(0, response.RedirectChain.Count - 1) : 0;
        foreach (var item in response.RedirectChain) {
            probe.RedirectChain.Add(item);
        }

        var status = response.StatusCode ?? 0;
        probe.Success = status >= 200 && status < 300 && !probe.RedirectLoop;
        if (probe.Success && options.CheckCanonical) {
            probe.NoIndex = HasNoIndex(response.Headers, response.Body);
            probe.CanonicalUrl = ExtractCanonical(response.FinalUri ?? uri, response.Body);
            if (!string.IsNullOrWhiteSpace(probe.CanonicalUrl) && response.FinalUri != null) {
                probe.CanonicalMismatch = !UrlsEqualWithoutFragment(probe.CanonicalUrl!, response.FinalUri.AbsoluteUri);
            }
        }

        return probe;
    }

    private void AddProbeAssessment(SitemapUrlProbe probe) {
        if (probe.RedirectLoop) {
            RedirectLoopCount++;
            AddAssessment(AssessmentSeverity.Error, SitemapCodes.UrlRedirectLoop, "Sitemap URL has a redirect loop.", probe.Url);
            return;
        }

        if (!probe.StatusCode.HasValue || probe.StatusCode.Value == 0) {
            AddAssessment(AssessmentSeverity.Warning, SitemapCodes.UrlFetchFailed, probe.Error ?? "Sitemap URL fetch failed.", probe.Url);
            return;
        }

        if (probe.StatusCode.Value >= 300 && probe.StatusCode.Value < 400) {
            AddAssessment(AssessmentSeverity.Warning, SitemapCodes.UrlFetchFailed, probe.Error ?? "Sitemap URL redirect could not be followed.", probe.Url);
            return;
        }

        if (probe.StatusCode.Value >= 500) {
            ServerErrorCount++;
            AddAssessment(AssessmentSeverity.Error, SitemapCodes.UrlServerError, "Sitemap URL returned HTTP " + probe.StatusCode.Value.ToString(CultureInfo.InvariantCulture) + ".", probe.Url);
        } else if (probe.StatusCode.Value == 401 || probe.StatusCode.Value == 403) {
            ClientErrorCount++;
            AddAssessment(AssessmentSeverity.Warning, SitemapCodes.UrlAccessForbidden, "Sitemap URL returned HTTP " + probe.StatusCode.Value.ToString(CultureInfo.InvariantCulture) + " to the unauthenticated probe. The page may still exist for browser sessions.", probe.Url);
        } else if (probe.StatusCode.Value >= 400) {
            ClientErrorCount++;
            AddAssessment(AssessmentSeverity.Error, SitemapCodes.UrlClientError, "Sitemap URL returned HTTP " + probe.StatusCode.Value.ToString(CultureInfo.InvariantCulture) + ".", probe.Url);
        } else if (probe.WasRedirected) {
            RedirectCount++;
            AddAssessment(AssessmentSeverity.Warning, SitemapCodes.UrlRedirect, "Sitemap URL redirects to " + (probe.FinalUrl ?? "another URL") + ".", probe.Url);
        } else {
            AddAssessment(AssessmentSeverity.Info, SitemapCodes.UrlOk, "Sitemap URL returned a successful response.", probe.Url);
        }

        if (probe.NoIndex) {
            NoIndexCount++;
            AddAssessment(AssessmentSeverity.Warning, SitemapCodes.UrlNoIndex, "Sitemap URL is marked noindex.", probe.Url);
        }

        if (probe.CanonicalMismatch) {
            CanonicalMismatchCount++;
            AddAssessment(AssessmentSeverity.Warning, SitemapCodes.CanonicalMismatch, "Sitemap URL canonicalizes to " + probe.CanonicalUrl + ".", probe.Url);
        }
    }

}
