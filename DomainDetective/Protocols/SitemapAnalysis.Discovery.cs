using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class SitemapAnalysis {
    private async Task ProcessSitemapQueueAsync(HttpClient client, IEnumerable<Uri> seeds,
        HashSet<string> seenDocs, HashSet<string> seenFinalDocs, SitemapAnalysisOptions options, CancellationToken cancellationToken) {
        var pending = new Queue<Uri>(seeds);
        int documentLimit = Math.Max(1, options.MaxSitemapDocuments);
        while (pending.Count > 0 && Documents.Count < documentLimit) {
            cancellationToken.ThrowIfCancellationRequested();
            var batch = new List<Uri>();
            int capacity = Math.Min(4, documentLimit - Documents.Count);
            while (pending.Count > 0 && batch.Count < capacity) {
                var uri = pending.Dequeue();
                if (seenDocs.Add(uri.AbsoluteUri)) { batch.Add(uri); }
            }

            // Only downloads overlap. Parsing and evidence publication retain BFS
            // order, deterministic limits and redirect-target deduplication.
            var downloads = new List<Task<SitemapHttpResult>>(batch.Count);
            foreach (var uri in batch) {
                downloads.Add(SendFollowingRedirectsAsync(client, uri, options, true, cancellationToken,
                    Math.Max(1024, options.MaxSitemapBodyCharacters)));
            }
            var responses = await Task.WhenAll(downloads).ConfigureAwait(false);
            for (int index = 0; index < batch.Count; index++) {
                var uri = batch[index];
                var parsed = await FetchAndParseSitemapAsync(client, uri, seenFinalDocs, options,
                    cancellationToken, responses[index]).ConfigureAwait(false);
                if (parsed.Document != null) { Documents.Add(parsed.Document); }
                foreach (var nested in parsed.NestedSitemaps) {
                    int reserved = batch.Count - index - 1;
                    if (Documents.Count + pending.Count + reserved >= documentLimit) {
                        AddAssessment(AssessmentSeverity.Warning, SitemapCodes.LimitReached,
                            "Sitemap document limit reached before all sitemapindex entries were fetched.", uri.AbsoluteUri);
                        break;
                    }
                    if (!IsTrustedRemoteUri(nested, options)) {
                        AddAssessment(AssessmentSeverity.Warning, SitemapCodes.CrossHostSitemap,
                            "Skipped sitemap index entry outside the analyzed origin host: " + nested.Host + ".", nested.AbsoluteUri);
                        continue;
                    }
                    pending.Enqueue(nested);
                }
                if (Entries.Count >= Math.Max(1, options.MaxEntries)) {
                    AddAssessment(AssessmentSeverity.Warning, SitemapCodes.LimitReached,
                        "Sitemap URL entry limit reached before all urlset entries were parsed.", uri.AbsoluteUri);
                    return;
                }
            }
        }
    }
}
