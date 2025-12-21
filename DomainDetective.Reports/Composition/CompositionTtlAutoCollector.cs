using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective;

namespace DomainDetective.Reports;

internal static class CompositionTtlAutoCollector
{
    public static async Task<IReadOnlyList<object>> AddMissingTtlAsync(
        IReadOnlyList<object> items,
        CompositionExecutionOptions? options,
        InternalLogger? logger,
        CancellationToken cancellationToken)
    {
        if (items == null || items.Count == 0)
        {
            return Array.Empty<object>();
        }

        var dkimSubjects = new HashSet<string>(
            items.OfType<DomainDetective.Views.DkimRecordInfo>()
                .Select(x => x?.Subject)
                .Where(s => !string.IsNullOrWhiteSpace(s))!
                .Select(s => s!),
            StringComparer.OrdinalIgnoreCase);
        if (dkimSubjects.Count == 0)
        {
            return items;
        }

        var ttlPresent = new HashSet<string>(
            items.OfType<DomainDetective.Views.TtlInfo>()
                .Select(x => x?.Subject)
                .Where(s => !string.IsNullOrWhiteSpace(s))!
                .Select(s => s!),
            StringComparer.OrdinalIgnoreCase);
        var need = dkimSubjects.Except(ttlPresent, StringComparer.OrdinalIgnoreCase).ToList();
        if (need.Count == 0)
        {
            return items;
        }

        logger?.WriteVerbose("Export-DDSecurityReport: adding TTL analysis for {0} domain(s) to populate DKIM TTLs.", need.Count);

        var exec = options ?? new CompositionExecutionOptions();
        var maxParallel = exec.GetEffectiveMaxParallelism();
        if (maxParallel < 1)
        {
            maxParallel = 1;
        }

        var results = new ConcurrentBag<object>();
        using var gate = new SemaphoreSlim(maxParallel, maxParallel);
        var tasks = new List<Task>(need.Count);

        foreach (var domain in need)
        {
            tasks.Add(Task.Run(async () =>
            {
                await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    logger?.WriteVerbose("Export-DDSecurityReport: TTL analysis for '{0}' started.", domain);

                    var analysis = new DomainDetective.DnsTtlAnalysis();
                    var selectors = items.OfType<DomainDetective.Views.DkimRecordInfo>()
                        .Where(r => string.Equals(r?.Subject, domain, StringComparison.OrdinalIgnoreCase))
                        .Select(r => r?.Selector)
                        .Where(s => !string.IsNullOrWhiteSpace(s))
                        .Select(s => s!)
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToList();
                    if (selectors.Count > 0)
                    {
                        analysis.DkimSelectors = selectors;
                    }

                    var analysisLogger = logger ?? new InternalLogger();
                    await analysis.Analyze(domain, analysisLogger).ConfigureAwait(false);
                    var ttlView = DomainDetective.Views.Converters.Convert(analysis);
                    if (ttlView != null)
                    {
                        results.Add(ttlView);
                    }

                    logger?.WriteVerbose("Export-DDSecurityReport: TTL analysis for '{0}' completed.", domain);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    logger?.WriteVerbose("TTL analysis for '{0}' failed: {1}", domain, ex.Message);
                }
                finally
                {
                    gate.Release();
                }
            }, cancellationToken));
        }

        try
        {
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }

        if (results.IsEmpty)
        {
            return items;
        }

        var combined = new List<object>(items.Count + results.Count);
        combined.AddRange(items);
        combined.AddRange(results);
        return combined;
    }
}
