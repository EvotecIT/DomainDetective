using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective;

namespace DomainDetective.Reports;

public static class CompositionWorkExecutor
{
    public static async Task<IReadOnlyList<TResult>> ExecuteAsync<TPayload, TResult>(
        CompositionWorkPlan<TPayload> plan,
        Func<TPayload, CancellationToken, Task<TResult>> executeAsync,
        CompositionExecutionOptions? options = null,
        InternalLogger? logger = null,
        Func<TPayload, string?>? labelSelector = null,
        CancellationToken cancellationToken = default)
    {
        if (plan == null)
        {
            throw new ArgumentNullException(nameof(plan));
        }
        if (executeAsync == null)
        {
            throw new ArgumentNullException(nameof(executeAsync));
        }

        var items = plan.Items ?? Array.Empty<TPayload>();
        if (items.Count == 0)
        {
            return Array.Empty<TResult>();
        }

        var exec = options ?? new CompositionExecutionOptions();
        if (!exec.EnableParallelism || items.Count == 1)
        {
            var results = new TResult[items.Count];
            for (var i = 0; i < items.Count; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                results[i] = await ExecuteItemAsync(items[i], executeAsync, logger, labelSelector, cancellationToken).ConfigureAwait(false);
            }
            return results;
        }

        var throttle = exec.GetEffectiveMaxParallelism();
        if (throttle < 1)
        {
            throttle = 1;
        }

        using var gate = new SemaphoreSlim(throttle, throttle);
        var tasks = new Task<TResult>[items.Count];
        for (var i = 0; i < items.Count; i++)
        {
            var local = items[i];
            tasks[i] = Task.Run(async () =>
            {
                await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    return await ExecuteItemAsync(local, executeAsync, logger, labelSelector, cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    gate.Release();
                }
            }, cancellationToken);
        }

        try
        {
            return await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (AggregateException ex)
        {
            var cancelled = ex.Flatten().InnerExceptions.FirstOrDefault(e => e is OperationCanceledException);
            if (cancelled != null)
            {
                throw cancelled;
            }
            throw;
        }
    }

    private static async Task<TResult> ExecuteItemAsync<TPayload, TResult>(
        TPayload item,
        Func<TPayload, CancellationToken, Task<TResult>> executeAsync,
        InternalLogger? logger,
        Func<TPayload, string?>? labelSelector,
        CancellationToken cancellationToken)
    {
        string? label = null;
        if (labelSelector != null)
        {
            label = labelSelector(item);
        }

        Stopwatch? sw = null;
        if (logger != null && !string.IsNullOrWhiteSpace(label))
        {
            logger.WriteVerbose("Starting item '{0}'.", label);
            sw = Stopwatch.StartNew();
        }

        try
        {
            return await executeAsync(item, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (sw != null)
            {
                sw.Stop();
                logger?.WriteVerbose("Completed item '{0}' in {1} ms.", label, sw.ElapsedMilliseconds);
            }
        }
    }
}
