using System;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests;

public class TestCancellationWait {
    [Fact]
    public async Task PortableWaitPreservesCompletionAndFaults() {
        using var cancellation = new CancellationTokenSource();
        var pending = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        Task wait = CancellationExtensions.WaitForCompletionAsync(pending.Task, cancellation.Token);
        Assert.False(wait.IsCompleted);
        pending.SetResult(true);
        await wait;
        cancellation.Cancel();
        await CancellationExtensions.WaitForCompletionAsync(Task.CompletedTask, cancellation.Token);
        var failure = new InvalidOperationException("provider failed");
        Assert.Same(failure, await Record.ExceptionAsync(() => CancellationExtensions.WaitForCompletionAsync(Task.FromException(failure), CancellationToken.None)));
    }

    [Fact]
    public async Task PortableWaitCancelsWithoutOwningTheProviderTask() {
        using var cancellation = new CancellationTokenSource();
        var pending = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        Task wait = CancellationExtensions.WaitForCompletionAsync(pending.Task, cancellation.Token);
        cancellation.Cancel();
        var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => wait);
        Assert.Equal(cancellation.Token, error.CancellationToken);
        Assert.False(pending.Task.IsCompleted);
        pending.SetException(new InvalidOperationException("late provider fault"));
    }
}
