using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Monitoring;
using Xunit;

namespace DomainDetective.Tests;

public sealed class TestUptimeMonitorLifecycle {
    [Fact]
    public async Task StopCancelsAnActiveCallback() {
        using var server = new LoopbackServer();
        var entered = new TaskCompletionSource<CancellationToken>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var monitor = new UptimeMonitor(new[] { server.Url }, TimeSpan.FromHours(1)) {
            OnAny = async (_, _, token) => {
                entered.TrySetResult(token);
                await release.Task.ConfigureAwait(false);
            }
        };

        try {
            monitor.Start();
            CancellationToken callbackToken = await WithinAsync(entered.Task);
            monitor.Stop();
            Assert.True(callbackToken.IsCancellationRequested);
        } finally {
            release.TrySetResult(true);
            monitor.Stop();
        }
    }

    [Fact]
    public async Task ASlowCallbackDoesNotAllowOverlappingTicks() {
        using var server = new LoopbackServer();
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int callbackCount = 0;
        using var monitor = new UptimeMonitor(new[] { server.Url }, TimeSpan.FromMilliseconds(30)) {
            OnAny = async (_, _, _) => {
                Interlocked.Increment(ref callbackCount);
                entered.TrySetResult(true);
                await release.Task.ConfigureAwait(false);
            }
        };

        try {
            monitor.Start();
            await WithinAsync(entered.Task);
            await Task.Delay(TimeSpan.FromMilliseconds(300));
            Assert.Equal(1, Volatile.Read(ref callbackCount));
        } finally {
            release.TrySetResult(true);
            monitor.Stop();
        }
    }

    [Fact]
    public async Task StartingTwiceDoesNotCreateAnotherImmediateProbe() {
        using var server = new LoopbackServer();
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int callbackCount = 0;
        using var monitor = new UptimeMonitor(new[] { server.Url }, TimeSpan.FromHours(1)) {
            OnAny = (_, _, _) => {
                Interlocked.Increment(ref callbackCount);
                entered.TrySetResult(true);
                return Task.CompletedTask;
            }
        };

        try {
            monitor.Start();
            await WithinAsync(entered.Task);
            monitor.Start();
            await Task.Delay(TimeSpan.FromMilliseconds(300));
            Assert.Equal(1, Volatile.Read(ref callbackCount));
        } finally {
            monitor.Stop();
        }
    }

    [Fact]
    public async Task StopAsyncWaitsForAnActiveCallback() {
        using var server = new LoopbackServer();
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var monitor = new UptimeMonitor(new[] { server.Url }, TimeSpan.FromHours(1)) {
            OnAny = async (_, _, _) => {
                entered.TrySetResult(true);
                await release.Task;
            }
        };

        try {
            monitor.Start();
            await WithinAsync(entered.Task);
            Task stopping = monitor.StopAsync();
            Assert.False(stopping.IsCompleted);
            release.TrySetResult(true);
            await WithinAsync(stopping);
        } finally {
            release.TrySetResult(true);
            await monitor.StopAsync();
        }
    }

    [Fact]
    public async Task CallbackCanRequestItsOwnStop() {
        using var server = new LoopbackServer();
        var stopped = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        UptimeMonitor? monitor = null;
        monitor = new UptimeMonitor(new[] { server.Url }, TimeSpan.FromHours(1)) {
            OnAny = (_, _, _) => {
                monitor!.Stop();
                stopped.TrySetResult(true);
                return Task.CompletedTask;
            }
        };

        using (monitor) {
            monitor.Start();
            await WithinAsync(stopped.Task);
            await monitor.StopAsync();
        }
    }

    [Fact]
    public async Task DetachedChildOfActiveCallbackMustWaitForCallbackToDrain() {
        using var server = new LoopbackServer();
        var childMayStop = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var childReady = new TaskCompletionSource<Task>(TaskCreationOptions.RunContinuationsAsynchronously);
        var childStopping = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseCallback = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        UptimeMonitor? monitor = null;
        monitor = new UptimeMonitor(new[] { server.Url }, TimeSpan.FromHours(1)) {
            OnAny = async (_, _, _) => {
                Task child = Task.Run(async () => {
                    await childMayStop.Task;
                    childStopping.TrySetResult(true);
                    await monitor!.StopAsync();
                });
                childReady.TrySetResult(child);
                await releaseCallback.Task;
            }
        };

        using (monitor) {
            try {
                monitor.Start();
                Task child = await WithinAsync(childReady.Task);
                childMayStop.TrySetResult(true);
                await WithinAsync(childStopping.Task);
                await Task.Delay(TimeSpan.FromMilliseconds(100));
                Assert.False(child.IsCompleted);
                releaseCallback.TrySetResult(true);
                await WithinAsync(child);
            } finally {
                childMayStop.TrySetResult(true);
                releaseCallback.TrySetResult(true);
                await monitor.StopAsync();
            }
        }
    }

    [Fact]
    public async Task ChildTaskAfterCallbackMustWaitForTheNextTickToDrain() {
        using var server = new LoopbackServer();
        var childMayStop = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var childReady = new TaskCompletionSource<Task>(TaskCreationOptions.RunContinuationsAsynchronously);
        var childStopping = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var secondEntered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseSecond = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int callbackCount = 0;
        UptimeMonitor? monitor = null;
        monitor = new UptimeMonitor(new[] { server.Url }, TimeSpan.FromMilliseconds(30)) {
            OnAny = async (_, _, _) => {
                if (Interlocked.Increment(ref callbackCount) == 1) {
                    Task child = Task.Run(async () => {
                        await childMayStop.Task;
                        childStopping.TrySetResult(true);
                        await monitor!.StopAsync();
                    });
                    childReady.TrySetResult(child);
                } else {
                    secondEntered.TrySetResult(true);
                    await releaseSecond.Task;
                }
            }
        };

        using (monitor) {
            try {
                monitor.Start();
                Task child = await WithinAsync(childReady.Task);
                await WithinAsync(secondEntered.Task);
                childMayStop.TrySetResult(true);
                await WithinAsync(childStopping.Task);
                await Task.Delay(TimeSpan.FromMilliseconds(100));
                Assert.False(child.IsCompleted);
                releaseSecond.TrySetResult(true);
                await WithinAsync(child);
            } finally {
                childMayStop.TrySetResult(true);
                releaseSecond.TrySetResult(true);
                await monitor.StopAsync();
            }
        }
    }

    [Fact]
    public async Task ChildTaskFromEarlierCallbackMustWaitForLaterCallbackToDrain() {
        using var server = new LoopbackServer();
        var childMayStop = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var childReady = new TaskCompletionSource<Task>(TaskCreationOptions.RunContinuationsAsynchronously);
        var childStopping = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var onAnyEntered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseOnAny = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        UptimeMonitor? monitor = null;
        monitor = new UptimeMonitor(new[] { server.Url }, TimeSpan.FromHours(1)) {
            MaxStatusCodeOk = 199,
            OnDown = (_, _) => {
                Task child = Task.Run(async () => {
                    await childMayStop.Task;
                    childStopping.TrySetResult(true);
                    await monitor!.StopAsync();
                });
                childReady.TrySetResult(child);
                return Task.CompletedTask;
            },
            OnAny = async (_, _, _) => {
                onAnyEntered.TrySetResult(true);
                await releaseOnAny.Task;
            }
        };

        using (monitor) {
            try {
                monitor.Start();
                Task child = await WithinAsync(childReady.Task);
                await WithinAsync(onAnyEntered.Task);
                childMayStop.TrySetResult(true);
                await WithinAsync(childStopping.Task);
                await Task.Delay(TimeSpan.FromMilliseconds(100));
                Assert.False(child.IsCompleted);
                releaseOnAny.TrySetResult(true);
                await WithinAsync(child);
            } finally {
                childMayStop.TrySetResult(true);
                releaseOnAny.TrySetResult(true);
                await monitor.StopAsync();
            }
        }
    }

    [Fact]
    public async Task LongIntervalDoesNotFaultTheBackgroundLoop() {
        using var server = new LoopbackServer();
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var monitor = new UptimeMonitor(new[] { server.Url }, TimeSpan.FromDays(30)) {
            OnAny = (_, _, _) => {
                entered.TrySetResult(true);
                return Task.CompletedTask;
            }
        };

        monitor.Start();
        await WithinAsync(entered.Task);
        await Task.Delay(TimeSpan.FromMilliseconds(100));
        await WithinAsync(monitor.StopAsync());
    }

    private static async Task WithinAsync(Task task) {
        Task completed = await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(5))).ConfigureAwait(false);
        Assert.Same(task, completed);
        await task.ConfigureAwait(false);
    }

    private static async Task<T> WithinAsync<T>(Task<T> task) {
        Task completed = await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(5))).ConfigureAwait(false);
        Assert.Same(task, completed);
        return await task.ConfigureAwait(false);
    }

    private sealed class LoopbackServer : IDisposable {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly Task _server;
        private int _stopping;

        public string Url { get; }

        public LoopbackServer() {
            _listener.Start();
            Url = $"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}/";
            _server = ServeAsync();
        }

        private async Task ServeAsync() {
            byte[] reply = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            try {
                while (true) {
                    using TcpClient client = await _listener.AcceptTcpClientAsync().ConfigureAwait(false);
                    using NetworkStream stream = client.GetStream();
                    byte[] request = new byte[1024];
                    if (await stream.ReadAsync(request, 0, request.Length).ConfigureAwait(false) > 0) {
                        await stream.WriteAsync(reply, 0, reply.Length).ConfigureAwait(false);
                    }
                }
            } catch (SocketException) {
                // Closing the listener ends the test server.
            } catch (ObjectDisposedException) {
                // Closing the listener ends the test server.
            } catch (InvalidOperationException) when (Volatile.Read(ref _stopping) != 0) {
                // .NET Framework can report a stopped listener as not listening.
            }
        }

        public void Dispose() {
            Interlocked.Exchange(ref _stopping, 1);
            _listener.Stop();
            _server.GetAwaiter().GetResult();
        }
    }
}
