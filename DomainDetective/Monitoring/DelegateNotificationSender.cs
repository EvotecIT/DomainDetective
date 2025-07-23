using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Monitoring;

internal sealed class DelegateNotificationSender : INotificationSender {
    private readonly Func<string, CancellationToken, Task> _handler;

    public DelegateNotificationSender(Func<string, CancellationToken, Task> handler) {
        _handler = handler ?? throw new ArgumentNullException(nameof(handler));
    }

    public Task SendAsync(string message, CancellationToken ct = default) {
        return _handler(message, ct);
    }
}