using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

internal sealed class HttpStubMessageHandler : HttpMessageHandler {
    private readonly Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> _handler;

    public HttpStubMessageHandler(Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> handler) {
        _handler = handler ?? throw new ArgumentNullException(nameof(handler));
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) {
        if (request == null) {
            throw new ArgumentNullException(nameof(request));
        }

        var response = _handler(request, cancellationToken);
        return Task.FromResult(response);
    }
}
