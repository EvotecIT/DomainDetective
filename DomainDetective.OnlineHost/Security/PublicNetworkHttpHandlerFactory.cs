using System.Net;
using System.Net.Sockets;
using DomainDetective.Security;

/// <summary>Creates HTTP handlers that resolve, validate, and connect directly to public addresses.</summary>
public sealed class PublicNetworkHttpHandlerFactory {
    private readonly PublicNetworkTargetValidator _validator;

    /// <summary>Creates the factory.</summary>
    public PublicNetworkHttpHandlerFactory(PublicNetworkTargetValidator validator) {
        _validator = validator;
    }

    /// <summary>Creates a handler with redirects disabled and proxy bypass prevented.</summary>
    public HttpMessageHandler Create() {
        return new SocketsHttpHandler {
            AllowAutoRedirect = false,
            UseProxy = false,
            ConnectCallback = ConnectAsync
        };
    }

    /// <summary>Resolves a host and returns only when all addresses are publicly routable.</summary>
    public async Task<IReadOnlyList<IPAddress>> ResolvePublicAddressesAsync(string host, CancellationToken cancellationToken) {
        var validation = await _validator.ValidateAsync(host, cancellationToken).ConfigureAwait(false);
        if (!validation.IsAllowed) {
            throw new HttpRequestException(validation.Error ?? "The outbound target is not publicly routable.");
        }
        return validation.Addresses;
    }

    private async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, CancellationToken cancellationToken) {
        var validation = await _validator.ValidateAsync(context.DnsEndPoint.Host, cancellationToken).ConfigureAwait(false);
        if (!validation.IsAllowed) {
            throw new HttpRequestException(validation.Error ?? "The outbound target is not publicly routable.");
        }

        Exception? lastError = null;
        foreach (var address in validation.Addresses) {
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try {
                await socket.ConnectAsync(new IPEndPoint(address, context.DnsEndPoint.Port), cancellationToken).ConfigureAwait(false);
                return new NetworkStream(socket, ownsSocket: true);
            } catch (Exception ex) when (ex is not OperationCanceledException) {
                lastError = ex;
                socket.Dispose();
            }
        }

        throw new HttpRequestException("No validated public address accepted the connection.", lastError);
    }
}
