using System;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Provides normalized failure classification for certificate probing.
/// </summary>
internal static class CertificateFailureClassifier {
    // TODO(net-compat): verified on .NET 8/10; revisit if SslStream changes this runtime message.
    // SslStream source/message: "This operation is only allowed using a successfully authenticated context."
    // Matched via substring because SslStream exposes no typed discriminator for this state.
    private const string SslStreamUnauthenticatedMessage = "successfully authenticated context";

    public static CertificateFailureKind Classify(Exception? exception) {
        if (exception == null) {
            return CertificateFailureKind.None;
        }

        CertificateFailureKind fallback = CertificateFailureKind.Unknown;
        Exception? current = exception;
        while (current != null) {
            if (current is SocketException socketException) {
                var socketFailureKind = Map(socketException.SocketErrorCode);
                if (socketFailureKind != CertificateFailureKind.Unknown) {
                    return socketFailureKind;
                }

                fallback = Promote(fallback, CertificateFailureKind.ConnectionError);
            }

#if NET8_0_OR_GREATER
            if (current is HttpRequestException httpRequestException) {
                var httpFailureKind = Map(httpRequestException);
                if (httpFailureKind != CertificateFailureKind.Unknown) {
                    return httpFailureKind;
                }

                fallback = Promote(fallback, CertificateFailureKind.ConnectionError);
            }
#endif

            if (current is AuthenticationException) {
                return CertificateFailureKind.TlsHandshake;
            }

            if (current is InvalidOperationException invalidOperationException &&
                IsSslStreamAuthenticationStateFailure(invalidOperationException)) {
                return CertificateFailureKind.TlsHandshake;
            }

            if (current is TimeoutException) {
                return CertificateFailureKind.Timeout;
            }

            if (current is TaskCanceledException ||
                current is OperationCanceledException) {
                fallback = Promote(fallback, CertificateFailureKind.Cancelled);
            }

            current = current.InnerException;
        }

        return fallback;
    }

    public static CertificateFailureKind ClassifyFailureReason(string? failureReason) {
        if (string.IsNullOrWhiteSpace(failureReason)) {
            return CertificateFailureKind.None;
        }

        string normalized = failureReason!.Trim();

        if (Contains(normalized, "FailureKind:NameResolution") ||
            Contains(normalized, "HttpRequestError:NameResolutionError") ||
            Contains(normalized, "SocketError:HostNotFound") ||
            Contains(normalized, "SocketError:NoData") ||
            Contains(normalized, "SocketError:TryAgain") ||
            Contains(normalized, "No such host is known")) {
            return CertificateFailureKind.NameResolution;
        }

        if (Contains(normalized, "FailureKind:ConnectionRefused") ||
            Contains(normalized, "SocketError:ConnectionRefused") ||
            Contains(normalized, "actively refused")) {
            return CertificateFailureKind.ConnectionRefused;
        }

        if (Contains(normalized, "FailureKind:ConnectionReset") ||
            Contains(normalized, "SocketError:ConnectionReset") ||
            Contains(normalized, "forcibly closed by the remote host")) {
            return CertificateFailureKind.ConnectionReset;
        }

        if (Contains(normalized, "FailureKind:ConnectionAborted") ||
            Contains(normalized, "SocketError:ConnectionAborted")) {
            return CertificateFailureKind.ConnectionAborted;
        }

        if (Contains(normalized, "FailureKind:NetworkUnreachable") ||
            Contains(normalized, "SocketError:HostUnreachable") ||
            Contains(normalized, "SocketError:NetworkUnreachable") ||
            Contains(normalized, "SocketError:NetworkDown")) {
            return CertificateFailureKind.NetworkUnreachable;
        }

        if (Contains(normalized, "FailureKind:TlsHandshake") ||
            Contains(normalized, "HttpRequestError:SecureConnectionError") ||
            (Contains(normalized, nameof(InvalidOperationException)) &&
             Contains(normalized, SslStreamUnauthenticatedMessage)) ||
            Contains(normalized, "TLS Handshake Failure")) {
            return CertificateFailureKind.TlsHandshake;
        }

        if (Contains(normalized, "FailureKind:Timeout") ||
            Contains(normalized, "SocketError:TimedOut")) {
            return CertificateFailureKind.Timeout;
        }

        if (Contains(normalized, "FailureKind:Cancelled")) {
            return CertificateFailureKind.Cancelled;
        }

        if (Contains(normalized, "FailureKind:ConnectionError") ||
            Contains(normalized, "HttpRequestError:ConnectionError")) {
            return CertificateFailureKind.ConnectionError;
        }

        return CertificateFailureKind.Unknown;
    }

    public static bool IsStableForSnapshotReuse(CertificateFailureKind failureKind) {
        return failureKind == CertificateFailureKind.Timeout ||
               failureKind == CertificateFailureKind.TlsHandshake ||
               failureKind == CertificateFailureKind.NameResolution ||
               failureKind == CertificateFailureKind.ConnectionRefused ||
               failureKind == CertificateFailureKind.ConnectionReset ||
               failureKind == CertificateFailureKind.ConnectionAborted ||
               failureKind == CertificateFailureKind.NetworkUnreachable ||
               failureKind == CertificateFailureKind.ConnectionError;
    }

    public static string ToMarker(CertificateFailureKind failureKind) {
        return "FailureKind:" + failureKind;
    }

    private static bool Contains(string value, string pattern) {
        return value.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private static bool IsSslStreamAuthenticationStateFailure(InvalidOperationException exception) {
        // Prefer typed AuthenticationException and transport errors above; this is a best-effort
        // fallback for the .NET message and persisted failure-reason text.
        return exception.Message.IndexOf(SslStreamUnauthenticatedMessage, StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private static CertificateFailureKind Promote(CertificateFailureKind current, CertificateFailureKind candidate) {
        return current == CertificateFailureKind.None || current == CertificateFailureKind.Unknown
            ? candidate
            : current;
    }

    private static CertificateFailureKind Map(SocketError socketError) {
        return socketError switch {
            SocketError.HostNotFound => CertificateFailureKind.NameResolution,
            SocketError.NoData => CertificateFailureKind.NameResolution,
            SocketError.TryAgain => CertificateFailureKind.NameResolution,
            SocketError.TimedOut => CertificateFailureKind.Timeout,
            SocketError.ConnectionRefused => CertificateFailureKind.ConnectionRefused,
            SocketError.ConnectionReset => CertificateFailureKind.ConnectionReset,
            SocketError.ConnectionAborted => CertificateFailureKind.ConnectionAborted,
            SocketError.HostUnreachable => CertificateFailureKind.NetworkUnreachable,
            SocketError.NetworkUnreachable => CertificateFailureKind.NetworkUnreachable,
            SocketError.NetworkDown => CertificateFailureKind.NetworkUnreachable,
            _ => CertificateFailureKind.Unknown
        };
    }

#if NET8_0_OR_GREATER
    private static CertificateFailureKind Map(HttpRequestException httpRequestException) {
        return httpRequestException.HttpRequestError switch {
            HttpRequestError.NameResolutionError => CertificateFailureKind.NameResolution,
            HttpRequestError.SecureConnectionError => CertificateFailureKind.TlsHandshake,
            HttpRequestError.ConnectionError => CertificateFailureKind.ConnectionError,
            _ => CertificateFailureKind.Unknown
        };
    }
#endif
}
