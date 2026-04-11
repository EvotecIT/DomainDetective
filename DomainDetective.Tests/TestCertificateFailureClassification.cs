using System;
using System.Net.Sockets;

namespace DomainDetective.Tests;

public class TestCertificateFailureClassification {
    [Fact]
    public void PublicWrapperClassifiesExceptionsLikeInternalClassifier() {
        var exception = new SocketException((int)SocketError.HostNotFound);

        Assert.Equal(
            CertificateFailureClassifier.Classify(exception),
            CertificateFailureClassification.Classify(exception));
    }

    [Fact]
    public void ClassifiesUnauthenticatedSslContextAsTlsHandshakeFailure() {
        var exception = new InvalidOperationException(
            "This operation is only allowed using a successfully authenticated context.");

        Assert.Equal(
            CertificateFailureKind.TlsHandshake,
            CertificateFailureClassification.Classify(exception));
    }

    [Fact]
    public void PublicWrapperClassifiesPersistedReasonsLikeInternalClassifier() {
        const string reason = "FailureKind:NameResolution SocketError:HostNotFound";

        Assert.Equal(
            CertificateFailureClassifier.ClassifyFailureReason(reason),
            CertificateFailureClassification.ClassifyFailureReason(reason));
    }

    [Fact]
    public void ClassifiesUnauthenticatedSslContextReasonAsTlsHandshakeFailure() {
        const string reason = "FailureKind:Unknown InvalidOperationException: This operation is only allowed using a successfully authenticated context.";

        Assert.Equal(
            CertificateFailureKind.TlsHandshake,
            CertificateFailureClassification.ClassifyFailureReason(reason));
    }

    [Fact]
    public void PublicWrapperExposesReuseAndMarkerHelpers() {
        Assert.Equal(
            CertificateFailureClassifier.IsStableForSnapshotReuse(CertificateFailureKind.Timeout),
            CertificateFailureClassification.IsStableForSnapshotReuse(CertificateFailureKind.Timeout));
        Assert.Equal(
            CertificateFailureClassifier.ToMarker(CertificateFailureKind.Timeout),
            CertificateFailureClassification.ToMarker(CertificateFailureKind.Timeout));
    }
}
