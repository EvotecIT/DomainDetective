using System;
using System.Net.Sockets;

namespace DomainDetective.Tests;

public class TestTlsFailureClassification {
    [Fact]
    public void PublicWrapperClassifiesSocketException() {
        var exception = new SocketException((int)SocketError.HostNotFound);

        Assert.Equal(
            CertificateFailureKind.NameResolution,
            TlsFailureClassification.Classify(exception));
    }

    [Fact]
    public void ClassifiesUnauthenticatedSslContextAsTlsHandshakeFailure() {
        var exception = new InvalidOperationException(
            "This operation is only allowed using a successfully authenticated context.");

        Assert.Equal(
            CertificateFailureKind.TlsHandshake,
            TlsFailureClassification.Classify(exception));
    }

    [Fact]
    public void PublicWrapperClassifiesPersistedReason() {
        const string reason = "FailureKind:NameResolution SocketError:HostNotFound";

        Assert.Equal(
            CertificateFailureKind.NameResolution,
            TlsFailureClassification.ClassifyFailureReason(reason));
    }

    [Fact]
    public void ClassifiesUnauthenticatedSslContextReasonAsTlsHandshakeFailure() {
        const string reason = "FailureKind:Unknown InvalidOperationException: This operation is only allowed using a successfully authenticated context.";

        Assert.Equal(
            CertificateFailureKind.TlsHandshake,
            TlsFailureClassification.ClassifyFailureReason(reason));
    }

    [Fact]
    public void ClassifiesInvalidOperationReasonWithoutSslContextMessageAsUnknown() {
        const string reason = "FailureKind:Unknown InvalidOperationException: Another invalid operation.";

        Assert.Equal(
            CertificateFailureKind.Unknown,
            TlsFailureClassification.ClassifyFailureReason(reason));
    }

    [Fact]
    public void PublicWrapperExposesReuseHelper() {
        Assert.True(TlsFailureClassification.IsStableForSnapshotReuse(CertificateFailureKind.Timeout));
    }

    [Fact]
    public void PublicWrapperExposesMarkerHelper() {
        Assert.Equal("FailureKind:Timeout", TlsFailureClassification.ToMarker(CertificateFailureKind.Timeout));
    }
}
