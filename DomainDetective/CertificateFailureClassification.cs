using System;

namespace DomainDetective;

/// <summary>
/// Public helpers for classifying certificate and TLS probe failures.
/// </summary>
public static class CertificateFailureClassification {
    /// <summary>
    /// Classifies an exception thrown while collecting certificate or TLS evidence.
    /// </summary>
    /// <param name="exception">The exception to classify.</param>
    /// <returns>The normalized certificate failure kind.</returns>
    public static CertificateFailureKind Classify(Exception? exception)
        => CertificateFailureClassifier.Classify(exception);

    /// <summary>
    /// Classifies a previously persisted failure reason.
    /// </summary>
    /// <param name="failureReason">The persisted failure reason text.</param>
    /// <returns>The normalized certificate failure kind.</returns>
    public static CertificateFailureKind ClassifyFailureReason(string? failureReason)
        => CertificateFailureClassifier.ClassifyFailureReason(failureReason);

    /// <summary>
    /// Determines whether the failure kind is stable enough for conservative reuse/backoff.
    /// </summary>
    /// <param name="failureKind">The normalized failure kind.</param>
    /// <returns><c>true</c> when the failure kind is considered stable.</returns>
    public static bool IsStableForSnapshotReuse(CertificateFailureKind failureKind)
        => CertificateFailureClassifier.IsStableForSnapshotReuse(failureKind);

    /// <summary>
    /// Formats the normalized failure kind as a durable marker.
    /// </summary>
    /// <param name="failureKind">The normalized failure kind.</param>
    /// <returns>A durable marker string.</returns>
    public static string ToMarker(CertificateFailureKind failureKind)
        => CertificateFailureClassifier.ToMarker(failureKind);
}
