using System.IO;
using MailKit;

namespace DomainDetective.TimeSeries;

/// <summary>Shared defaults for distinct report acquisition and expansion boundaries.</summary>
internal static class ReportReadLimits {
    internal const long DefaultAttachmentBytes = 50L * 1024 * 1024;
    internal const long DefaultUncompressedBytes = 50L * 1024 * 1024;
    internal const long DefaultMessageBytes = 100L * 1024 * 1024;
}

/// <summary>Rejects an excessive literal during download, before MIME materialization.</summary>
internal sealed class MessageReadLimit : ITransferProgress {
    private readonly long _maximum;
    internal MessageReadLimit(long maximum) => _maximum = maximum;
    public void Report(long bytesTransferred) => Check(bytesTransferred);
    public void Report(long bytesTransferred, long totalSize) {
        Check(totalSize);
        Check(bytesTransferred);
    }
    private void Check(long size) {
        if (_maximum > 0 && size > _maximum) {
            throw new MessageReadLimitException($"IMAP message exceeds max size {_maximum} bytes.");
        }
    }
}

/// <summary>An interrupted literal cannot be followed by another command on that connection.</summary>
internal sealed class MessageReadLimitException : IOException {
    internal MessageReadLimitException(string message) : base(message) { }
}
