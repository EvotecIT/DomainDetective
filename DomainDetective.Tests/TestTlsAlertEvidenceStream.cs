using DomainDetective.Helpers;
using System.IO;

namespace DomainDetective.Tests;

public class TestTlsAlertEvidenceStream {
    public static IEnumerable<object[]> Frames() {
        var cases = new[] {
            (Frame: new byte[] { 21, 3, 3, 0, 2, 2, 70 }, Rejected: true),
            (Frame: Array.Empty<byte>(), Rejected: false),
            (Frame: new byte[] { 21, 3, 3, 0, 2, 2, 40 }, Rejected: false),
            (Frame: new byte[] { 21, 3, 3, 0, 2, 1, 70 }, Rejected: false),
            (Frame: new byte[] { 22, 3, 3, 0, 2, 2, 70 }, Rejected: false),
            (Frame: new byte[] { 21, 3, 3, 0, 3, 2, 70 }, Rejected: false),
            (Frame: new byte[] { 21, 3, 3, 0, 2, 2 }, Rejected: false),
            (Frame: new byte[] { 22, 3, 3, 0, 2, 2, 70, 21, 3, 3, 0, 2, 2, 70 }, Rejected: false)
        };
        foreach (var item in cases) {
            yield return new object[] { item.Frame, item.Rejected, false };
            yield return new object[] { item.Frame, item.Rejected, true };
        }
    }

    [Theory]
    [MemberData(nameof(Frames))]
    public async Task OnlyAnExplicitRemoteVersionAlertIsDefinitive(byte[] frame, bool rejected, bool asynchronous) {
        using var source = new MemoryStream(frame);
        using var observed = new TlsAlertEvidenceStream(source, leaveOpen: true);
        var buffer = new byte[2];
        while ((asynchronous ? await observed.ReadAsync(buffer, 0, buffer.Length) : observed.Read(buffer, 0, buffer.Length)) > 0) { }
        Assert.Equal(rejected, observed.SawProtocolVersionRejection);
    }

    [Fact]
    public void AnOutgoingLocalAlertCannotEstablishRemoteRejection() {
        using var source = new MemoryStream();
        using var observed = new TlsAlertEvidenceStream(source, leaveOpen: true);
        var alert = new byte[] { 21, 3, 3, 0, 2, 2, 70 };
        observed.Write(alert, 0, alert.Length);
        Assert.False(observed.SawProtocolVersionRejection);
    }
}
