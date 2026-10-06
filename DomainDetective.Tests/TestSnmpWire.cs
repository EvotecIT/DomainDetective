using System.Net;
using System.Net.Sockets;
using DomainDetective;
using Org.BouncyCastle.Asn1;
using Xunit;

namespace DomainDetective.Tests;

public class TestSnmpWire {
    // Independently encoded SNMPv1 noSuchName response to request 1 for 1.3.6.1.2.1.
    private static readonly byte[] Response = {
        0x30,0x23,0x02,0x01,0x00,0x04,0x06,0x70,0x75,0x62,0x6c,0x69,0x63,
        0xa2,0x16,0x02,0x01,0x01,0x02,0x01,0x02,0x02,0x01,0x01,
        0x30,0x0b,0x30,0x09,0x06,0x05,0x2b,0x06,0x01,0x02,0x01,0x05,0x00
    };

    [Fact]
    public void CorrelatedProtocolErrorStillIdentifiesSnmp() {
        Assert.True(SnmpMessage.IsResponse(Response, 1));
        Assert.False(SnmpMessage.IsResponse(Response, 2));
    }

    [Fact]
    public void AcceptsSuccessfulPrimitiveValuesAndLongDefiniteLengths() {
        var request = SnmpMessage.CreateRequest(int.MaxValue);
        Assert.True(SnmpMessage.IsResponse(CreateResponse(request, value: new DerOctetString(new byte[512])), int.MaxValue));
        Assert.True(SnmpMessage.IsResponse(CreateResponse(request, value: DerInteger.ValueOf(int.MinValue)), int.MaxValue));
        Assert.False(SnmpMessage.IsResponse(CreateResponse(request, value: DerInteger.ValueOf(long.MaxValue)), int.MaxValue));
    }

    [Theory]
    [InlineData(4, 1)] // different protocol version
    [InlineData(7, 0x78)] // different community
    [InlineData(13, 0xa0)] // request, not response
    [InlineData(20, 6)] // invalid v1 error status
    [InlineData(23, 2)] // error points beyond the single binding
    [InlineData(34, 2)] // different object identifier
    [InlineData(35, 0x30)] // nested constructed value
    [InlineData(1, 0x80)] // indefinite outer frame
    [InlineData(27, 0x7f)] // oversized inner frame
    public void InvalidOrUnrelatedDatagramsAreNotSnmpEvidence(int offset, int value) {
        var bytes = (byte[])Response.Clone();
        bytes[offset] = (byte)value;
        Assert.False(SnmpMessage.IsResponse(bytes, 1));
    }

    [Fact]
    public void RequiresOneCompleteMessage() {
        Assert.False(SnmpMessage.IsResponse(new byte[] { 1 }, 1));
        Assert.False(SnmpMessage.IsResponse(Response.Take(Response.Length - 1).ToArray(), 1));
        Assert.False(SnmpMessage.IsResponse(Response.Concat(new byte[] { 0 }).ToArray(), 1));
        Assert.False(SnmpMessage.IsResponse(new byte[] { 0x30, 0x84, 0xff, 0xff, 0xff, 0xff }, 1));
    }

    [Fact]
    public async Task IgnoresNoiseUntilMatchingResponseAndReportsAssessment() {
        using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        int port = ((IPEndPoint)server.Client.LocalEndPoint!).Port;
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var responder = Respond();
        var analysis = new SnmpAnalysis { Timeout = TimeSpan.FromSeconds(3) };
        try {
            await analysis.AnalyzeServer("127.0.0.1", port, new InternalLogger(), stop.Token);
            Assert.True(analysis.ServerResults[$"127.0.0.1:{port}"]);
            Assert.Contains(analysis.Assessments, a => a.Code == SnmpCodes.Responds);
        } finally {
            stop.Cancel();
            server.Close();
            await responder;
        }

        async Task Respond() {
            try {
                var request = await server.ReceiveAsync().WaitWithCancellation(stop.Token);
                var valid = CreateResponse(request.Buffer);
                var wrong = CreateResponse(request.Buffer, wrongId: true);
                await server.SendAsync(new byte[] { 1 }, 1, request.RemoteEndPoint);
                await server.SendAsync(wrong, wrong.Length, request.RemoteEndPoint);
                await server.SendAsync(valid, valid.Length, request.RemoteEndPoint);
            } catch (Exception) when (stop.IsCancellationRequested) { }
        }
    }

    [Fact]
    public async Task NoiseAloneDoesNotReportExposedSnmp() {
        using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        int port = ((IPEndPoint)server.Client.LocalEndPoint!).Port;
        var receive = server.ReceiveAsync();
        var analysis = new SnmpAnalysis { Timeout = TimeSpan.FromMilliseconds(500) };
        var probe = analysis.AnalyzeServer("127.0.0.1", port, new InternalLogger());
        var request = await receive;
        await server.SendAsync(new byte[] { 1 }, 1, request.RemoteEndPoint);
        await probe;
        Assert.False(analysis.ServerResults[$"127.0.0.1:{port}"]);
        Assert.DoesNotContain(analysis.Assessments, a => a.Code == SnmpCodes.Responds);
    }

    [Fact]
    public async Task CallerCancellationIsNotReportedAsSecuredSnmp() {
        using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        int port = ((IPEndPoint)server.Client.LocalEndPoint!).Port;
        using var stop = new CancellationTokenSource();
        var request = server.ReceiveAsync();
        var analysis = new SnmpAnalysis();
        var probe = analysis.AnalyzeServer("127.0.0.1", port, new InternalLogger(), stop.Token);
        await request;
        stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => probe);
        Assert.Empty(analysis.ServerResults);
        Assert.DoesNotContain(analysis.Assessments, a => a.Code == SnmpCodes.Disabled);
    }

    internal static byte[] CreateResponse(byte[] request, bool wrongId = false, Asn1Encodable? value = null) {
        var message = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(request));
        var pdu = Asn1Sequence.GetInstance(Asn1TaggedObject.GetInstance(message[2]), false);
        int id = DerInteger.GetInstance(pdu[0]).IntValueExact;
        var bindings = new DerSequence(new DerSequence(new DerObjectIdentifier("1.3.6.1.2.1"), value ?? DerNull.Instance));
        var response = new DerSequence(DerInteger.ValueOf(wrongId ? id ^ 1 : id), DerInteger.ValueOf(value == null ? 2 : 0),
            DerInteger.ValueOf(value == null ? 1 : 0), bindings);
        return new DerSequence(DerInteger.ValueOf(0), new DerOctetString(System.Text.Encoding.ASCII.GetBytes("public")),
            new DerTaggedObject(false, 2, response)).GetDerEncoded();
    }
}
