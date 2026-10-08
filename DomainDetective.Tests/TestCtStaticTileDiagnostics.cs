using System.Net;
using System.Net.Http;

namespace DomainDetective.Tests;

public sealed class TestCtStaticTileDiagnostics {
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CompleteDecodingPreservesExactFailedEntryFromLaterTileOffset(bool precertificate) {
        // Invalid certificate bytes reach the binding failure for precertificates and
        // record decoding failure for X509 entries. Both paths must retain replay evidence.
        byte[] der = { 0x30, 0x00 };
        byte[] header = { 0, 0, 0, 0, 0, 0, 0, 1, 0, precertificate ? (byte)1 : (byte)0 };
        byte[] issuerHash = precertificate ? new byte[32] : Array.Empty<byte>();
        byte[] leaf = new byte[2].Concat(header).Concat(issuerHash).Concat(Vector(der))
            .Concat(new byte[] { 0, 3, 0xA1, 0xB2, 0xC3 }).ToArray();
        byte[] entry = leaf.Skip(2).Concat(precertificate ? Vector(der) : Array.Empty<byte>())
            .Concat(new byte[] { 0, 32 }).Concat(new byte[32]).ToArray();
        byte[] tile = entry.Concat(entry).ToArray();
        var client = new CtLogIngestionClient {
            SendOverride = (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) {
                Content = new ByteArrayContent(tile)
            })
        };

        var request = new CtLogIngestionBatchRequest {
            LogUrl = "https://ct.example.test/diagnostics/", MonitoringUrl = "https://ct.example.test/diagnostics/",
            ApiKind = CtLogApiKind.StaticCt, KnownTreeSize = 2, StartIndex = 1, BatchSize = 1,
            RequireCompleteDecoding = true
        };
        CtEntryDecodingException error = await Assert.ThrowsAsync<CtEntryDecodingException>(() => client.ReadBatchAsync(request));

        Assert.Equal(1, error.EntryIndex);
        Assert.Equal(Convert.ToBase64String(leaf), error.Payload.LeafInputBase64);
        Assert.Equal(Convert.ToBase64String(precertificate ? Vector(der).Concat(new byte[3]).ToArray() : Array.Empty<byte>()),
            error.Payload.ExtraDataBase64);
        Assert.Equal(Convert.ToBase64String(entry), error.StaticTileEntryBase64);
    }

    private static byte[] Vector(byte[] bytes) => new byte[] {
        (byte)(bytes.Length >> 16), (byte)(bytes.Length >> 8), (byte)bytes.Length
    }.Concat(bytes).ToArray();
}
