using DomainDetective.Helpers;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.X509;

namespace DomainDetective.Tests;

/// <summary>
/// Uses the www.google.com certificate and its WE2 issuer captured on 2026-11-14. Expected SCT values are
/// copied from <c>openssl x509 -ext ct_precert_scts</c>; log entries come from the Chrome v3 log list of that day.
/// </summary>
public class TestEmbeddedSctValidation {
    private const string WyvernLogId = "ABpdGhwtk3W2SFV4+C9xoa5u7zl9KXyK4xV7yt7hoB4=";
    private const string WillowLogId = "ooEAGHNOF24dR+CVQPOBulRml81jqENQcW64CU7a8Q0=";

    [Fact]
    public void Parse_DecodesEveryEmbeddedSct() {
        Asn1OctetString extension = Load("sct-www.google.com.pem").GetExtensionValue(new DerObjectIdentifier("1.3.6.1.4.1.11129.2.4.2"));

        var scts = EmbeddedSctValidator.Parse(extension.GetOctets());

        Assert.Collection(scts,
            sct => {
                Assert.Equal(WyvernLogId, Convert.ToBase64String(sct.LogId));
                Assert.Equal(new DateTimeOffset(2026, 11, 3, 9, 29, 38, 1, TimeSpan.Zero), sct.Timestamp);
                Assert.Empty(sct.Extensions);
            },
            sct => {
                Assert.Equal(WillowLogId, Convert.ToBase64String(sct.LogId));
                Assert.Equal(new DateTimeOffset(2026, 11, 3, 9, 29, 38, 750, TimeSpan.Zero), sct.Timestamp);
                Assert.Equal(new byte[] { 0x00, 0x00, 0x05, 0x00, 0x36, 0x4A, 0xFC, 0x95 }, sct.Extensions);
            });
    }

    [Fact]
    public void Parse_RejectsTruncatedSctList() {
        // OCTET STRING { list length 0x0010, but only one serialized SCT length byte follows }
        byte[] truncated = { 0x04, 0x03, 0x00, 0x10, 0x00 };

        var error = Assert.Throws<FormatException>(() => EmbeddedSctValidator.Parse(truncated));

        Assert.Contains("truncated", error.Message);
    }

    [Fact]
    public async Task Validate_VerifiesSignaturesAgainstPresentedIssuer() {
        var logs = await LoadLogs(LogList());

        var result = EmbeddedSctValidator.Validate(Load("sct-www.google.com.pem"), Load("sct-www.google.com-issuer.pem"), logs, logs)!;

        Assert.All(result.Scts, sct => Assert.Equal(SctSignatureStatus.Valid, sct.SignatureStatus));
        Assert.Equal(2, result.ValidCount);
        Assert.Equal(CtPolicyCompliance.Compliant, result.Chrome.Compliance);
        Assert.Equal(CtPolicyCompliance.Compliant, result.Apple.Compliance);
    }

    [Fact]
    public async Task Validate_LeavesSignaturesUnverifiedWithoutIssuer() {
        var logs = await LoadLogs(LogList());

        var result = EmbeddedSctValidator.Validate(Load("sct-www.google.com.pem"), null, logs, logs)!;

        Assert.All(result.Scts, sct => Assert.Equal(SctSignatureStatus.Unverified, sct.SignatureStatus));
        Assert.Equal(CtPolicyCompliance.Undetermined, result.Chrome.Compliance);
        Assert.Equal(CtPolicyCompliance.Undetermined, result.Apple.Compliance);
    }

    [Fact]
    public async Task Validate_RejectsSignaturesOverAnotherIssuerKey() {
        var logs = await LoadLogs(LogList());
        var leaf = Load("sct-www.google.com.pem");

        var result = EmbeddedSctValidator.Validate(leaf, leaf, logs, logs)!;

        Assert.All(result.Scts, sct => Assert.Equal(SctSignatureStatus.Invalid, sct.SignatureStatus));
        Assert.Equal(CtPolicyCompliance.NotCompliant, result.Chrome.Compliance);
        Assert.Equal(CtPolicyCompliance.NotCompliant, result.Apple.Compliance);
    }

    [Fact]
    public async Task Validate_RequiresDistinctLogOperators() {
        var logs = await LoadLogs(LogList(willowOperator: "DigiCert"));

        var result = EmbeddedSctValidator.Validate(Load("sct-www.google.com.pem"), Load("sct-www.google.com-issuer.pem"), logs, logs)!;

        Assert.Equal(CtPolicyCompliance.NotCompliant, result.Chrome.Compliance);
        Assert.Equal(CtPolicyCompliance.NotCompliant, result.Apple.Compliance);
    }

    [Theory]
    [InlineData("2026-11-01T00:00:00Z", CtPolicyCompliance.NotCompliant)]
    [InlineData("2026-11-04T00:00:00Z", CtPolicyCompliance.Compliant)]
    public async Task Validate_CountsRetiredLogOnlyForSctsBeforeRetirement(string retiredAt, CtPolicyCompliance expected) {
        var logs = await LoadLogs(LogList(willowState: $$"""{ "retired": { "timestamp": "{{retiredAt}}" } }"""));

        var result = EmbeddedSctValidator.Validate(Load("sct-www.google.com.pem"), Load("sct-www.google.com-issuer.pem"), logs, logs)!;

        Assert.Equal("retired", result.Scts[1].ChromeLogState);
        Assert.Equal(expected, result.Chrome.Compliance);
        Assert.Equal(expected, result.Apple.Compliance);
    }

    [Fact]
    public async Task Validate_AppleRequiresAnRfc6962Log() {
        var logs = await LoadLogs(LogList(wyvernTiled: true));

        var result = EmbeddedSctValidator.Validate(Load("sct-www.google.com.pem"), Load("sct-www.google.com-issuer.pem"), logs, logs)!;

        Assert.Equal(CtPolicyCompliance.Compliant, result.Chrome.Compliance);
        Assert.Equal(CtPolicyCompliance.NotCompliant, result.Apple.Compliance);
    }

    [Theory]
    [InlineData(180 * 86400, CtPolicyCompliance.Compliant)]
    [InlineData(180 * 86400 + 1, CtPolicyCompliance.NotCompliant)]
    public void Chrome_RequiresThreeLogsAbove180DayLifetime(long lifetimeSeconds, CtPolicyCompliance expected) {
        var (scts, logs) = TwoValidSctsFromTwoOperators();
        var notBefore = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        var result = EmbeddedSctValidator.EvaluateChrome(scts, scts, logs, notBefore, notBefore.AddSeconds(lifetimeSeconds));

        Assert.Equal(expected, result.Compliance);
    }

    [Theory]
    // Apple counts notBefore through notAfter inclusive: 180 days minus one second is a 180-day certificate.
    [InlineData(180 * 86400 - 1, CtPolicyCompliance.Compliant)]
    [InlineData(180 * 86400, CtPolicyCompliance.NotCompliant)]
    public void Apple_RequiresThreeLogsAbove180DayLifetime(long lifetimeSeconds, CtPolicyCompliance expected) {
        var (scts, logs) = TwoValidSctsFromTwoOperators();
        var notBefore = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        var result = EmbeddedSctValidator.EvaluateApple(scts, logs, notBefore, notBefore.AddSeconds(lifetimeSeconds));

        Assert.Equal(expected, result.Compliance);
    }

    private static (IReadOnlyList<EmbeddedSct> Scts, Dictionary<string, CtLogDescriptor> Logs) TwoValidSctsFromTwoOperators() {
        var logs = new Dictionary<string, CtLogDescriptor> {
            ["a"] = new() { LogId = "a", OperatorName = "Operator A", State = "usable" },
            ["b"] = new() { LogId = "b", OperatorName = "Operator B", State = "usable" }
        };
        var timestamp = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var scts = logs.Keys.Select(id => new EmbeddedSct { LogId = id, Timestamp = timestamp, SignatureStatus = SctSignatureStatus.Valid }).ToList();
        return (scts, logs);
    }

    private static X509Certificate Load(string name) {
        using var certificate = CertificateLoaderCompat.LoadCertificateFromFile(Path.Combine("Data", name));
        return new X509CertificateParser().ReadCertificate(certificate.RawData);
    }

    private static Task<IReadOnlyList<CtLogDescriptor>> LoadLogs(string json) =>
        new CtLogIngestionClient { HttpGetOverride = (_, _) => Task.FromResult(json) }
            .GetLogsAsync("https://logs.example.test/list.json", includePending: true);

    private static string LogList(string willowOperator = "Let's Encrypt", string willowState = """{ "usable": { "timestamp": "2025-11-27T03:00:00Z" } }""",
        bool wyvernTiled = false) {
        string wyvern = $$"""
            {
              "description": "DigiCert Wyvern2027h1",
              "log_id": "{{WyvernLogId}}",
              "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEastxYj1mntGuyv74k4f+yaIx+ZEzlSJ+iVTYWlw8SpSKJ4TfxYWuBhnETlhpyG/5seJn0mOSnVgXsZ1JRflI7g==",
              "url": "https://wyvern.ct.digicert.com/2027h1/",
              "monitoring_url": "https://wyvern.ct.digicert.com/2027h1/",
              "state": { "usable": { "timestamp": "2025-12-20T18:00:00Z" } }
            }
            """;
        string willow = $$"""
            {
              "description": "Let's Encrypt Willow2027h1",
              "log_id": "{{WillowLogId}}",
              "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzsMKtojO0BVB4t59lVyAhxtqObVA+wId5BpJGA8pZrw5GTjzuhpvLu/heQGi0hHCeislkDe34N/2D0SwEUBE0w==",
              "submission_url": "https://log.willow.ct.letsencrypt.org/2027h1/",
              "monitoring_url": "https://mon.willow.ct.letsencrypt.org/2027h1/",
              "state": {{willowState}}
            }
            """;
        string digicertLogs = wyvernTiled ? $$"""{ "name": "DigiCert", "tiled_logs": [ {{wyvern}} ] }""" : $$"""{ "name": "DigiCert", "logs": [ {{wyvern}} ] }""";
        string willowOperatorJson = willowOperator == "DigiCert"
            ? $$"""{ "name": "DigiCert", "logs": [ {{wyvern}} ], "tiled_logs": [ {{willow}} ] }"""
            : $$"""{ "name": "{{willowOperator}}", "tiled_logs": [ {{willow}} ] }""";
        return willowOperator == "DigiCert"
            ? $$"""{ "operators": [ {{willowOperatorJson}} ] }"""
            : $$"""{ "operators": [ {{digicertLogs}}, {{willowOperatorJson}} ] }""";
    }
}
