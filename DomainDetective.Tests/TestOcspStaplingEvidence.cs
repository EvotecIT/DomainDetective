namespace DomainDetective.Tests;

public class TestOcspStaplingEvidence {
    [Theory]
    [InlineData("", "", null)]
    [InlineData("CONNECTED(000001)", "", null)]
    [InlineData("", "TLS handshake failed", null)]
    [InlineData("OCSP Response Status: successful", "diagnostic", true)]
    [InlineData("", "ocsp response data:", true)]
    [InlineData("OCSP response: no response sent", "", false)]
    public void OnlyExplicitOcspEvidenceEstablishesPresenceOrAbsence(string output, string error, bool? expected) {
        Assert.Equal(expected, Helpers.OcspStaplingEvidence.Parse(output, error));
    }
}
