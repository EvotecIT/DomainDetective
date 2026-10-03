using DnsClientX;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DomainDetective.Tests;

public class TestDaneAuthentication {
    private const string Owner = "_443._tcp.example.com";

    [Theory]
    [InlineData(false, DaneAuthenticationStatus.Authenticated)]
    [InlineData(true, DaneAuthenticationStatus.Failed)]
    public async Task PrivateAnchorAuthenticatesOnlyAValidLeafPath(bool expired, DaneAuthenticationStatus expected) {
        using var root = CreateRoot();
        using var leaf = CreateLeaf(root, expired);
        var analysis = await Analyze(2, 0, 1, root);
        Validate(analysis, leaf, new[] { leaf, root }, nameMatch: true);
        var result = Assert.Single(analysis.AnalysisResults);
        Assert.Equal(DaneAssociationMatchStatus.Match, result.AssociationMatchStatus);
        Assert.Equal(expected, result.AuthenticationStatus);
        Assert.Equal(!expired, analysis.AllServicesAuthenticated);
        var view = DomainDetective.Views.Converters.Convert(analysis);
        Assert.Equal(expired, view.HasAuthenticationFailures);
        Assert.Equal(!expired, view.AllServicesAuthenticated);
        if (expired) Assert.Equal("Error", view.Status);
    }

    [Fact]
    public async Task MissingIntermediateCannotAuthenticateEvenWithMatchingAnchor() {
        using var root = CreateRoot(pathLength: 1);
        using var intermediate = CreateIntermediate(root);
        using var leaf = CreateLeaf(intermediate, false);
        var analysis = await Analyze(2, 0, 1, root);
        Validate(analysis, leaf, new[] { leaf, root }, true);
        Assert.Equal(DaneAssociationMatchStatus.Match, Assert.Single(analysis.AnalysisResults).AssociationMatchStatus);
        Assert.Equal(DaneAuthenticationStatus.Failed, Assert.Single(analysis.AnalysisResults).AuthenticationStatus);
    }

    [Theory]
    [InlineData(0, DaneAuthenticationStatus.Failed)]
    [InlineData(1, DaneAuthenticationStatus.Authenticated)]
    public async Task AnchorCertificatePathLengthAppliesOnlyToCertificateSelector(int selector, DaneAuthenticationStatus expected) {
        using var root = CreateRoot();
        using var intermediate = CreateIntermediate(root);
        using var leaf = CreateLeaf(intermediate, false);
        var analysis = await Analyze(2, selector, 1, root);
        Validate(analysis, leaf, new[] { leaf, intermediate, root }, true);
        Assert.Equal(expected, Assert.Single(analysis.AnalysisResults).AuthenticationStatus);
    }

    [Theory]
    [InlineData(0, "example.com", DaneAuthenticationStatus.Authenticated)]
    [InlineData(0, "outside.test", DaneAuthenticationStatus.Failed)]
    [InlineData(1, "outside.test", DaneAuthenticationStatus.Authenticated)]
    public async Task AnchorNameConstraintsApplyOnlyToCertificateSelector(int selector, string leafName, DaneAuthenticationStatus expected) {
        using var root = CreateRoot(permittedName: "example.com");
        using var leaf = CreateLeaf(root, false, name: leafName);
        var analysis = await Analyze(2, selector, 1, root);
        Validate(analysis, leaf, new[] { leaf, root }, true);
        Assert.Equal(expected, Assert.Single(analysis.AnalysisResults).AuthenticationStatus);
    }

    [Fact]
    public async Task MatchingUnrelatedAnchorDoesNotAuthenticateTheLeaf() {
        using var root = CreateRoot();
        using var unrelated = CreateRoot("CN=Unrelated");
        using var leaf = CreateLeaf(root, false);
        var analysis = await Analyze(2, 0, 1, unrelated);
        Validate(analysis, leaf, new[] { leaf, root, unrelated }, true);
        var result = Assert.Single(analysis.AnalysisResults);
        Assert.Equal(DaneAssociationMatchStatus.Match, result.AssociationMatchStatus);
        Assert.Equal(DaneAuthenticationStatus.Failed, result.AuthenticationStatus);
    }

    [Fact]
    public async Task FullCertificateAnchorCanComeOnlyFromDns() {
        using var root = CreateRoot();
        using var leaf = CreateLeaf(root, false);
        var analysis = await Analyze(2, 0, 0, root);
        Validate(analysis, leaf, new[] { leaf }, true);
        Assert.Equal(DaneAuthenticationStatus.Authenticated, Assert.Single(analysis.AnalysisResults).AuthenticationStatus);
        Assert.True(analysis.AllServicesAuthenticated);
        Assert.Equal(DaneAssociationMatchStatus.NoMatch, Assert.Single(analysis.AnalysisResults).AssociationMatchStatus);
        Assert.DoesNotContain(analysis.Assessments, assessment => assessment.Code == DaneCodes.CertificateMatches);
    }

    [Theory]
    [InlineData("00")]
    [InlineData("3000")]
    [InlineData("trailing")]
    public async Task MalformedDnsAnchorDoesNotStopAValidRolloverAlternative(string input) {
        using var root = CreateRoot();
        using var leaf = CreateLeaf(root, false);
        string association = input == "trailing" ? Hex(root.RawData) + "00" : input;
        var analysis = new DANEAnalysis();
        await analysis.AnalyzeDANERecords(new[] {
            new DnsAnswer { Name = Owner, Type = DnsRecordType.TLSA, DataRaw = "2 0 0 " + association },
            new DnsAnswer { Name = Owner, Type = DnsRecordType.TLSA, DataRaw = "3 0 1 " + Digest(leaf.RawData) }
        }, new InternalLogger());
        Validate(analysis, leaf, new[] { leaf }, true);
        Assert.Equal(DaneAuthenticationStatus.Failed, analysis.AnalysisResults[0].AuthenticationStatus);
        Assert.Equal(DaneAuthenticationStatus.Authenticated, analysis.AnalysisResults[1].AuthenticationStatus);
        Assert.True(analysis.AllServicesAuthenticated);
    }

    [Theory]
    [InlineData("1.3.6.1.5.5.7.3.1", DaneAuthenticationStatus.Authenticated)]
    [InlineData("1.3.6.1.5.5.7.3.2", DaneAuthenticationStatus.Failed)]
    public async Task CriticalIntermediatePurposeIsProcessedDuringPathValidation(string purpose, DaneAuthenticationStatus expected) {
        using var root = CreateRoot(pathLength: 1);
        using var intermediate = CreateIntermediate(root, purpose);
        using var leaf = CreateLeaf(intermediate, false);
        var analysis = await Analyze(2, 0, 1, root);
        Validate(analysis, leaf, new[] { leaf, intermediate, root }, true);
        Assert.Equal(expected, Assert.Single(analysis.AnalysisResults).AuthenticationStatus);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public async Task EndEntityCanBeItsOwnDaneTrustAnchor(int selector) {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=example.com", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, true));
        using var leaf = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        var analysis = await Analyze(2, selector, 1, leaf);
        Validate(analysis, leaf, new[] { leaf }, true);
        Assert.Equal(DaneAssociationMatchStatus.Match, Assert.Single(analysis.AnalysisResults).AssociationMatchStatus);
        Assert.Equal(DaneAuthenticationStatus.Authenticated, Assert.Single(analysis.AnalysisResults).AuthenticationStatus);
    }

    [Fact]
    public async Task SyntaxOnlyRecordsCannotProduceAnAuthenticatedSectionStatus() {
        using var root = CreateRoot();
        var analysis = await Analyze(3, 1, 1, root);
        var view = DomainDetective.Views.Converters.Convert(analysis);
        Assert.False(view.AuthenticationValidationPerformed);
        Assert.False(view.AllServicesAuthenticated);
        Assert.Equal("Warning", view.Status);
    }

    [Theory]
    [InlineData(true, DaneAuthenticationStatus.Authenticated)]
    [InlineData(false, DaneAuthenticationStatus.Failed)]
    [InlineData(null, DaneAuthenticationStatus.Inconclusive)]
    public async Task TrustAnchorUsageRequiresNameEvidence(bool? nameMatch, DaneAuthenticationStatus expected) {
        using var root = CreateRoot();
        using var leaf = CreateLeaf(root, false);
        var analysis = await Analyze(2, 1, 1, root);
        Validate(analysis, leaf, new[] { leaf, root }, nameMatch);
        Assert.Equal(expected, Assert.Single(analysis.AnalysisResults).AuthenticationStatus);
    }

    [Fact]
    public async Task TrustAnchorUsageRejectsNonServerPurpose() {
        using var root = CreateRoot();
        using var leaf = CreateLeaf(root, false, "1.3.6.1.5.5.7.3.2");
        var analysis = await Analyze(2, 0, 1, root);
        Validate(analysis, leaf, new[] { leaf, root }, true);
        Assert.Equal(DaneAuthenticationStatus.Failed, Assert.Single(analysis.AnalysisResults).AuthenticationStatus);
    }

    [Fact]
    public async Task EndEntityUsageIgnoresPkixExpiryAndNames() {
        using var root = CreateRoot();
        using var leaf = CreateLeaf(root, true);
        var analysis = await Analyze(3, 1, 1, leaf);
        Validate(analysis, leaf, new[] { leaf }, false);
        Assert.Equal(DaneAuthenticationStatus.Authenticated, Assert.Single(analysis.AnalysisResults).AuthenticationStatus);
    }

    [Fact]
    public async Task OneAuthenticatedRolloverRecordIsEnoughForAService() {
        using var root = CreateRoot();
        using var leaf = CreateLeaf(root, false);
        var analysis = new DANEAnalysis();
        await analysis.AnalyzeDANERecords(new[] {
            new DnsAnswer { Name = Owner, Type = DnsRecordType.TLSA, DataRaw = "3 0 1 " + Digest(leaf.RawData) },
            new DnsAnswer { Name = Owner, Type = DnsRecordType.TLSA, DataRaw = "3 0 1 " + new string('0', 64) }
        }, new InternalLogger());
        Validate(analysis, leaf, new[] { leaf }, null);
        Assert.True(analysis.AllServicesAuthenticated);
        Assert.False(analysis.AllCertificateAssociationsMatch);
        var view = DomainDetective.Views.Converters.Convert(analysis);
        Assert.True(view.AllServicesAuthenticated);
        Assert.False(view.HasAuthenticationFailures);
        Assert.DoesNotContain(analysis.Assessments, assessment => assessment.Code == DaneCodes.CertificateMismatch);
    }

    private static void Validate(DANEAnalysis analysis, X509Certificate2 leaf, X509Certificate2[] chain, bool? nameMatch) =>
        analysis.ValidateCertificateAssociations(new[] {
            new DaneCertificateEvidence { TlsaOwnerName = Owner, EndEntityCertificate = leaf, CertificateChain = chain,
                DnssecValidated = true, PkixValidated = false, HostnameMatch = nameMatch }
        }, new InternalLogger());

    private static async Task<DANEAnalysis> Analyze(int usage, int selector, int matching, X509Certificate2 certificate) {
        byte[] selected = selector == 0 ? certificate.RawData : new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(certificate.RawData)
            .CertificateStructure.SubjectPublicKeyInfo.GetEncoded();
        string association = matching == 0 ? Hex(selected) : Digest(selected);
        var analysis = new DANEAnalysis();
        await analysis.AnalyzeDANERecords(new[] {
            new DnsAnswer { Name = Owner, Type = DnsRecordType.TLSA, DataRaw = $"{usage} {selector} {matching} {association}" }
        }, new InternalLogger());
        return analysis;
    }

    private static string Digest(byte[] bytes) {
        using var sha = SHA256.Create();
        return Hex(sha.ComputeHash(bytes));
    }
    private static string Hex(byte[] bytes) => BitConverter.ToString(bytes).Replace("-", string.Empty);

    private static X509Certificate2 CreateRoot(string name = "CN=Private DANE Root", int pathLength = 0, string? permittedName = null) {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(name, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, pathLength, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        if (permittedName != null) {
            var constraints = new Org.BouncyCastle.Asn1.X509.NameConstraints(
                new Org.BouncyCastle.Asn1.X509.GeneralSubtrees(new Org.BouncyCastle.Asn1.X509.GeneralSubtree(
                    new Org.BouncyCastle.Asn1.X509.GeneralName(Org.BouncyCastle.Asn1.X509.GeneralName.DnsName, permittedName))), null);
            request.CertificateExtensions.Add(new X509Extension("2.5.29.30", constraints.GetDerEncoded(), true));
        }
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-10), DateTimeOffset.UtcNow.AddDays(10));
    }

    private static X509Certificate2 CreateIntermediate(X509Certificate2 issuer, string? purpose = null) {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=Intermediate", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        if (purpose != null) request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(purpose) }, true));
        using var certificate = request.Create(issuer, DateTimeOffset.UtcNow.AddDays(-3), DateTimeOffset.UtcNow.AddDays(3), new byte[] { 5, 6, 7, 8 });
        return certificate.CopyWithPrivateKey(key);
    }

    private static X509Certificate2 CreateLeaf(X509Certificate2 issuer, bool expired, string purpose = "1.3.6.1.5.5.7.3.1", string name = "example.com") {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=" + name, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName(name);
        request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(purpose) }, true));
        return request.Create(issuer, DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddDays(expired ? -1 : 2), new byte[] { 1, 2, 3, 4 });
    }
}
