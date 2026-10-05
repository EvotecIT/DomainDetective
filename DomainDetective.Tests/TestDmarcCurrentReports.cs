using MimeKit;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Schema;

namespace DomainDetective.Tests;

public class TestDmarcCurrentReports {
    private const string CurrentNamespace = "urn:ietf:params:xml:ns:dmarc-2.0";
    private const string CurrentXml = """
        <feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">
          <version>1.0</version>
          <report_metadata><org_name>Reporter</org_name><email>reports@example.net</email>
            <report_id>current-1</report_id><date_range><begin>1700000000</begin><end>1700086399</end></date_range>
            <generator>Test reporter</generator></report_metadata>
          <policy_published><domain>example.com</domain><p>reject</p><np>quarantine</np>
            <testing>y</testing><discovery_method>treewalk</discovery_method></policy_published>
          <record><row><source_ip>192.0.2.1</source_ip><count>3</count>
            <policy_evaluated><disposition>pass</disposition><dkim>pass</dkim><spf>fail</spf></policy_evaluated></row>
            <identifiers><header_from>example.com</header_from><envelope_from>sender.example.com</envelope_from></identifiers>
            <auth_results><dkim><domain>example.com</domain><selector>first</selector><result>pass</result></dkim>
              <dkim><domain>other.example</domain><selector>second</selector><result>fail</result><human_result>bad signature</human_result></dkim>
              <spf><domain>sender.example.com</domain><scope>mfrom</scope><result>fail</result></spf></auth_results>
          </record>
        </feedback>
        """;

    [Fact]
    public void OfficialAggregateExampleIsAcceptedWithoutSchemaDiagnostics() {
        var report = DmarcReportParser.Parse("Reports/rfc9990-example.xml");
        Assert.Empty(report.ValidationMessages);
        Assert.Equal("Sample Reporter", report.ReporterOrgName);
        Assert.Equal("Example DMARC Aggregate Reporter v1.2", report.Generator);
        var row = Assert.Single(report.Records);
        Assert.Equal(123, row.Count);
        Assert.Equal("pass", row.Disposition);
        Assert.Equal("abc123", Assert.Single(row.DkimResults).Selector);
        Assert.Equal("fail", Assert.Single(row.SpfResults).Result);
    }

    [Fact]
    public void OfficialFailureExamplePreservesItsMachineReadableEvidence() {
        using var message = MimeMessage.Load("Reports/rfc9991-example.eml");
        var report = Assert.IsType<DmarcForensicReport>(DmarcForensicParser.ParseMessage(message));
        Assert.Empty(report.ValidationMessages);
        Assert.Equal("dmarc", report.AuthFailure);
        Assert.Equal("192.0.2.2", report.SourceIp);
        Assert.Equal("consumer.example", report.HeaderFrom);
        Assert.Equal(new[] { "dkim" }, report.IdentityAlignment);
        Assert.Equal("epsilon", report.DkimSelector);
        Assert.Equal("author=gen.example@forwarder.example", report.OriginalMailFrom);
        Assert.Contains("dmarc=fail", Assert.Single(report.FeedbackFields["Authentication-Results"]));
    }

    [Theory]
    [InlineData("2001:db8::1", true)]
    [InlineData("not-an-ip", false)]
    [InlineData("127.1", false)]
    [InlineData("fe80::1%3", false)]
    public void SourceAddressesUseLiteralSyntaxAndPreserveInvalidEvidence(string address, bool valid) {
        string xml = CurrentXml.Replace("192.0.2.1", address);
        using var strict = new MemoryStream(Encoding.UTF8.GetBytes(xml));
        if (valid) Assert.Equal(address, Assert.Single(DmarcReportParser.Parse(strict).Records).SourceIp);
        else {
            Assert.Throws<XmlSchemaValidationException>(() => DmarcReportParser.Parse(strict));
            using var partial = new MemoryStream(Encoding.UTF8.GetBytes(xml));
            var errors = new List<string>();
            var report = DmarcReportParser.Parse(partial, validationMessages: errors);
            Assert.Equal(address, Assert.Single(report.Records).SourceIp);
            Assert.Contains(report.ValidationMessages, error => error.Contains("source_ip"));
            Assert.Equal(errors, report.ValidationMessages);
        }
    }

    [Fact]
    public void AnAttachedMessageIsNotMistakenForAFailureReport() {
        using var attached = Forensic("", "Feedback-Type: auth-failure\r\nAuth-Failure: dmarc\r\nIdentity-Alignment: none\r\n");
        using var outer = new MimeMessage();
        outer.Body = new Multipart("mixed") { new TextPart("plain") { Text = "Forwarded message" }, new MessagePart { Message = attached } };
        Assert.Null(DmarcForensicParser.ParseMessage(outer));
    }

    [Theory]
    [InlineData("2147483648")]
    [InlineData("-1")]
    public void UnrepresentableCurrentCountsAreDiagnosedWithoutInventingOneMessage(string count) {
        string xml = CurrentXml.Replace("<count>3</count>", "<count>" + count + "</count>");
        using var strict = new MemoryStream(Encoding.UTF8.GetBytes(xml));
        Assert.Throws<XmlSchemaValidationException>(() => DmarcReportParser.Parse(strict));
        using var partial = new MemoryStream(Encoding.UTF8.GetBytes(xml));
        var errors = new List<string>();
        var report = DmarcReportParser.Parse(partial, validationMessages: errors);
        Assert.Equal(0, Assert.Single(report.Records).Count);
        Assert.Contains(report.ValidationMessages, error => error.Contains(count));
        Assert.Equal(errors, report.ValidationMessages);
    }

    [Fact]
    public void OutOfRangeReportDatesRespectThePartialEvidenceContract() {
        string xml = CurrentXml.Replace("1700000000", "253402300800");
        using var strict = new MemoryStream(Encoding.UTF8.GetBytes(xml));
        Assert.Throws<XmlSchemaValidationException>(() => DmarcReportParser.Parse(strict));
        using var partial = new MemoryStream(Encoding.UTF8.GetBytes(xml));
        var errors = new List<string>();
        var report = DmarcReportParser.Parse(partial, validationMessages: errors);
        Assert.Null(report.RangeBeginUtc);
        Assert.Single(report.Records);
        Assert.Contains(report.ValidationMessages, error => error.Contains("date_range/begin"));
        Assert.Equal(errors, report.ValidationMessages);
    }

    [Theory]
    [InlineData("0", "All underlying mechanisms fail to produce an aligned pass")]
    [InlineData("1", "Any underlying mechanism fails to produce an aligned pass")]
    public void FailureReportingOptionsDescribeTheirActualGenerationCondition(string option, string description) {
        string xml = CurrentXml.Replace("<p>reject</p>", "<p>reject</p><fo>" + option + "</fo>");
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(xml));
        Assert.Equal(description, DmarcReportParser.Parse(stream).PolicyPublished.RequestedReportingPolicy);
    }

    [Fact]
    public void CurrentAggregateNamespaceAndDispositionAreAccepted() {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(CurrentXml));
        var report = DmarcReportParser.Parse(stream);
        Assert.Empty(report.ValidationMessages);
        Assert.Equal("current-1", report.ReportId);
        Assert.Equal("pass", Assert.Single(report.Records).Disposition);
        Assert.Equal(3, report.Records[0].Count);
    }

    [Fact]
    public void CurrentMetadataAndEveryAuthenticationObservationArePreserved() {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(CurrentXml));
        var report = DmarcReportParser.Parse(stream);
        Assert.Equal(CurrentNamespace, report.XmlNamespace);
        Assert.Equal("1.0", report.Version);
        Assert.Equal("Test reporter", report.Generator);
        Assert.Equal("y", report.PolicyPublished.Testing);
        Assert.Equal("treewalk", report.PolicyPublished.DiscoveryMethod);
        var row = Assert.Single(report.Records);
        Assert.Equal(2, row.DkimResults.Count);
        Assert.Equal("first", row.DkimSelector);
        Assert.Equal("bad signature", row.DkimResults[1].HumanResult);
        Assert.Equal("mfrom", Assert.Single(row.SpfResults).Scope);
        Assert.Equal("sender.example.com", row.EnvelopeFrom);
    }

    [Theory]
    [InlineData("")]
    [InlineData("qualified")]
    [InlineData("unqualified")]
    public void LegacyReportsWithMetadataUseTheirActualNamespaceForm(string form) {
        string xml = CurrentXml.Replace(" xmlns=\"" + CurrentNamespace + "\"", "")
            .Replace("<version>1.0</version>", "").Replace("<generator>Test reporter</generator>", "")
            .Replace("<np>quarantine</np>", "<sp>reject</sp><pct>100</pct>")
            .Replace("<testing>y</testing><discovery_method>treewalk</discovery_method>", "")
            .Replace("<disposition>pass</disposition>", "<disposition>none</disposition>");
        if (form == "qualified") xml = xml.Replace("<feedback>", "<feedback xmlns=\"http://dmarc.org/dmarc-xml/0.1\">");
        if (form == "unqualified") xml = xml.Replace("<feedback>", "<d:feedback xmlns:d=\"http://dmarc.org/dmarc-xml/0.1\">").Replace("</feedback>", "</d:feedback>");
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(xml));
        var report = DmarcReportParser.Parse(stream);
        Assert.Equal("current-1", report.ReportId);
        Assert.Equal("example.com", report.PolicyPublished.Domain);
        Assert.Equal(2, Assert.Single(report.Records).DkimResults.Count);
        Assert.Empty(report.ValidationMessages);
    }

    [Fact]
    public void ForeignExtensionRecordsAreRetainedWithoutBecomingAggregateRows() {
        var doc = XDocument.Parse(CurrentXml);
        XNamespace ns = CurrentNamespace;
        XNamespace foreign = "urn:example:extension";
        var real = doc.Root!.Element(ns + "record")!;
        real.AddBeforeSelf(new XElement(ns + "extension", new XElement(foreign + "evidence", new XElement(real))));
        real.Add(new XElement(foreign + "note", "receiver detail"));
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(doc.ToString()));
        var report = DmarcReportParser.Parse(stream);
        Assert.Single(report.Records);
        Assert.Contains("urn:example:extension", Assert.Single(report.Extensions));
        Assert.Contains("receiver detail", Assert.Single(report.Records[0].Extensions));
    }

    [Theory]
    [InlineData("xml")]
    [InlineData("gz")]
    [InlineData("zip")]
    public void CurrentReportsHonorUncompressedLimitForEveryContainer(string format) {
        byte[] xml = Encoding.UTF8.GetBytes(CurrentXml);
        using var stream = new MemoryStream();
        if (format == "gz") {
            using var gzip = new GZipStream(stream, CompressionMode.Compress, true);
            gzip.Write(xml, 0, xml.Length);
        } else if (format == "zip") {
            using var zip = new ZipArchive(stream, ZipArchiveMode.Create, true);
            using var entry = zip.CreateEntry("report.xml").Open();
            entry.Write(xml, 0, xml.Length);
        } else stream.Write(xml, 0, xml.Length);
        stream.Position = 0;
        Assert.Throws<IOException>(() => DmarcReportParser.Parse(stream, "report." + format, null, xml.Length - 1));
    }

    [Fact]
    public void CurrentSchemaErrorsAreExplicitAndOptionalCollectorRetainsPartialEvidence() {
        string xml = CurrentXml.Replace("<testing>y</testing>", "<testing>maybe</testing>");
        using var strict = new MemoryStream(Encoding.UTF8.GetBytes(xml));
        Assert.Throws<XmlSchemaValidationException>(() => DmarcReportParser.Parse(strict));
        using var partial = new MemoryStream(Encoding.UTF8.GetBytes(xml));
        var errors = new List<string>();
        var report = DmarcReportParser.Parse(partial, validationMessages: errors);
        Assert.NotEmpty(report.ValidationMessages);
        Assert.Single(report.Records);
    }

    [Fact]
    public void DtdIsRejectedBeforeReportInterpretation() {
        string xml = "<!DOCTYPE feedback [<!ENTITY x 'example.com'>]>" + CurrentXml;
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(xml));
        Assert.Throws<XmlException>(() => DmarcReportParser.Parse(stream));
    }

    [Fact]
    public void FeedbackFieldsTakePrecedenceOverAttachedOriginalHeaders() {
        using var message = Forensic("From: Author <author@example.com>\r\nSource-IP: 203.0.113.9\r\n",
            "Feedback-Type: auth-failure\r\nVersion: 1\r\nUser-Agent: Test\r\nAuth-Failure: dmarc\r\nIdentity-Alignment: none\r\nSource-IP: 192.0.2.1\r\nReported-Domain: example.com\r\n");
        var report = Assert.IsType<DmarcForensicReport>(DmarcForensicParser.ParseMessage(message));
        Assert.Equal("192.0.2.1", report.SourceIp);
        Assert.Equal("example.com", report.HeaderFrom);
    }

    [Fact]
    public void OriginalFromFallbackReturnsItsDomain() {
        using var message = Forensic("From: Author <author@example.com>\r\n",
            "Feedback-Type: auth-failure\r\nVersion: 1\r\nUser-Agent: Test\r\nAuth-Failure: dmarc\r\nIdentity-Alignment: none\r\nSource-IP: 192.0.2.1\r\n");
        var report = Assert.IsType<DmarcForensicReport>(DmarcForensicParser.ParseMessage(message));
        Assert.Equal("example.com", report.HeaderFrom);
    }

    [Fact]
    public void FailureFieldsUnfoldAndRetainDkimSpfAndRepeatedEvidence() {
        using var message = Forensic("From: Author <author@example.com>\r\n",
            "Feedback-Type: auth-failure\r\nAuth-Failure: dmarc\r\nIdentity-Alignment: DKIM (signature, failed),\r\n\tSPF\r\n"
            + "DKIM-Domain: example.com\r\nDKIM-Identity: @example.com\r\nDKIM-Selector: first\r\nDKIM-Selector: second\r\n"
            + "SPF-DNS: txt : sender.example.com : v=spf1\r\n\t-all\r\nDelivery-Result: delivered\r\n");
        var report = Assert.IsType<DmarcForensicReport>(DmarcForensicParser.ParseMessage(message));
        Assert.True(report.HasFeedbackReport);
        Assert.Equal(new[] { "dkim", "spf" }, report.IdentityAlignment);
        Assert.Equal("first", report.DkimSelector);
        Assert.Equal(2, report.FeedbackFields["DKIM-Selector"].Count);
        Assert.Contains("-all", report.SpfDns);
        Assert.Equal("delivered", report.DeliveryResult);
        Assert.Empty(report.ValidationMessages);
    }

    [Theory]
    [InlineData("dkim,dkim")]
    [InlineData("none,spf")]
    [InlineData("sp(comment)f")]
    public void InvalidIdentityAlignmentRetainsEvidenceWithDiagnostics(string alignment) {
        using var message = Forensic("", "Feedback-Type: auth-failure\r\nAuth-Failure: dmarc\r\nIdentity-Alignment: " + alignment + "\r\n");
        var report = Assert.IsType<DmarcForensicReport>(DmarcForensicParser.ParseMessage(message));
        Assert.NotEmpty(report.ValidationMessages);
        Assert.Equal(alignment, Assert.Single(report.FeedbackFields["Identity-Alignment"]));
    }

    private static MimeMessage Forensic(string originalHeaders, string feedback) {
        var message = new MimeMessage();
        var body = new Multipart("report");
        body.ContentType.Parameters["report-type"] = "feedback-report";
        body.Add(new MimePart("text", "rfc822-headers") { Content = new MimeContent(new MemoryStream(Encoding.UTF8.GetBytes(originalHeaders))) });
        body.Add(new MimePart("message", "feedback-report") { Content = new MimeContent(new MemoryStream(Encoding.UTF8.GetBytes(feedback))) });
        message.Body = body;
        return message;
    }
}
