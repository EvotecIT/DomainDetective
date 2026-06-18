using System.IO;

namespace DomainDetective.Tests;

public class TestMessageHeaderIssues {
    [Fact]
    public void MissingArcIsReported() {
        var raw = File.ReadAllText("Data/dkimvalidator-headers.txt");
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new InternalLogger());
        Assert.Contains(MessageHeaderIssue.MissingArc, analysis.Issues);
    }

    [Fact]
    public void InvalidDkimSignatureIsReported() {
        var raw = File.ReadAllText("Data/dkim-bad-padding.txt");
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new InternalLogger());
        Assert.Contains(MessageHeaderIssue.InvalidDkim, analysis.Issues);
    }

    [Fact]
    public void DirectExchangeOnlineInboxDeliveryIsReported() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <direct-test@example.net>",
            "From: user@example.com",
            "To: user@example.com",
            "Subject: Authorized validation",
            "Authentication-Results: mx.example.com; dkim=none (message not signed) header.d=none; spf=fail smtp.mailfrom=example.com; dmarc=fail action=quarantine header.from=example.com",
            "X-MS-Exchange-Organization-AuthAs: Anonymous",
            "X-MS-Exchange-Organization-SCL: 1",
            "X-Microsoft-Antispam-Mailbox-Delivery: ucf:0;jmr:0;auth:0;dest:I",
            "X-Forefront-Antispam-Report: CIP:192.0.2.25;CTRY:ZZ;SCL:1;SFV:NSPM;H:sender.example.net",
            "Received: from sender.example.net (sender.example.net [192.0.2.25]) by DB1PEPF00000001.mail.protection.outlook.com with SMTP id abc; Wed, 17 Jun 2026 12:00:00 +0000",
            string.Empty
        });

        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new InternalLogger());

        Assert.True(analysis.SeenMicrosoftEop);
        Assert.True(analysis.DirectToExchangeOnlineObserved);
        Assert.True(analysis.DeliveredToInbox);
        Assert.True(analysis.AuthenticationFailedDeliveredToInbox);
        Assert.True(analysis.SelfSpoofDeliveredToInbox);
        Assert.Equal("192.0.2.25", analysis.SourceIp);
        Assert.Equal(1, analysis.Scl);
        Assert.Contains(MessageHeaderIssue.DirectToExchangeOnline, analysis.Issues);
        Assert.Contains(MessageHeaderIssue.AuthenticationFailedDeliveredToInbox, analysis.Issues);
        Assert.Contains(MessageHeaderIssue.SelfSpoofDeliveredToInbox, analysis.Issues);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == MessageHeaderCodes.DirectToExchangeOnlineObserved);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == MessageHeaderCodes.AuthenticationFailedDeliveredToInbox);
    }

    [Fact]
    public void ExpectedMxComparisonReportsBypassedGateway() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <mx-bypass@example.net>",
            "From: sender@example.net",
            "To: recipient@example.com",
            "Subject: Authorized validation",
            "Authentication-Results: mx.example.com; dkim=none; spf=fail smtp.mailfrom=example.net; dmarc=fail header.from=example.net",
            "X-MS-Exchange-Organization-AuthAs: Anonymous",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "X-Forefront-Antispam-Report: CIP:198.51.100.7;SCL:1;SFV:NSPM;H:sender.example.net",
            "Received: from sender.example.net (sender.example.net [198.51.100.7]) by example-com.mail.protection.outlook.com with SMTP id abc; Wed, 17 Jun 2026 12:00:00 +0000",
            string.Empty
        });

        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new InternalLogger());
        analysis.CompareExpectedMx(new[] { "mail-gateway.example.com" });

        Assert.False(analysis.ExpectedMxObserved);
        Assert.True(analysis.ExpectedMxBypassed);
        Assert.Contains(MessageHeaderIssue.ExpectedMxBypassed, analysis.Issues);
    }

    [Fact]
    public void ExpectedMxComparisonIgnoresNonRouteHeaderMentions() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <mail-gateway.example.com@example.net>",
            "From: sender@example.net",
            "To: recipient@example.com",
            "Subject: mail-gateway.example.com mentioned only in subject",
            "Authentication-Results: mx.example.com; dkim=none; spf=fail smtp.mailfrom=example.net; dmarc=fail header.from=example.net",
            "X-MS-Exchange-Organization-AuthAs: Anonymous",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "X-Forefront-Antispam-Report: CIP:198.51.100.7;SCL:1;SFV:NSPM;H:sender.example.net",
            "Received: from sender.example.net (sender.example.net [198.51.100.7]) by example-com.mail.protection.outlook.com with SMTP id abc; Wed, 17 Jun 2026 12:00:00 +0000",
            string.Empty
        });

        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new InternalLogger());
        analysis.CompareExpectedMx(new[] { "mail-gateway.example.com" });

        Assert.False(analysis.ExpectedMxObserved);
        Assert.True(analysis.ExpectedMxBypassed);
        Assert.Contains(MessageHeaderIssue.ExpectedMxBypassed, analysis.Issues);
    }

    [Fact]
    public void ExpectedMxComparisonNormalizesTrailingDotsAndSuppressesDirectEop() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <gateway-observed@example.net>",
            "From: sender@example.net",
            "To: recipient@example.com",
            "Subject: Gateway observed",
            "Authentication-Results: mx.example.com; dkim=none; spf=fail smtp.mailfrom=example.net; dmarc=fail header.from=example.net",
            "X-MS-Exchange-Organization-AuthAs: Anonymous",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "X-Forefront-Antispam-Report: CIP:198.51.100.7;SCL:1;SFV:NSPM;H:mail-gateway.example.com",
            "Received: from mail-gateway.example.com (mail-gateway.example.com [198.51.100.7]) by example-com.mail.protection.outlook.com with SMTP id abc; Wed, 17 Jun 2026 12:00:00 +0000",
            string.Empty
        });

        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new InternalLogger());
        Assert.True(analysis.DirectToExchangeOnlineObserved);

        analysis.CompareExpectedMx(new[] { "mail-gateway.example.com." });

        Assert.True(analysis.ExpectedMxObserved);
        Assert.False(analysis.ExpectedMxBypassed);
        Assert.False(analysis.DirectToExchangeOnlineObserved);
        Assert.DoesNotContain(MessageHeaderIssue.DirectToExchangeOnline, analysis.Issues);
    }

    [Fact]
    public void ExpectedMxBypassCheckAddsAssessment() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <mx-bypass-assessment@example.net>",
            "From: sender@example.net",
            "To: recipient@example.com",
            "Subject: Authorized validation",
            "Authentication-Results: mx.example.com; dkim=none; spf=fail smtp.mailfrom=example.net; dmarc=fail header.from=example.net",
            "X-MS-Exchange-Organization-AuthAs: Anonymous",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "X-Forefront-Antispam-Report: CIP:198.51.100.7;SCL:1;SFV:NSPM;H:sender.example.net",
            "Received: from sender.example.net (sender.example.net [198.51.100.7]) by example-com.mail.protection.outlook.com with SMTP id abc; Wed, 17 Jun 2026 12:00:00 +0000",
            string.Empty
        });

        var healthCheck = new DomainHealthCheck();
        var analysis = healthCheck.CheckMessageHeaders(raw, new[] { "mail-gateway.example.com" });

        Assert.True(analysis.ExpectedMxBypassed);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == MessageHeaderCodes.ExpectedMxBypassed);
    }

    [Fact]
    public void DkimMissingWithPassingSpfAndDmarcDoesNotReportFailedAuthentication() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <spf-authenticated@example.net>",
            "From: sender@example.net",
            "To: recipient@example.com",
            "Subject: SPF authenticated",
            "Authentication-Results: mx.example.com; dkim=none; spf=pass smtp.mailfrom=example.net; dmarc=pass header.from=example.net",
            "X-MS-Exchange-Organization-AuthAs: Anonymous",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "X-Forefront-Antispam-Report: CIP:198.51.100.7;SCL:1;SFV:NSPM;H:sender.example.net",
            "Received: from sender.example.net (sender.example.net [198.51.100.7]) by example-com.mail.protection.outlook.com with SMTP id abc; Wed, 17 Jun 2026 12:00:00 +0000",
            string.Empty
        });

        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new InternalLogger());

        Assert.True(analysis.DkimMissingOrFailed);
        Assert.False(analysis.AuthenticationFailedDeliveredToInbox);
        Assert.DoesNotContain(MessageHeaderIssue.AuthenticationFailedDeliveredToInbox, analysis.Issues);
    }

    [Fact]
    public void SameDomainAuthenticatedInboxDeliveryIsNotSelfSpoof() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <internal@example.com>",
            "From: user@example.com",
            "To: colleague@example.com",
            "Subject: Internal mail",
            "Authentication-Results: mx.example.com; dkim=pass header.d=example.com; spf=pass smtp.mailfrom=example.com; dmarc=pass header.from=example.com",
            "X-MS-Exchange-Organization-AuthAs: Internal",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "Received: from internal.example.com by example-com.mail.protection.outlook.com with SMTP id abc; Wed, 17 Jun 2026 12:00:00 +0000",
            string.Empty
        });

        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new InternalLogger());

        Assert.True(analysis.SameDomainSelfSpoof);
        Assert.False(analysis.SelfSpoofDeliveredToInbox);
        Assert.DoesNotContain(MessageHeaderIssue.SelfSpoofDeliveredToInbox, analysis.Issues);
    }

    [Fact]
    public void GatewayLoopIsReported() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <loop-test@example.net>",
            "From: sender@example.net",
            "To: recipient@example.com",
            "Subject: Gateway loop",
            "Authentication-Results: mx.example.com; dkim=none; spf=fail smtp.mailfrom=example.net; dmarc=fail header.from=example.net",
            "X-MS-Exchange-Organization-AuthAs: Anonymous",
            "X-Example-O365-RedirectToProofpoint: true",
            "X-Proofpoint-Spam-Details: rule=notspam policy=default score=0",
            "X-Example-O365-EmailReceivedFromPP: true",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "X-Forefront-Antispam-Report: CIP:203.0.113.10;SCL:-1;SFV:SKN;H:sender.example.net",
            "Received: from mx0a-00000000.pphosted.com (mx0a-00000000.pphosted.com [203.0.113.20]) by example-com.mail.protection.outlook.com with ESMTPS id def; Wed, 17 Jun 2026 12:01:00 +0000",
            "Received: from example-com.mail.protection.outlook.com by mx0a-00000000.pphosted.com with ESMTPS id abc; Wed, 17 Jun 2026 12:00:30 +0000",
            string.Empty
        });

        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new InternalLogger());

        Assert.True(analysis.SeenMicrosoftEop);
        Assert.True(analysis.SeenProofpoint);
        Assert.True(analysis.RedirectedToProofpoint);
        Assert.True(analysis.ReceivedFromProofpoint);
        Assert.True(analysis.GatewayLoopDetected);
        Assert.Contains(MessageHeaderIssue.GatewayLoopDetected, analysis.Issues);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == MessageHeaderCodes.GatewayLoopDetected);
    }

    [Fact]
    public void GatewayLoopIsReportedFromReceivedRoute() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <received-loop@example.net>",
            "From: sender@example.net",
            "To: recipient@example.com",
            "Subject: Gateway loop",
            "Authentication-Results: mx.example.com; dkim=none; spf=fail smtp.mailfrom=example.net; dmarc=fail header.from=example.net",
            "X-MS-Exchange-Organization-AuthAs: Anonymous",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "X-Forefront-Antispam-Report: CIP:203.0.113.10;SCL:-1;SFV:SKN;H:sender.example.net",
            "Received: from mx0a-00000000.pphosted.com by example-com.mail.protection.outlook.com with ESMTPS id def; Wed, 17 Jun 2026 12:01:00 +0000",
            "Received: from example-com.mail.protection.outlook.com by mx0a-00000000.pphosted.com with ESMTPS id abc; Wed, 17 Jun 2026 12:00:30 +0000",
            string.Empty
        });

        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new InternalLogger());

        Assert.True(analysis.SeenMicrosoftEop);
        Assert.True(analysis.SeenProofpoint);
        Assert.True(analysis.GatewayLoopDetected);
        Assert.Contains(MessageHeaderIssue.GatewayLoopDetected, analysis.Issues);
    }
}
