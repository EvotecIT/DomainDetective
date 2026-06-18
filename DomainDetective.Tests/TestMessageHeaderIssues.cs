using System.Collections.Generic;
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
        Assert.DoesNotContain(MessageHeaderIssue.DirectToExchangeOnline, analysis.Issues);
        Assert.Contains(MessageHeaderIssue.AuthenticationFailedDeliveredToInbox, analysis.Issues);
        Assert.Contains(MessageHeaderIssue.SelfSpoofDeliveredToInbox, analysis.Issues);
        Assert.DoesNotContain(analysis.Assessments, assessment => assessment.Code == MessageHeaderCodes.DirectToExchangeOnlineObserved);
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
    public void ExpectedMxComparisonRequiresGatewayAtMicrosoftIngress() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <gateway-header-order@example.net>",
            "From: sender@example.net",
            "To: recipient@example.com",
            "Subject: Gateway header order",
            "Authentication-Results: mx.example.com; dkim=none; spf=fail smtp.mailfrom=example.net; dmarc=fail header.from=example.net",
            "X-MS-Exchange-Organization-AuthAs: Anonymous",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "X-Forefront-Antispam-Report: CIP:198.51.100.7;SCL:1;SFV:NSPM;H:sender.example.net",
            "Received: from sender.example.net (sender.example.net [198.51.100.7]) by example-com.mail.protection.outlook.com with SMTP id abc; Wed, 17 Jun 2026 12:02:00 +0000",
            "Received: from mail-gateway.example.com by example-com.mail.protection.outlook.com with ESMTPS id def; Wed, 17 Jun 2026 12:00:00 +0000",
            string.Empty
        });

        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new InternalLogger());
        analysis.CompareExpectedMx(new[] { "mail-gateway.example.com" });

        Assert.False(analysis.ExpectedMxObserved);
        Assert.True(analysis.ExpectedMxBypassed);
        Assert.True(analysis.DirectToExchangeOnlineObserved);
        Assert.Contains(MessageHeaderIssue.DirectToExchangeOnline, analysis.Issues);
        Assert.Contains(MessageHeaderIssue.ExpectedMxBypassed, analysis.Issues);
    }

    [Fact]
    public void ExpectedMxComparisonTreatsExpectedExchangeOnlineMxAsObserved() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <expected-eop-mx@example.net>",
            "From: sender@example.net",
            "To: recipient@example.com",
            "Subject: Expected EOP MX",
            "Authentication-Results: mx.example.com; dkim=none; spf=pass smtp.mailfrom=example.net; dmarc=pass header.from=example.net",
            "X-MS-Exchange-Organization-AuthAs: Anonymous",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "X-Forefront-Antispam-Report: CIP:198.51.100.7;SCL:1;SFV:NSPM;H:sender.example.net",
            "Received: from sender.example.net (sender.example.net [198.51.100.7]) by example-com.mail.protection.outlook.com with SMTP id abc; Wed, 17 Jun 2026 12:00:00 +0000",
            string.Empty
        });

        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new InternalLogger());
        analysis.CompareExpectedMx(new[] { "example-com.mail.protection.outlook.com" });

        Assert.True(analysis.ExpectedMxObserved);
        Assert.False(analysis.ExpectedMxBypassed);
        Assert.False(analysis.DirectToExchangeOnlineObserved);
        Assert.DoesNotContain(MessageHeaderIssue.DirectToExchangeOnline, analysis.Issues);
        Assert.DoesNotContain(MessageHeaderIssue.ExpectedMxBypassed, analysis.Issues);
    }

    [Fact]
    public void ExpectedMxComparisonSkipsMicrosoftInternalHopsForIngress() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <gateway-with-internal-eop@example.net>",
            "From: sender@example.net",
            "To: recipient@example.com",
            "Subject: Gateway with internal EOP",
            "Authentication-Results: mx.example.com; dkim=none; spf=fail smtp.mailfrom=example.net; dmarc=fail header.from=example.net",
            "X-MS-Exchange-Organization-AuthAs: Anonymous",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "X-Forefront-Antispam-Report: CIP:198.51.100.7;SCL:1;SFV:NSPM;H:mail-gateway.example.com",
            "Received: from EURP250MB0001.EURP250.PROD.OUTLOOK.COM by DB1PEPF00000001.mail.protection.outlook.com with ESMTPS id internal; Wed, 17 Jun 2026 12:02:00 +0000",
            "Received: from mail-gateway.example.com (mail-gateway.example.com [198.51.100.7]) by example-com.mail.protection.outlook.com with ESMTPS id abc; Wed, 17 Jun 2026 12:01:00 +0000",
            string.Empty
        });

        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new InternalLogger());
        analysis.CompareExpectedMx(new[] { "mail-gateway.example.com" });

        Assert.True(analysis.ExpectedMxObserved);
        Assert.False(analysis.ExpectedMxBypassed);
        Assert.False(analysis.DirectToExchangeOnlineObserved);
        Assert.DoesNotContain(MessageHeaderIssue.ExpectedMxBypassed, analysis.Issues);
    }

    [Fact]
    public void ExpectedMxComparisonRequiresHostBoundaryMatch() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <gateway-boundary@example.net>",
            "From: sender@example.net",
            "To: recipient@example.com",
            "Subject: Gateway boundary",
            "Authentication-Results: mx.example.com; dkim=none; spf=fail smtp.mailfrom=example.net; dmarc=fail header.from=example.net",
            "X-MS-Exchange-Organization-AuthAs: Anonymous",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "X-Forefront-Antispam-Report: CIP:198.51.100.7;SCL:1;SFV:NSPM;H:sender.example.net",
            "Received: from mail-gateway.example.com.evil.net (mail-gateway.example.com.evil.net [198.51.100.7]) by example-com.mail.protection.outlook.com with SMTP id abc; Wed, 17 Jun 2026 12:00:00 +0000",
            string.Empty
        });

        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new InternalLogger());
        analysis.CompareExpectedMx(new[] { "mail-gateway.example.com" });

        Assert.False(analysis.ExpectedMxObserved);
        Assert.True(analysis.ExpectedMxBypassed);
        Assert.True(analysis.DirectToExchangeOnlineObserved);
        Assert.Contains(MessageHeaderIssue.ExpectedMxBypassed, analysis.Issues);
    }

    [Fact]
    public void ExpectedMxComparisonIgnoresReceivedRawMentionsOutsideRouteHosts() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <gateway-raw-mention@example.net>",
            "From: sender@example.net",
            "To: recipient@example.com",
            "Subject: Gateway raw mention",
            "Authentication-Results: mx.example.com; dkim=none; spf=fail smtp.mailfrom=example.net; dmarc=fail header.from=example.net",
            "X-MS-Exchange-Organization-AuthAs: Anonymous",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "X-Forefront-Antispam-Report: CIP:198.51.100.7;SCL:1;SFV:NSPM;H:sender.example.net",
            "Received: from sender.example.net (sender.example.net [198.51.100.7]) by example-com.mail.protection.outlook.com for <mail-gateway.example.com>; Wed, 17 Jun 2026 12:00:00 +0000",
            string.Empty
        });

        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new InternalLogger());
        analysis.CompareExpectedMx(new[] { "mail-gateway.example.com" });

        Assert.False(analysis.ExpectedMxObserved);
        Assert.True(analysis.ExpectedMxBypassed);
        Assert.True(analysis.DirectToExchangeOnlineObserved);
        Assert.Contains(MessageHeaderIssue.ExpectedMxBypassed, analysis.Issues);
    }

    [Fact]
    public void ExpectedMxComparisonCanBeRepeatedWithDifferentHost() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <gateway-repeat@example.net>",
            "From: sender@example.net",
            "To: recipient@example.com",
            "Subject: Gateway repeat",
            "Authentication-Results: mx.example.com; dkim=none; spf=fail smtp.mailfrom=example.net; dmarc=fail header.from=example.net",
            "X-MS-Exchange-Organization-AuthAs: Anonymous",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "X-Forefront-Antispam-Report: CIP:198.51.100.7;SCL:1;SFV:NSPM;H:mail-gateway.example.com",
            "Received: from mail-gateway.example.com (mail-gateway.example.com [198.51.100.7]) by example-com.mail.protection.outlook.com with SMTP id abc; Wed, 17 Jun 2026 12:00:00 +0000",
            string.Empty
        });

        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new InternalLogger());
        analysis.CompareExpectedMx(new[] { "mail-gateway.example.com" });

        Assert.True(analysis.ExpectedMxObserved);
        Assert.False(analysis.ExpectedMxBypassed);
        Assert.False(analysis.DirectToExchangeOnlineObserved);

        analysis.CompareExpectedMx(new[] { "other-gateway.example.com" });

        Assert.False(analysis.ExpectedMxObserved);
        Assert.True(analysis.ExpectedMxBypassed);
        Assert.True(analysis.DirectToExchangeOnlineObserved);
        Assert.Contains(MessageHeaderIssue.DirectToExchangeOnline, analysis.Issues);
        Assert.Contains(MessageHeaderIssue.ExpectedMxBypassed, analysis.Issues);
    }

    [Fact]
    public void ExpectedMxComparisonClearsBypassFindingsWhenExpectedMxCleared() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <gateway-clear@example.net>",
            "From: sender@example.net",
            "To: recipient@example.com",
            "Subject: Gateway clear",
            "Authentication-Results: mx.example.com; dkim=none; spf=fail smtp.mailfrom=example.net; dmarc=fail header.from=example.net",
            "X-MS-Exchange-Organization-AuthAs: Anonymous",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "X-Forefront-Antispam-Report: CIP:198.51.100.7;SCL:1;SFV:NSPM;H:sender.example.net",
            "Received: from sender.example.net (sender.example.net [198.51.100.7]) by example-com.mail.protection.outlook.com with SMTP id abc; Wed, 17 Jun 2026 12:00:00 +0000",
            string.Empty
        });
        var logger = new InternalLogger();

        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, logger);
        analysis.CompareExpectedMx(new[] { "mail-gateway.example.com" }, logger);

        Assert.True(analysis.ExpectedMxBypassed);
        Assert.Contains(MessageHeaderIssue.DirectToExchangeOnline, analysis.Issues);
        Assert.Contains(MessageHeaderIssue.ExpectedMxBypassed, analysis.Issues);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == MessageHeaderCodes.DirectToExchangeOnlineObserved);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == MessageHeaderCodes.ExpectedMxBypassed);

        analysis.CompareExpectedMx(null, logger);

        Assert.Empty(analysis.ExpectedMxHosts);
        Assert.False(analysis.ExpectedMxBypassed);
        Assert.DoesNotContain(MessageHeaderIssue.DirectToExchangeOnline, analysis.Issues);
        Assert.DoesNotContain(MessageHeaderIssue.ExpectedMxBypassed, analysis.Issues);
        Assert.DoesNotContain(analysis.Assessments, assessment => assessment.Code == MessageHeaderCodes.DirectToExchangeOnlineObserved);
        Assert.DoesNotContain(analysis.Assessments, assessment => assessment.Code == MessageHeaderCodes.ExpectedMxBypassed);
    }

    [Fact]
    public void ExpectedMxComparisonPreservesAssessmentsWhenRepeatedWithSameLogger() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <gateway-repeat-assessments@example.net>",
            "From: sender@example.net",
            "To: recipient@example.com",
            "Subject: Gateway repeat assessments",
            "Authentication-Results: mx.example.com; dkim=none; spf=fail smtp.mailfrom=example.net; dmarc=fail header.from=example.net",
            "X-MS-Exchange-Organization-AuthAs: Anonymous",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "X-Forefront-Antispam-Report: CIP:198.51.100.7;SCL:1;SFV:NSPM;H:sender.example.net",
            "Received: from sender.example.net (sender.example.net [198.51.100.7]) by example-com.mail.protection.outlook.com with SMTP id abc; Wed, 17 Jun 2026 12:00:00 +0000",
            string.Empty
        });
        var logger = new InternalLogger();

        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, logger);
        analysis.CompareExpectedMx(new[] { "first-gateway.example.com" }, logger);
        analysis.CompareExpectedMx(new[] { "second-gateway.example.com" }, logger);

        Assert.True(analysis.ExpectedMxBypassed);
        Assert.Contains(MessageHeaderIssue.DirectToExchangeOnline, analysis.Issues);
        Assert.Contains(MessageHeaderIssue.ExpectedMxBypassed, analysis.Issues);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == MessageHeaderCodes.DirectToExchangeOnlineObserved);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == MessageHeaderCodes.ExpectedMxBypassed);
    }

    [Fact]
    public void ExpectedMxComparisonIgnoresSpoofedMicrosoftHeadersWithoutEopHop() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <spoofed-microsoft-headers@example.net>",
            "From: sender@example.net",
            "To: recipient@example.com",
            "Subject: Spoofed Microsoft headers",
            "Authentication-Results: mx.example.com; dkim=none; spf=fail smtp.mailfrom=example.net; dmarc=fail header.from=example.net",
            "X-MS-Exchange-Organization-AuthAs: Anonymous",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "X-Forefront-Antispam-Report: CIP:198.51.100.7;SCL:1;SFV:NSPM;H:sender.example.net",
            "Received: from sender.example.net (sender.example.net [198.51.100.7]) by mail-gateway.example.com with SMTP id abc; Wed, 17 Jun 2026 12:00:00 +0000",
            string.Empty
        });

        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new InternalLogger());
        analysis.CompareExpectedMx(new[] { "mail-gateway.example.com" });

        Assert.True(analysis.SeenMicrosoftEop);
        Assert.False(analysis.DirectToExchangeOnlineObserved);
        Assert.False(analysis.ExpectedMxBypassed);
        Assert.DoesNotContain(MessageHeaderIssue.DirectToExchangeOnline, analysis.Issues);
        Assert.DoesNotContain(MessageHeaderIssue.ExpectedMxBypassed, analysis.Issues);
    }

    [Fact]
    public void ExpectedMxComparisonRequiresMicrosoftIngressHopForDirectBypass() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <outbound-microsoft-hop@example.net>",
            "From: sender@example.net",
            "To: recipient@example.com",
            "Subject: Outbound Microsoft hop",
            "Authentication-Results: mx.example.com; dkim=none; spf=fail smtp.mailfrom=example.net; dmarc=fail header.from=example.net",
            "X-MS-Exchange-Organization-AuthAs: Anonymous",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "X-Forefront-Antispam-Report: CIP:198.51.100.7;SCL:1;SFV:NSPM;H:sender.mail.protection.outlook.com",
            "Received: from sender.mail.protection.outlook.com by mail-gateway.example.com with ESMTPS id abc; Wed, 17 Jun 2026 12:00:00 +0000",
            string.Empty
        });

        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new InternalLogger());
        analysis.CompareExpectedMx(new[] { "mail-gateway.example.com" });

        Assert.True(analysis.SeenMicrosoftEop);
        Assert.False(analysis.DirectToExchangeOnlineObserved);
        Assert.False(analysis.ExpectedMxBypassed);
        Assert.DoesNotContain(MessageHeaderIssue.DirectToExchangeOnline, analysis.Issues);
        Assert.DoesNotContain(MessageHeaderIssue.ExpectedMxBypassed, analysis.Issues);
    }

    [Fact]
    public void ProviderDetectionUsesDnsBoundaryMatching() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <provider-boundary@example.net>",
            "From: sender@example.net",
            "To: recipient@example.com",
            "Subject: Provider boundary",
            "Authentication-Results: mx.example.com; dkim=none; spf=fail smtp.mailfrom=example.net; dmarc=fail header.from=example.net",
            "X-MS-Exchange-Organization-AuthAs: Anonymous",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "X-Forefront-Antispam-Report: CIP:198.51.100.7;SCL:1;SFV:NSPM;H:sender.example.net",
            "Received: from sender.example.net (sender.example.net [198.51.100.7]) by example-com.mail.protection.outlook.com.evil.net with SMTP id abc; Wed, 17 Jun 2026 12:00:00 +0000",
            "Received: from sender.example.net by mx.pphosted.com.evil.net with ESMTPS id def; Wed, 17 Jun 2026 12:01:00 +0000",
            string.Empty
        });

        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new InternalLogger());
        analysis.CompareExpectedMx(new[] { "mail-gateway.example.com" });

        Assert.False(analysis.DirectToExchangeOnlineObserved);
        Assert.False(analysis.ExpectedMxBypassed);
        Assert.False(analysis.GatewayLoopDetected);
        Assert.DoesNotContain(MessageHeaderIssue.DirectToExchangeOnline, analysis.Issues);
        Assert.DoesNotContain(MessageHeaderIssue.ExpectedMxBypassed, analysis.Issues);
        Assert.DoesNotContain(MessageHeaderIssue.GatewayLoopDetected, analysis.Issues);
    }

    [Fact]
    public void ProofpointDotComProviderHostIsDetected() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <proofpoint-dot-com@example.net>",
            "From: sender@example.net",
            "To: recipient@example.com",
            "Subject: Proofpoint dot com",
            "Authentication-Results: mx.example.com; dkim=none; spf=fail smtp.mailfrom=example.net; dmarc=fail header.from=example.net",
            "X-MS-Exchange-Organization-AuthAs: Anonymous",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "X-Forefront-Antispam-Report: CIP:203.0.113.10;SCL:-1;SFV:SKN;H:sender.example.net",
            "Received: from mx.proofpoint.com by example-com.mail.protection.outlook.com with ESMTPS id def; Wed, 17 Jun 2026 12:01:00 +0000",
            "Received: from example-com.mail.protection.outlook.com by mx.proofpoint.com with ESMTPS id abc; Wed, 17 Jun 2026 12:00:30 +0000",
            string.Empty
        });

        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new InternalLogger());

        Assert.True(analysis.SeenProofpoint);
    }

    [Fact]
    public void ExpectedMxComparisonSuppressesDirectEopWarningForObservedGateway() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <gateway-logger@example.net>",
            "From: sender@example.net",
            "To: recipient@example.com",
            "Subject: Gateway logger",
            "Authentication-Results: mx.example.com; dkim=none; spf=fail smtp.mailfrom=example.net; dmarc=fail header.from=example.net",
            "X-MS-Exchange-Organization-AuthAs: Anonymous",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "X-Forefront-Antispam-Report: CIP:198.51.100.7;SCL:1;SFV:NSPM;H:mail-gateway.example.com",
            "Received: from mail-gateway.example.com (mail-gateway.example.com [198.51.100.7]) by example-com.mail.protection.outlook.com with SMTP id abc; Wed, 17 Jun 2026 12:00:00 +0000",
            string.Empty
        });
        var logger = new InternalLogger();
        var warnings = new List<LogEventArgs>();
        logger.OnWarningMessage += (_, warning) => warnings.Add(warning);
        var healthCheck = new DomainHealthCheck(internalLogger: logger);

        var analysis = healthCheck.CheckMessageHeaders(raw, new[] { "mail-gateway.example.com" });

        Assert.True(analysis.ExpectedMxObserved);
        Assert.False(analysis.DirectToExchangeOnlineObserved);
        Assert.DoesNotContain(MessageHeaderIssue.DirectToExchangeOnline, analysis.Issues);
        Assert.DoesNotContain(warnings, warning => warning.Code == MessageHeaderCodes.DirectToExchangeOnlineObserved);
        Assert.DoesNotContain(analysis.Assessments, assessment => assessment.Code == MessageHeaderCodes.DirectToExchangeOnlineObserved);
    }

    [Fact]
    public void ExpectedMxComparisonPreservesParseAssessments() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <gateway-auth-pass@example.net>",
            "From: sender@example.net",
            "To: recipient@example.com",
            "Subject: Gateway auth pass",
            "Authentication-Results: mx.example.com; dkim=pass; spf=pass; dmarc=pass; arc=pass",
            "X-MS-Exchange-Organization-AuthAs: Anonymous",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "X-Forefront-Antispam-Report: CIP:198.51.100.7;SCL:1;SFV:NSPM;H:mail-gateway.example.com",
            "Received: from mail-gateway.example.com (mail-gateway.example.com [198.51.100.7]) by example-com.mail.protection.outlook.com with SMTP id abc; Wed, 17 Jun 2026 12:00:00 +0000",
            string.Empty
        });
        var healthCheck = new DomainHealthCheck(internalLogger: new InternalLogger());

        var analysis = healthCheck.CheckMessageHeaders(raw, new[] { "mail-gateway.example.com" });

        Assert.True(analysis.ExpectedMxObserved);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == MessageHeaderCodes.DkimPass);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == MessageHeaderCodes.SpfPass);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == MessageHeaderCodes.DmarcPass);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == MessageHeaderCodes.ArcPass);
        Assert.DoesNotContain(analysis.Assessments, assessment => assessment.Code == MessageHeaderCodes.DirectToExchangeOnlineObserved);
    }

    [Fact]
    public void RouteDiagnosticsUseTopmostForefrontHeader() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <duplicate-forefront@example.net>",
            "From: sender@example.net",
            "To: recipient@example.com",
            "Subject: Duplicate Forefront",
            "Authentication-Results: mx.example.com; dkim=none; spf=fail smtp.mailfrom=example.net; dmarc=fail header.from=example.net",
            "X-MS-Exchange-Organization-AuthAs: Anonymous",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "X-Forefront-Antispam-Report: CIP:198.51.100.7;SCL:1;SFV:NSPM;H:sender.example.net",
            "X-Forefront-Antispam-Report: SCL:1;SFV:NSPM;H:mail-gateway.example.com",
            "Received: from sender.example.net (sender.example.net [198.51.100.7]) by example-com.mail.protection.outlook.com with SMTP id abc; Wed, 17 Jun 2026 12:00:00 +0000",
            string.Empty
        });

        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new InternalLogger());
        analysis.CompareExpectedMx(new[] { "mail-gateway.example.com" });

        Assert.Equal("198.51.100.7", analysis.ForefrontSourceIp);
        Assert.Equal("sender.example.net", analysis.ForefrontHost);
        Assert.False(analysis.ExpectedMxObserved);
        Assert.True(analysis.ExpectedMxBypassed);
        Assert.True(analysis.DirectToExchangeOnlineObserved);
    }

    [Fact]
    public void ExpectedMxComparisonDoesNotTrustForefrontHostAsGatewayEvidence() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <forefront-h-gateway@example.net>",
            "From: sender@example.net",
            "To: recipient@example.com",
            "Subject: Forefront H gateway",
            "Authentication-Results: mx.example.com; dkim=none; spf=fail smtp.mailfrom=example.net; dmarc=fail header.from=example.net",
            "X-MS-Exchange-Organization-AuthAs: Anonymous",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "X-Forefront-Antispam-Report: CIP:198.51.100.7;SCL:1;SFV:NSPM;H:mail-gateway.example.com",
            "Received: from sender.example.net (sender.example.net [198.51.100.7]) by example-com.mail.protection.outlook.com with SMTP id abc; Wed, 17 Jun 2026 12:00:00 +0000",
            string.Empty
        });

        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new InternalLogger());
        analysis.CompareExpectedMx(new[] { "mail-gateway.example.com" });

        Assert.Equal("mail-gateway.example.com", analysis.ForefrontHost);
        Assert.False(analysis.ExpectedMxObserved);
        Assert.True(analysis.ExpectedMxBypassed);
        Assert.Contains(MessageHeaderIssue.ExpectedMxBypassed, analysis.Issues);
    }

    [Fact]
    public void DirectExchangeOnlineUsesCrossTenantAuthAsFallback() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <cross-tenant-authas@example.net>",
            "From: sender@example.net",
            "To: recipient@example.com",
            "Subject: CrossTenant AuthAs",
            "Authentication-Results: mx.example.com; dkim=none; spf=fail smtp.mailfrom=example.net; dmarc=fail header.from=example.net",
            "X-MS-Exchange-CrossTenant-AuthAs: Anonymous",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "X-Forefront-Antispam-Report: CIP:198.51.100.7;SCL:1;SFV:NSPM;H:sender.example.net",
            "Received: from sender.example.net (sender.example.net [198.51.100.7]) by example-com.mail.protection.outlook.com with SMTP id abc; Wed, 17 Jun 2026 12:00:00 +0000",
            string.Empty
        });

        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new InternalLogger());
        analysis.CompareExpectedMx(new[] { "mail-gateway.example.com" });

        Assert.Equal("Anonymous", analysis.CrossTenantAuthAs);
        Assert.True(analysis.DirectToExchangeOnlineObserved);
        Assert.True(analysis.ExpectedMxBypassed);
        Assert.Contains(MessageHeaderIssue.DirectToExchangeOnline, analysis.Issues);
        Assert.Contains(MessageHeaderIssue.ExpectedMxBypassed, analysis.Issues);
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
    public void PassingDmarcDoesNotReportInboxAuthenticationFailureForSpfSoftFail() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <dmarc-pass-spf-softfail@example.net>",
            "From: sender@example.net",
            "To: recipient@example.com",
            "Subject: DMARC pass SPF softfail",
            "Authentication-Results: mx.example.com; dkim=pass header.d=example.net; spf=softfail smtp.mailfrom=example.net; dmarc=pass header.from=example.net",
            "X-MS-Exchange-Organization-AuthAs: Anonymous",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "X-Forefront-Antispam-Report: CIP:198.51.100.7;SCL:1;SFV:NSPM;H:sender.example.net",
            "Received: from sender.example.net (sender.example.net [198.51.100.7]) by example-com.mail.protection.outlook.com with SMTP id abc; Wed, 17 Jun 2026 12:00:00 +0000",
            string.Empty
        });

        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new InternalLogger());

        Assert.True(analysis.SpfFailedOrSoftFailed);
        Assert.False(analysis.DmarcFailed);
        Assert.False(analysis.AuthenticationFailedDeliveredToInbox);
        Assert.DoesNotContain(MessageHeaderIssue.AuthenticationFailedDeliveredToInbox, analysis.Issues);
    }

    [Fact]
    public void InboxAuthenticationWarningUsesTrustedAuthenticationResults() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <spoofed-auth-results@example.net>",
            "From: sender@example.net",
            "To: recipient@example.com",
            "Subject: Spoofed auth results",
            "Authentication-Results: mx.example.com; dkim=none; spf=fail smtp.mailfrom=example.net; dmarc=fail header.from=example.net",
            "Authentication-Results: attacker.example.net; dkim=pass header.d=example.net; spf=pass smtp.mailfrom=example.net; dmarc=pass header.from=example.net",
            "X-MS-Exchange-Organization-AuthAs: Anonymous",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "X-Forefront-Antispam-Report: CIP:198.51.100.7;SCL:1;SFV:NSPM;H:sender.example.net",
            "Received: from sender.example.net (sender.example.net [198.51.100.7]) by example-com.mail.protection.outlook.com with SMTP id abc; Wed, 17 Jun 2026 12:00:00 +0000",
            string.Empty
        });

        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new InternalLogger());

        Assert.Equal("pass header.from=example.net", analysis.DmarcResult);
        Assert.True(analysis.AuthenticationFailedDeliveredToInbox);
        Assert.Contains(MessageHeaderIssue.AuthenticationFailedDeliveredToInbox, analysis.Issues);
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
    public void SameDomainSelfSpoofChecksAllRecipients() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <recipient-list@example.com>",
            "From: spoofed@example.com",
            "To: user@example.net, target@example.com",
            "Subject: Recipient list",
            "Authentication-Results: mx.example.com; dkim=none; spf=fail smtp.mailfrom=example.com; dmarc=fail header.from=example.com",
            "X-MS-Exchange-Organization-AuthAs: Anonymous",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "X-Forefront-Antispam-Report: CIP:192.0.2.25;SCL:1;SFV:NSPM;H:sender.example.net",
            "Received: from sender.example.net (sender.example.net [192.0.2.25]) by example-com.mail.protection.outlook.com with SMTP id abc; Wed, 17 Jun 2026 12:00:00 +0000",
            string.Empty
        });

        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new InternalLogger());

        Assert.True(analysis.SameDomainSelfSpoof);
        Assert.True(analysis.SelfSpoofDeliveredToInbox);
        Assert.Contains(MessageHeaderIssue.SelfSpoofDeliveredToInbox, analysis.Issues);
    }

    [Fact]
    public void ExpectedMxComparisonDoesNotDuplicateParseRouteAssessments() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <no-duplicate-route-assessment@example.com>",
            "From: spoofed@example.com",
            "To: target@example.com",
            "Subject: No duplicate route assessment",
            "Authentication-Results: mx.example.com; dkim=none; spf=fail smtp.mailfrom=example.com; dmarc=fail header.from=example.com",
            "X-MS-Exchange-Organization-AuthAs: Anonymous",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "X-Forefront-Antispam-Report: CIP:192.0.2.25;SCL:1;SFV:NSPM;H:sender.example.net",
            "Received: from sender.example.net (sender.example.net [192.0.2.25]) by example-com.mail.protection.outlook.com with SMTP id abc; Wed, 17 Jun 2026 12:00:00 +0000",
            string.Empty
        });
        var logger = new InternalLogger();

        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, logger);
        analysis.CompareExpectedMx(new[] { "mail-gateway.example.com" }, logger);

        Assert.Equal(1, analysis.Assessments.Count(assessment => assessment.Code == MessageHeaderCodes.AuthenticationFailedDeliveredToInbox));
        Assert.Equal(1, analysis.Assessments.Count(assessment => assessment.Code == MessageHeaderCodes.SelfSpoofDeliveredToInbox));
        Assert.Equal(1, analysis.Assessments.Count(assessment => assessment.Code == MessageHeaderCodes.DirectToExchangeOnlineObserved));
        Assert.Equal(1, analysis.Assessments.Count(assessment => assessment.Code == MessageHeaderCodes.ExpectedMxBypassed));
    }

    [Fact]
    public void ExpectedMxHealthCheckPreservesNonMxRouteAssessments() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <healthcheck-non-mx-route@example.com>",
            "From: spoofed@example.com",
            "To: target@example.com",
            "Subject: Health check non MX route",
            "Authentication-Results: mx.example.com; dkim=none; spf=fail smtp.mailfrom=example.com; dmarc=fail header.from=example.com",
            "X-MS-Exchange-Organization-AuthAs: Anonymous",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "X-Forefront-Antispam-Report: CIP:192.0.2.25;SCL:1;SFV:NSPM;H:sender.example.net",
            "Received: from sender.example.net (sender.example.net [192.0.2.25]) by example-com.mail.protection.outlook.com with SMTP id abc; Wed, 17 Jun 2026 12:00:00 +0000",
            string.Empty
        });

        var healthCheck = new DomainHealthCheck(internalLogger: new InternalLogger());

        var analysis = healthCheck.CheckMessageHeaders(raw, new[] { "mail-gateway.example.com" });

        Assert.True(analysis.AuthenticationFailedDeliveredToInbox);
        Assert.True(analysis.SelfSpoofDeliveredToInbox);
        Assert.True(analysis.ExpectedMxBypassed);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == MessageHeaderCodes.AuthenticationFailedDeliveredToInbox);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == MessageHeaderCodes.SelfSpoofDeliveredToInbox);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == MessageHeaderCodes.DirectToExchangeOnlineObserved);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == MessageHeaderCodes.ExpectedMxBypassed);
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

    [Fact]
    public void CrossTenantGatewayDeliveryIsNotReportedAsGatewayLoop() {
        var raw = string.Join("\r\n", new[] {
            "Message-ID: <cross-tenant-gateway@example.net>",
            "From: sender@example.net",
            "To: recipient@example.com",
            "Subject: Cross tenant gateway",
            "Authentication-Results: mx.example.com; dkim=pass; spf=pass smtp.mailfrom=example.net; dmarc=pass header.from=example.net",
            "X-MS-Exchange-Organization-AuthAs: Anonymous",
            "X-Microsoft-Antispam-Mailbox-Delivery: dest:I",
            "X-Forefront-Antispam-Report: CIP:203.0.113.20;SCL:1;SFV:NSPM;H:mx0a-00000000.pphosted.com",
            "Received: from mx0a-00000000.pphosted.com by recipient-com.mail.protection.outlook.com with ESMTPS id def; Wed, 17 Jun 2026 12:01:00 +0000",
            "Received: from sender-com.mail.protection.outlook.com by mx0a-00000000.pphosted.com with ESMTPS id abc; Wed, 17 Jun 2026 12:00:30 +0000",
            string.Empty
        });

        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new InternalLogger());

        Assert.True(analysis.SeenMicrosoftEop);
        Assert.True(analysis.SeenProofpoint);
        Assert.False(analysis.GatewayLoopDetected);
        Assert.DoesNotContain(MessageHeaderIssue.GatewayLoopDetected, analysis.Issues);
    }
}
