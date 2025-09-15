using System;
using System.Collections.Generic;
using DomainDetective.Reports;
using Xunit;

namespace DomainDetective.Tests.Reports
{
    public class TestOverviewWording
    {
        [Fact]
        public void ComposeFromItems_Builds_Uniform_Sentence()
        {
            var items = new List<object>();
            // Domain A with many controls
            items.Add(new DomainDetective.Views.MxInfo { Subject = "example.com", Status = "OK" });
            items.Add(new DomainDetective.Views.SpfRecordInfo { Subject = "example.com", Status = "OK" });
            items.Add(new DomainDetective.Views.DkimRecordInfo { Subject = "example.com", Selector = "s1", Status = "OK" });
            items.Add(new DomainDetective.Views.DmarcRecordInfo { Subject = "example.com", Status = "OK" });
            items.Add(new DomainDetective.Views.MtastsInfo { Subject = "example.com", Status = "OK" });
            items.Add(new DomainDetective.Views.TlsRptInfo { Subject = "example.com", Status = "OK" });
            items.Add(new DomainDetective.Views.MailTlsInfo { Subject = "example.com", Status = "OK", Check = DomainDetective.HealthCheckType.SMTPTLS });

            // Domain B with SPF only
            items.Add(new DomainDetective.Views.SpfRecordInfo { Subject = "sample.net", Status = "OK" });

            var text = OverviewWording.ComposeFromItems(items);
            var expected = "This report summarizes the email security posture for 2 domain(s). The table highlights the presence and status of key controls (MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, MAILTLS) and the count of warnings/errors detected. Total across all domains: 0 warning(s), 0 error(s).";
            Assert.Equal(expected, text);
        }
    }
}

