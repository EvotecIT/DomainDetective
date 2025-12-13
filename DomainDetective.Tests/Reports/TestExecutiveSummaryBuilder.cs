using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Reports;
using Xunit;

namespace DomainDetective.Tests.Reports
{
    public class TestExecutiveSummaryBuilder
    {
        [Fact]
        public void Builds_DKIM_WithSelectorCount_And_Dnssec_Rpki()
        {
            var items = new List<object>();
            // Minimal views for a single domain
            items.Add(new DomainDetective.Views.MxInfo { Subject = "example.com", Status = "OK" });
            items.Add(new DomainDetective.Views.SpfRecordInfo { Subject = "example.com", Status = "OK" });
            items.Add(new DomainDetective.Views.DmarcRecordInfo { Subject = "example.com", Status = "OK" });
            items.Add(new DomainDetective.Views.DkimRecordInfo { Subject = "example.com", Selector = "s1", Status = "OK", PublicKeyExists = true, KeyLength = 2048, HashAlgorithm = "rsa-sha256" });
            items.Add(new DomainDetective.Views.DkimRecordInfo { Subject = "example.com", Selector = "s2", Status = "OK", PublicKeyExists = true, KeyLength = 2048, HashAlgorithm = "rsa-sha256" });
            items.Add(new DomainDetective.Views.DnssecStatusInfo { Subject = "example.com", ChainValid = true, DsMatch = true, Status = "OK" });
            items.Add(new DomainDetective.Views.RpkiInfo { Subject = "example.com", TotalChecked = 3, ValidCount = 2, Status = "OK" });

            var rows = ExecutiveSummaryBuilder.Build(items, DomainOrder.Alphabetical);
            Assert.Single(rows);
            var r = rows[0];
            Assert.Equal("example.com", r.Domain);
            Assert.Contains("selectors", r.Dkim, StringComparison.OrdinalIgnoreCase);
            Assert.False(string.IsNullOrWhiteSpace(r.Dnssec));
            Assert.False(string.IsNullOrWhiteSpace(r.Rpki));
        }
    }
}

