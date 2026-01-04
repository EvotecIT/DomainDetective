using System;
using System.Collections.Generic;
using System.IO;
using DomainDetective.Reports.Office;
using Xunit;

namespace DomainDetective.Tests.Reports
{
    public class TestExcelDkimDetailsSmoke
    {
        [Fact]
        public void Excel_Generates_With_Dkim_Ttl_Details()
        {
            // Arrange
            var domain = "example.org";
            var items = new List<object>();
            items.Add(new DomainDetective.Views.MxInfo { Subject = domain, Status = "OK" });
            items.Add(new DomainDetective.Views.DkimRecordInfo {
                Subject = domain,
                Selector = "s1",
                Status = "OK",
                DkimRecordExists = true,
                PublicKeyExists = true,
                KeyLength = 2048,
                HashAlgorithm = "rsa-sha256",
                DkimRecord = "v=DKIM1; k=rsa; p=ABC..."
            });
            items.Add(new DomainDetective.Views.TtlInfo {
                Subject = domain,
                DkimTxtTtls = new System.Collections.Generic.Dictionary<string, System.Collections.Generic.IReadOnlyList<int>> {
                    { "s1._domainkey.example.org", new [] { 600, 300 } }
                }
            });

            var tmp = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".xlsx");

            ExcelCompositionReport.Generate(tmp, items, DomainDetective.Reports.ReportScope.Detailed);
            Assert.True(File.Exists(tmp));
            var len = new FileInfo(tmp).Length;
            Assert.True(len > 0);
        }
    }
}

