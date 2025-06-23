using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Xunit;

namespace DomainDetective.Tests {
    public class TestDnsblDuplicates {
        [Fact]
        public void ConvertToResultsReplacesExistingEntry() {
            var analysis = new DNSBLAnalysis();
            var method = typeof(DNSBLAnalysis).GetMethod("ConvertToResults", BindingFlags.NonPublic | BindingFlags.Instance);
            var first = new[] { new DNSBLRecord { IPAddress = "1.2.3.4", FQDN = "1.2.3.4.test", BlackList = "first", IsBlackListed = true, Answer = "127.0.0.2" } };
            method.Invoke(analysis, new object[] { "1.2.3.4", first });
            var second = new[] { new DNSBLRecord { IPAddress = "1.2.3.4", FQDN = "1.2.3.4.test2", BlackList = "second", IsBlackListed = false, Answer = string.Empty } };
            method.Invoke(analysis, new object[] { "1.2.3.4", second });

            Assert.Single(analysis.Results);
            Assert.Equal("second", analysis.Results["1.2.3.4"].DNSBLRecords.First().BlackList);
        }
    }
}
