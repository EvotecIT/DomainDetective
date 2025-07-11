using DnsClientX;
using DomainDetective;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using Xunit;

namespace DomainDetective.Tests {
    public class TestDnsSnapshots {
        [Fact]
        public void DetectsSnapshotChanges() {
            var dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Directory.CreateDirectory(dir);
            try {
                var analysis = new DnsPropagationAnalysis { SnapshotDirectory = dir };
                var first = new List<DnsPropagationResult> {
                    new() {
                        Server = new PublicDnsEntry { IPAddress = IPAddress.Parse("1.1.1.1"), Enabled = true },
                        RecordType = DnsRecordType.A,
                        Records = new[] { "1.2.3.4" },
                        Success = true
                    }
                };
                analysis.SaveSnapshot("example.com", DnsRecordType.A, first);

                var second = new List<DnsPropagationResult> {
                    new() {
                        Server = new PublicDnsEntry { IPAddress = IPAddress.Parse("1.1.1.1"), Enabled = true },
                        RecordType = DnsRecordType.A,
                        Records = new[] { "4.5.6.7" },
                        Success = true
                    }
                };
                var diff = analysis.GetSnapshotChanges("example.com", DnsRecordType.A, second).ToList();
                analysis.SaveSnapshot("example.com", DnsRecordType.A, second);
                Assert.Contains("- 1.1.1.1:1.2.3.4", diff);
                Assert.Contains("+ 1.1.1.1:4.5.6.7", diff);
            } finally {
                Directory.Delete(dir, true);
            }
        }
    }
}
