using System;
using System.IO;
using System.Linq;

namespace DomainDetective.Tests {
    public class TestDnsblConfig {
        [Fact]
        public void LoadConfigWithClear() {
            var json = "{\"providers\":[{\"domain\":\"test.example\"},{\"domain\":\"another.test\",\"enabled\":false}]}";
            var file = Path.GetTempFileName();
            try {
                File.WriteAllText(file, json);

                var analysis = new DNSBLAnalysis();
                analysis.LoadDnsblConfig(file, clearExisting: true);
                using (File.Open(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) { }

                var entries = analysis.GetDNSBL().ToList();
                Assert.Equal(2, entries.Count);
                Assert.Contains(entries, e => e.Domain == "test.example");
                Assert.Contains(entries, e => e.Domain == "another.test" && !e.Enabled);
            }
            finally {
                File.Delete(file);
            }
        }

        [Fact]
        public void LoadConfigAddsMissing() {
            var json = "{\"providers\":[{\"domain\":\"added.test\"}]}"; 
            var file = Path.GetTempFileName();
            try {
                File.WriteAllText(file, json);

                var analysis = new DNSBLAnalysis();
                var before = analysis.GetDNSBL().Count;
                analysis.LoadDnsblConfig(file);
                using (File.Open(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) { }
                var after = analysis.GetDNSBL().Count;

                Assert.Equal(before + 1, after);
                Assert.Contains(analysis.GetDNSBL(), e => e.Domain == "added.test");
            }
            finally {
                File.Delete(file);
            }
        }

        [Fact]
        public void LoadConfigSkipsDuplicateProviders() {
            var json = "{\"providers\":[{\"domain\":\"dup.test\"},{\"domain\":\"DUP.Test\"}]}"; 
            var file = Path.GetTempFileName();
            try {
                File.WriteAllText(file, json);

                var analysis = new DNSBLAnalysis();
                analysis.LoadDnsblConfig(file, clearExisting: true);
                using (File.Open(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) { }

                var entries = analysis.GetDNSBL()
                    .Where(e => string.Equals(e.Domain, "dup.test", StringComparison.OrdinalIgnoreCase))
                    .ToList();
                Assert.Single(entries);
            }
            finally {
                File.Delete(file);
            }
        }

        [Fact]
        public void DefaultPortIs53() {
            var json = "{\"providers\":[{\"domain\":\"test.port\"}]}";
            var file = Path.GetTempFileName();
            try {
                File.WriteAllText(file, json);

                var analysis = new DNSBLAnalysis();
                analysis.LoadDnsblConfig(file, clearExisting: true);
                using (File.Open(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) { }

                var entry = Assert.Single(analysis.GetDNSBL());
                Assert.Equal(53, entry.Port);
            }
            finally {
                File.Delete(file);
            }
        }
    }}