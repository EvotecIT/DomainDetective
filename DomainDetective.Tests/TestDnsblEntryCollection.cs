using System;
namespace DomainDetective.Tests {
    public class TestDnsblEntryCollection {
        [Fact]
        public void AddNullThrows() {
            var collection = new DnsblEntryCollection();
            Assert.Throws<ArgumentNullException>(() => collection.Add(null!));
        }

        [Fact]
        public void AddInvalidDomainThrows() {
            var collection = new DnsblEntryCollection();
            var entry = new DnsblEntry { Domain = "" };
            Assert.Throws<ArgumentException>(() => collection.Add(entry));
        }
    }
}