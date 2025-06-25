using DnsClientX;
using DomainDetective;
using System;

namespace DomainDetective.Tests {
    public class TestDnsConfiguration {
        [Fact]
        public async Task QueryFullDNSThrowsIfNamesNull() {
            var config = new DnsConfiguration();
            await Assert.ThrowsAsync<ArgumentNullException>(async () =>
                await config.QueryFullDNS(null!, DnsRecordType.A));
        }

        [Fact]
        public async Task QueryFullDNSThrowsIfNamesEmpty() {
            var config = new DnsConfiguration();
            await Assert.ThrowsAsync<ArgumentNullException>(async () =>
                await config.QueryFullDNS(Array.Empty<string>(), DnsRecordType.A));
        }

        [Fact]
        public async Task QueryDNSThrowsIfNameNull() {
            var config = new DnsConfiguration();
            await Assert.ThrowsAsync<ArgumentNullException>(async () =>
                await config.QueryDNS((string)null!, DnsRecordType.A));
        }

        [Fact]
        public async Task QueryDNSThrowsIfNameEmpty() {
            var config = new DnsConfiguration();
            await Assert.ThrowsAsync<ArgumentNullException>(async () =>
                await config.QueryDNS(string.Empty, DnsRecordType.A));
        }
    }
}