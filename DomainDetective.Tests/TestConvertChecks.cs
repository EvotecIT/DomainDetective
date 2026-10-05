using System.Collections.Generic;
using System.Linq;
using DomainDetective.Views;
using Xunit;

namespace DomainDetective.Tests {
    public class TestConvertChecks {
        [Fact]
        public void ConvertChecks_ConvertsRequestedChecksOnce() {
            var health = new DomainHealthCheck();
            var errors = new List<string>();

            IReadOnlyList<object> items = Converters.ConvertChecks(health, new[] {
                HealthCheckType.SPF,
                HealthCheckType.DMARC,
                HealthCheckType.NS,
                HealthCheckType.DELEGATION, // shares the NS analysis
                HealthCheckType.WILDCARDDNS,
                HealthCheckType.HTTP        // never reached a site, so it did not run
            }, errors);

            Assert.Empty(errors);
            Assert.Collection(items,
                item => Assert.IsType<SpfRecordInfo>(item),
                item => Assert.IsType<DmarcRecordInfo>(item),
                item => Assert.IsType<NsInfo>(item),
                item => Assert.IsType<WildcardDnsInfo>(item));
        }

        [Fact]
        public void ConvertChecks_DefaultsToTheChecksTheLastRunExecuted() {
            var health = new DomainHealthCheck();

            Assert.Empty(health.LastVerifiedChecks);
            Assert.Empty(Converters.ConvertChecks(health));
        }

        [Fact]
        public void ConvertChecks_PassesFinishedViewsThroughAndLeavesMessageHeadersOut() {
            var health = new DomainHealthCheck();
            var errors = new List<string>();

            // MESSAGEHEADER is one of the default checks but describes a message, not the domain.
            IReadOnlyList<object> items = Converters.ConvertChecks(health, new[] { HealthCheckType.WEBSITE, HealthCheckType.MESSAGEHEADER }, errors);

            Assert.Contains(items, static item => item is WebsiteInfo);
            Assert.Empty(errors);
        }

        [Fact]
        public void ConvertChecks_EveryCheckOfADomainRunHasAView() {
            var health = new DomainHealthCheck();
            var errors = new List<string>();
            var checks = new[] { HealthCheckType.ROBOTS, HealthCheckType.HPKP, HealthCheckType.SNMP, HealthCheckType.NTP, HealthCheckType.FLATTENINGSERVICE };

            IReadOnlyList<object> items = Converters.ConvertChecks(health, checks, errors);

            Assert.Empty(errors);
            Assert.Contains(items, static item => item is RobotsTxtInfo);
            Assert.Contains(items, static item => item is HpkpInfo);
            Assert.Contains(items, static item => item is SnmpInfo);
            Assert.Contains(items, static item => item is NtpInfo);
            Assert.Contains(items, static item => item is FlatteningServiceInfo);
        }

        [Fact]
        public void ConvertChecks_FlattensChecksWithSeveralViews() {
            var health = new DomainHealthCheck();

            IReadOnlyList<object> items = Converters.ConvertChecks(health, new[] { HealthCheckType.DKIM, HealthCheckType.MX });

            Assert.All(items, static item => Assert.False(item is System.Collections.IEnumerable and not string));
            Assert.Contains(items, static item => item is MxInfo);
        }
    }
}
