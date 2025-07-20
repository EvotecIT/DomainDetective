using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using DnsClientX;
namespace DomainDetective.Tests {
    public class TestGeoLookup {
        [Fact]
        public async Task LookupUsesOverride() {
            var analysis = new DnsPropagationAnalysis {
                GeoLookupOverride = (ip, _) => Task.FromResult<GeoLocationInfo?>(new GeoLocationInfo { Country = "US", Region = "NY" })
            };
            var info = await analysis.GetGeoLocationAsync("1.1.1.1", CancellationToken.None);
            Assert.NotNull(info);
            Assert.Equal("US", info!.Country);
            Assert.Equal("NY", info.Region);
        }

        [Fact]
        public async Task QueryAsyncPopulatesGeo() {
            var analysis = new DnsPropagationAnalysis {
                DnsQueryOverride = (_, _, _, _) => Task.FromResult<IEnumerable<string>>(new[] { "1.2.3.4" }),
                GeoLookupOverride = (ip, _) => Task.FromResult<GeoLocationInfo?>(new GeoLocationInfo { Country = "US", Region = "Test" })
            };
            var server = new PublicDnsEntry { IPAddress = IPAddress.Loopback, Country = CountryId.UnitedStates, Enabled = true };
            var results = await analysis.QueryAsync("example.com", DnsRecordType.A, new[] { server }, includeGeo: true);
            var result = Assert.Single(results);
            Assert.NotNull(result.Geo);
            Assert.Equal("Test", result.Geo!["1.2.3.4"].Region);
        }

        [Fact]
        public async Task QueryAsyncWithoutGeoProducesNull() {
            var analysis = new DnsPropagationAnalysis {
                DnsQueryOverride = (_, _, _, _) => Task.FromResult<IEnumerable<string>>(new[] { "1.2.3.4" }),
                GeoLookupOverride = (_, _) => Task.FromResult<GeoLocationInfo?>(new GeoLocationInfo { Country = "US", Region = "Nope" })
            };
            var server = new PublicDnsEntry { IPAddress = IPAddress.Loopback, Country = CountryId.UnitedStates, Enabled = true };
            var results = await analysis.QueryAsync("example.com", DnsRecordType.A, new[] { server }, includeGeo: false);
            var result = Assert.Single(results);
            Assert.Null(result.Geo);
        }
    }
}
