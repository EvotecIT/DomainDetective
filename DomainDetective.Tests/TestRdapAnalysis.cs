using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestRdapAnalysis {
        [Fact]
        public async Task ParsesRdapResponse() {
            RdapAnalysis.ClearCache();
            const string json = "{\"ldhName\":\"example.com\",\"status\":[\"active\"],\"nameservers\":[{\"ldhName\":\"ns1.example.net\"},{\"ldhName\":\"ns2.example.net\"}],\"events\":[{\"eventAction\":\"registration\",\"eventDate\":\"2000-01-01T00:00:00Z\"},{\"eventAction\":\"expiration\",\"eventDate\":\"2030-01-01T00:00:00Z\"}],\"entities\":[{\"handle\":\"123\",\"roles\":[\"registrar\"],\"vcardArray\":[\"vcard\",[[\"fn\",{},\"text\",\"Registrar Inc\"]]]}]}";
            var analysis = new RdapAnalysis { QueryOverride = _ => Task.FromResult(json) };
            await analysis.Analyze("example.com", new InternalLogger());
            Assert.Equal("example.com", analysis.DomainName.ToLowerInvariant());
            Assert.Equal("Registrar Inc", analysis.Registrar);
            Assert.Equal("123", analysis.RegistrarId);
            Assert.Equal("2000-01-01T00:00:00Z", analysis.CreationDate);
            Assert.Equal("2030-01-01T00:00:00Z", analysis.ExpiryDate);
            Assert.Contains("ns1.example.net", analysis.NameServers);
            Assert.Contains("ns2.example.net", analysis.NameServers);
            Assert.Contains(RdapDomainStatus.Active, analysis.Status);
        }

        [Fact]
        public async Task IntegratesWithHealthCheck() {
            const string json = "{\"ldhName\":\"example.org\"}";
            var health = new DomainHealthCheck();
            health.RdapAnalysis.QueryOverride = _ => Task.FromResult(json);
            await health.QueryRDAP("example.org");
            Assert.Equal("example.org", health.RdapAnalysis.DomainName.ToLowerInvariant());
        }

        [Fact]
        public async Task CachedResultReusedUntilExpiration() {
            RdapAnalysis.ClearCache();
            int hitCount = 0;
            string json = "{\"ldhName\":\"example.net\"}";
            var analysis = new RdapAnalysis {
                CacheDuration = TimeSpan.FromMilliseconds(500),
                QueryOverride = _ => { hitCount++; return Task.FromResult(json); }
            };

            await analysis.Analyze("example.net", new InternalLogger());
            await analysis.Analyze("example.net", new InternalLogger());

            Assert.Equal(1, hitCount);

            await Task.Delay(600);
            var analysis2 = new RdapAnalysis {
                CacheDuration = TimeSpan.FromMilliseconds(500),
                QueryOverride = _ => { hitCount++; return Task.FromResult(json); }
            };
            await analysis2.Analyze("example.net", new InternalLogger());

            Assert.Equal(2, hitCount);
        }

        [Fact]
        public async Task NotFoundResponseLogged() {
            RdapAnalysis.ClearCache();
            var logger = new InternalLogger();
            LogEventArgs? error = null;
            logger.OnErrorMessage += (_, e) => error = e;

            var analysis = new RdapAnalysis {
#if NET8_0_OR_GREATER
                QueryOverride = _ => throw new HttpRequestException(
                    "NotFound",
                    null,
                    HttpStatusCode.NotFound),
#else
                QueryOverride = _ => throw new HttpRequestException("404"),
#endif
                RdapClient = new RdapClient("http://localhost")
            };

            await analysis.Analyze("example.com", logger);

            Assert.Null(analysis.DomainData);
            Assert.NotNull(error);
            Assert.Contains("404", error!.FullMessage);
            Assert.Contains("http://localhost/domain/example.com", error.FullMessage);
        }

        [Fact]
        public async Task ServerErrorThrowsAndLogs() {
            RdapAnalysis.ClearCache();
            var logger = new InternalLogger();
            LogEventArgs? error = null;
            logger.OnErrorMessage += (_, e) => error = e;

            var analysis = new RdapAnalysis {
#if NET8_0_OR_GREATER
                QueryOverride = _ => throw new HttpRequestException(
                    "ServerError",
                    null,
                    HttpStatusCode.InternalServerError),
#else
                QueryOverride = _ => throw new HttpRequestException("500"),
#endif
                RdapClient = new RdapClient("http://localhost")
            };

            await Assert.ThrowsAsync<HttpRequestException>(
                () => analysis.Analyze("example.com", logger));

            Assert.NotNull(error);
            Assert.Contains("500", error!.FullMessage);
            Assert.Contains("http://localhost/domain/example.com", error.FullMessage);
        }
    }
}
