namespace DomainDetective.Tests;

using System.Collections.Generic;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;

public class TestWhoisDynamicLookup {
    [Fact]
    public async Task UnmappedTldFallsBackToIanaLookup() {
        var whois = new WhoisAnalysis {
            IanaQueryOverride = _ => Task.FromResult("% IANA WHOIS server\r\nwhois: whois.test.net\r\n")
        };
        var method = typeof(WhoisAnalysis).GetMethod("GetWhoisServer", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);
        var task = (Task<string?>)method!.Invoke(whois, new object[] { "example.unknownxtld", CancellationToken.None })!;
        var server = await task;
        Assert.Equal("whois.test.net", server);

        var dictField = typeof(WhoisAnalysis).GetField("WhoisServers", BindingFlags.NonPublic | BindingFlags.Instance);
        var lockField = typeof(WhoisAnalysis).GetField("_whoisServersLock", BindingFlags.NonPublic | BindingFlags.Instance);
        var dict = (Dictionary<string, string>)dictField!.GetValue(whois)!;
        var lockObj = lockField!.GetValue(whois)!;
        lock (lockObj) {
            Assert.Equal("whois.test.net", dict["unknownxtld"]);

    [Fact]
    public async Task SingleTldFallbackUpdatesTld() {
        var whois = new WhoisAnalysis();
        var method = typeof(WhoisAnalysis).GetMethod("GetWhoisServer", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);
        var task = (Task<string?>)method!.Invoke(whois, new object[] { "example.co.uk", CancellationToken.None })!;
        var server = await task;
        Assert.Equal("whois.nic.uk", server);
        Assert.Equal("uk", whois.Tld);
    }

            var method = typeof(WhoisAnalysis).GetMethod("GetWhoisServer", BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(method);
            var task = (Task<string?>)method!.Invoke(whois, new object[] { "example.unknownxtld", CancellationToken.None })!;
            var server = await task;
            Assert.Equal("whois.test.net", server);

            var dictField = typeof(WhoisAnalysis).GetField("WhoisServers", BindingFlags.NonPublic | BindingFlags.Instance);
            var lockField = typeof(WhoisAnalysis).GetField("_whoisServersLock", BindingFlags.NonPublic | BindingFlags.Instance);
            var dict = (Dictionary<string, string>)dictField!.GetValue(whois)!;
            var lockObj = lockField!.GetValue(whois)!;
            lock (lockObj) {
                Assert.Equal("whois.test.net", dict["unknownxtld"]);
            }
        }
    }
}
