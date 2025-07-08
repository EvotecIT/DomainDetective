using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Xunit;
using Xunit.Sdk;
using DomainDetective.Network;

namespace DomainDetective.Tests {
    public class TestPingTraceroute {
        [SkippableFact]
        public async Task PingLocalhost() {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows) &&
                !RuntimeInformation.IsOSPlatform(OSPlatform.Linux) &&
                !RuntimeInformation.IsOSPlatform(OSPlatform.OSX)) {
                throw Xunit.Sdk.SkipException.ForSkip("ICMP not supported on this platform");
            }

            var reply = await PingTraceroute.PingAsync("127.0.0.1");
            Assert.Equal(IPStatus.Success, reply.Status);
        }

        [SkippableFact]
        public async Task TracerouteLocalhost() {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows) &&
                !RuntimeInformation.IsOSPlatform(OSPlatform.Linux) &&
                !RuntimeInformation.IsOSPlatform(OSPlatform.OSX)) {
                throw Xunit.Sdk.SkipException.ForSkip("ICMP not supported on this platform");
            }

            var hops = await PingTraceroute.TracerouteAsync("127.0.0.1", maxHops: 3);
            Assert.NotEmpty(hops);
            Assert.Equal(IPStatus.Success, hops[hops.Count - 1].Status);
        }
    }
}
