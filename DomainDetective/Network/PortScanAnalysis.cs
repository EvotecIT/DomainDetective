using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;

namespace DomainDetective;

/// <summary>
/// Scans TCP and UDP ports on a host.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class PortScanAnalysis
{
    /// <summary>Result of a single port scan.</summary>
    public class ScanResult
    {
        /// <summary>Indicates whether the TCP port is open.</summary>
        public bool TcpOpen { get; init; }
        /// <summary>Indicates whether the UDP port is open.</summary>
        public bool UdpOpen { get; init; }
        /// <summary>Latency of the TCP connection attempt.</summary>
        public TimeSpan TcpLatency { get; init; }
    }

    /// <summary>Scan results keyed by port number.</summary>
    public Dictionary<int, ScanResult> Results { get; } = new();

    /// <summary>Maximum wait time per connection.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(1);

    /// <summary>Controls the number of concurrent connection attempts.</summary>
    public int MaxConcurrency { get; set; } = 100;

    private const string PortsCsv = "80,631,161,137,123,445,138,1434,135,53,139,67,23,443,21,22,500,1900,68,520,25,514,4500,111,49152,162,69,5353,49154,3389,110,1701,999,998,996,997,49153,3283,1025,5060,1812,32768,136,143,2049,2222,3306,1433,8080,3456,1026,1723,995,7,993,1027,20031,5900,593,427,1645,1646,518,2048,2000,626,587,199,88,9,10000,1719,177,497,19,1029,515,4444,1023,1028,8888,6001,65024,49193,113,5000,49,465,1720,17185,548,81,1718,49156,49186,3703,31337,17,8000,49201,49192,179,2223,1030,49181,1813,158,120,990,5001,49200,8443,32771,37,32815,1022,389,6000,1031,2967,13,554,32769,2001,1032,33281,4000,4045,623,26,513,5632,32770,49191,30718,49194,49182,9200,49155,8008,49211,49190,1041,49188,49185,79,5355,49158,1110,37444,34861,34555,1024,3659,3130,5666,49196,646,2121,106,407,1039,1038,989,5800,5631,32772,4672,1034,34862,49195,8081,5357,49189,42,49187,49162,2148,33354,543,544,1068,41524,1049,10080,49157,6004,1036,1044,464,2002,444,1056,144,1001,1033,1000,5050,5101,6346,9876,49199,49180,1045,1054,1782,5190,19283,517,9999,800,49171,1065,1048,8009,49202,49179,1066,7938,3986,49210,49209,49208,49205,49184,3128,39213,5009,49159,1064,7000,1043,7070,1419,3052,1080,192,1008,44968,3001,3000,5003,49166,5432,1761,873,1755,1053,5500,5051,1021,22986,19682,1069,32773,49165,49163,9000,8010,8193,1047,664,119,58002,49168,6646,11487,49172,82,1037,683,902,32774,2103,49160,1019,2717,4899,1040,1050,5351,5093,1885,9100,5002,27892,16680,1,1035,6002,41058,35777,32775,52225,49169,782,49174,685,786,686,1059,512,1886,38293,1042,38037,20,5555,10010,32779,780,1234,9001,1058,2161,49175,3,9090,636,1014,49167,2107,9950,983,682,2105,781,6971,6970,2051,808,31891,31681,31073,30365,30303,29823,28547,27195,25375,22996,22846,21383,20389,20126,20019,19616,19503,19120,18449,16947,16832,3689,42172,33355,49213,49204,1801,32777,1090,1071,8001,53571,52503,49215,49212,49198,8031,27015,9103,5120,2869,1521,684,1060,1055,255,32776,8181,2160,311,1998,1485,54321,539,767,434,112,1067,3401,49176,49161,2005,280,6347,687,47624,40732,5901,9102,100,4001,363,30704,829,7100,1012,49197,49173,49170,1051,32780,45441,42508,41370,41081,40915,40708,40441,40116,39888,36206,35438,34892,34125,33744,32931,32818,776,38,9020,1901,29810,29243,23040,22341,19130,2601,1100,1081,1057,1046,2401,959,64513,63555,62287,61370,58640,58631,56141,54281,51717,50612,49503,49207,688,775,217,2004,643,9199,3702,1346,32528,32385,32345,31731,31625,31365,31195,31189,31109,31059,30975,30697,30656,30544,30263,29977,29256,29078,28973,28840,28641,28543,28493,28465,28369,28122,27899,27707,27482,27473,26966,26872,26720,26415,26407,25931,25709,25546,25541,25462,25337,25280,25240,25157,25003,24910,24854,24644,24606,24594,24511,24279,24007,23980,23965,23781,23679,23608,23557,23531,23354,23176,22914,22799,22739,22695,22692,22055,21902,21803,21621,21354,21298,21261,21212,21131,20359,20004,19933,19687,19600,19489,19332,19322,19294,19197,19165,19039,19017,18980,18835,18582,18360,18331,18234,18004,17989,17939,17888,17616,17615,17573,17459,17455,17091,16918,16430,16402,9877,1124,1524,7001,1074,625,32778,2,1007,888,1214,254,903,1105,772,1993,787,1088,402,1352,1666,6050,9595,1062,1052,1494,83,2006,965,773,5010,814,222,31335,1072,1070,774,24800,3333,838,1083,6112,3664,2343,1804,44334,44101,37393,32798,1087,24444,19315,1484,3690,1455,563,64727,64080,49216,33,2301,48761,48489,48455,48255,48189,48078,47981,47915,47808,47772,47765,46836,46532,46093,45928,45818,45722,45685,45380,45247,44946,44923,44508,44253,44190,44185,44179,44160,43967,43824,43686,43514,43370,43195,43094,42639,42627,42577,42557,42434,42431,42313,42056,41971,41967,41896,41774,41702,41638,41446,41308,40866,40847,40805,40724,40711,40622,40539,40019,39723,39714,39683,39632,39217,38615,38498,38412,38063,37843,37813,37783,37761,37602,37212,37144,36945,36893,36778,36669,36489,36458,36384,36108,35794,35702,34855,34796,34758,34580,34579,34578,34577,34570,34433,34422,34358,34079,34038,33872,33866,33717,33459,33249,33030,27444,617,6666,64590,64481,63420,62958,62699,62677,62575,62154,61961,61685,61550,61481,61412,61322,61319,61142,61024,60423,60381,60172,59846,59765,59207,59193,58797,58419,58178,58075,57977,57958,57843,57813,57410,57409,57172,55587,55544,55043,54925,54807,54711,54114,54094,53838,53589,53037,53006,52144,51972,51905,51690,51586,51554,51456,51255,50919,50708,50497,50164,50099,49968,49640,49396,49393,49360,49350,49306,49262,49259,49226,49222,49220,49214,49178,49177,2008,6969,264,24,639,2007,502,146,28211,3457,7937,4666,1013,4008,657,1020,559,163,8900,1200,1101,789,63331,32219,30299,27017,26340,23430,19995,18669,764,826,3301,1098,1061,27010,2383,2010,944,689,2009,207,9535,1457,750,898,769,1501,2065,9370,3343,3296,2362,2345,16086,27007,27002,50000,1503,61532,770,32760,32750,32727,32611,32607,32546,32506,32499,32495,32479,32469,32446,32430,32425,32422,32415,32404,32382,32368,32359,32352,32326,32273,32262,32216,32185,32132,32129,32124,32066,32053,32044,31999,31963,31918,31887,31882,31852,31803,31794,31792,31783,31750,31743,31735,31732,31720,31692,31673,31609,31602,31599,31584,31569,31560,31521,31520,31481,31428,31412,31404,31361,31352,31350,31343,31334,31284,31267,31266,31261,31202,31199,31180,31162,31155,31137,31134,31133,31115,31112,31084,31082,31051,31049,31036,31034,30996,30943,30932,30930,30909,30880,30875,30869,30856,30824,30803,30789,30785,30757,30698,30669,30661,30622,30612,30583,30578,30533,30526,30512,30477,30474,30473,30465,30461,30348,30260,30256,30214,30209,30154,30134,30093,30085";
    private static readonly int[] _topPorts = Array.ConvertAll(PortsCsv.Split(','), int.Parse);

    /// <summary>List of default ports to scan.</summary>
    public static IReadOnlyList<int> DefaultPorts => _topPorts;

    /// <summary>Performs a scan against the host.</summary>
    public async Task Scan(string host, IEnumerable<int>? ports, InternalLogger? logger = null, CancellationToken cancellationToken = default)
    {
        Results.Clear();
        var list = ports ?? _topPorts;
        using var semaphore = new SemaphoreSlim(MaxConcurrency);
        var tasks = list.Select(async port =>
        {
            await semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                var result = await ScanPort(host, port, logger, cancellationToken).ConfigureAwait(false);
                lock (Results)
                {
                    Results[port] = result;
                }
            }
            finally
            {
                semaphore.Release();
            }
        });
        await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    private async Task<ScanResult> ScanPort(string host, int port, InternalLogger? logger, CancellationToken token)
    {
        bool tcpOpen = false;
        bool udpOpen = false;
        var sw = Stopwatch.StartNew();

        IPAddress address;
        if (!IPAddress.TryParse(host, out address))
        {
            try
            {
                address = (await Dns.GetHostAddressesAsync(host).ConfigureAwait(false)).First();
            }
            catch
            {
                return new ScanResult { TcpOpen = false, UdpOpen = false, TcpLatency = sw.Elapsed };
            }
        }

        using (var client = new TcpClient(address.AddressFamily))
        using (var cts = CancellationTokenSource.CreateLinkedTokenSource(token))
        {
            cts.CancelAfter(Timeout);
            try
            {
#if NET6_0_OR_GREATER
                await client.ConnectAsync(address, port, cts.Token).ConfigureAwait(false);
#else
                await client.ConnectAsync(address, port).WaitWithCancellation(cts.Token).ConfigureAwait(false);
#endif
                tcpOpen = true;
            }
            catch (Exception ex) when (ex is SocketException || ex is OperationCanceledException)
            {
                logger?.WriteVerbose("TCP {0}:{1} closed - {2}", address, port, ex.Message);
            }
        }
        sw.Stop();

        using (var udp = new UdpClient(address.AddressFamily))
        {
            try
            {
                udp.Client.SendTimeout = (int)Timeout.TotalMilliseconds;
                udp.Client.ReceiveTimeout = (int)Timeout.TotalMilliseconds;
                await udp.SendAsync(Array.Empty<byte>(), 0, new IPEndPoint(address, port)).ConfigureAwait(false);
#if NET8_0_OR_GREATER
                using (var cts = CancellationTokenSource.CreateLinkedTokenSource(token))
                {
                    cts.CancelAfter(Timeout);
                    var result = await udp.ReceiveAsync(cts.Token).ConfigureAwait(false);
                    udpOpen = result.Buffer.Length >= 0;
                }
#else
                using (var cts = CancellationTokenSource.CreateLinkedTokenSource(token))
                {
                    cts.CancelAfter(Timeout);
                    var receiveTask = udp.ReceiveAsync();
                    await receiveTask.WaitWithCancellation(cts.Token).ConfigureAwait(false);
                    udpOpen = true;
                }
#endif
            }
            catch (Exception ex) when (ex is SocketException || ex is OperationCanceledException)
            {
                logger?.WriteVerbose("UDP {0}:{1} closed - {2}", address, port, ex.Message);
            }
        }

        return new ScanResult { TcpOpen = tcpOpen, UdpOpen = udpOpen, TcpLatency = sw.Elapsed };
    }

    /// <summary>Determines whether the host has a reachable IPv6 address.</summary>
    public static async Task<bool> IsIPv6Reachable(string host, int port = 80, CancellationToken cancellationToken = default)
    {
        IPAddress[] addresses;
        try
        {
            addresses = await Dns.GetHostAddressesAsync(host).ConfigureAwait(false);
        }
        catch
        {
            return false;
        }

        foreach (var addr in addresses)
        {
            if (addr.AddressFamily != AddressFamily.InterNetworkV6)
            {
                continue;
            }

            using var socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(1));
            try
            {
#if NET6_0_OR_GREATER
                await socket.ConnectAsync(addr, port, cts.Token).ConfigureAwait(false);
#else
                await socket.ConnectAsync(addr, port).WaitWithCancellation(cts.Token).ConfigureAwait(false);
#endif
                return true;
            }
            catch
            {
            }
        }

        return false;
    }
}

