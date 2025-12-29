using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;
using System.Text.RegularExpressions;
using PortScanProfile = DomainDetective.PortScanProfileDefinition.PortScanProfile;

namespace DomainDetective;

/// <summary>
/// Scans TCP and UDP ports on a host.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
/// <remarks>
/// This analysis attempts connections in parallel and records latency or
/// failure reasons for each tested port.
/// </remarks>
public class PortScanAnalysis : IHasAssessments
{
    /// <summary>Subject for this analysis (usually the host name).</summary>
    public string? Subject { get; set; }
    /// <summary>Result of a single port scan.</summary>
    public class ScanResult
    {
        /// <summary>Indicates whether the TCP port is open.</summary>
        public bool TcpOpen { get; init; }
        /// <summary>Indicates whether the UDP port is open.</summary>
        public bool UdpOpen { get; init; }
        /// <summary>Latency of the TCP connection attempt.</summary>
        public TimeSpan TcpLatency { get; init; }
        /// <summary>Socket exception message, if the scan failed.</summary>
        public string? Error { get; init; }
        /// <summary>Optional service banner or detected protocol.</summary>
        public string? Banner { get; init; }
    }

    /// <summary>Scan results keyed by port number.</summary>
    public Dictionary<int, ScanResult> Results { get; } = new();

    /// <summary>Maximum wait time per connection.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(1);

    /// <summary>Controls the number of concurrent connection attempts.</summary>
    public int MaxConcurrency { get; set; } = 100;

    /// <summary>Factory used to create <see cref="UdpClient"/> instances.</summary>
    internal Func<AddressFamily, UdpClient> UdpClientFactory { get; set; } = af => new UdpClient(af);
    internal Func<AddressFamily, TcpClient> TcpClientFactory { get; set; } = af => new TcpClient(af);

    /// <summary>Structured assessments captured during port scans.</summary>
    public List<Assessment> Assessments { get; } = new();

    private static readonly Dictionary<int, (string Code, string Name)> SensitiveTcpServices = new()
    {
        [3389] = (PortScanCodes.RdpOpen, "RDP"),
        [5900] = (PortScanCodes.VncOpen, "VNC"),
        [23]   = (PortScanCodes.TelnetOpen, "Telnet"),
        [445]  = (PortScanCodes.SmbOpen, "SMB"),
        [6379] = (PortScanCodes.RedisOpen, "Redis"),
        [27017]= (PortScanCodes.MongoOpen, "MongoDB"),
        [9200] = (PortScanCodes.ElasticOpen, "Elasticsearch"),
        [11211]= (PortScanCodes.MemcachedOpen, "Memcached"),
    };

    private static readonly Regex VersionLeakRegex = new(
        @"(?:(?:OpenSSH_|nginx/|Apache/|Microsoft-IIS/|Exim\s+\d|Redis\s+\d|MongoDB\s+\d|Elasticsearch\s+\d|memcached\s+\d))",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);


    private static readonly Func<NetworkStream, CancellationToken, Task<string?>>[] DefaultDetectors =
    {
        DetectBannerAsync,
        DetectSshAsync,
        DetectHttpAsync,
        DetectRdpAsync
    };

    private static readonly Dictionary<int, Func<NetworkStream, CancellationToken, Task<string?>>[]> DetectionStrategies = new()
    {
        [21] = new[] { DetectBannerAsync },
        [22] = new[] { DetectSshAsync },
        [25] = new[] { DetectBannerAsync },
        [80] = new[] { DetectHttpAsync },
        [110] = new[] { DetectBannerAsync },
        [143] = new[] { DetectBannerAsync },
        [443] = new[] { DetectHttpAsync },
        [3389] = new[] { DetectRdpAsync },
        [8080] = new[] { DetectHttpAsync }
    };


    /// <summary>List of default ports to scan.</summary>
    public static IReadOnlyList<int> DefaultPorts => PortScanProfileDefinition.DefaultPorts;

    /// <summary>Performs a scan against the host.</summary>
    public async Task Scan(string host, IEnumerable<int>? ports, InternalLogger? logger = null, CancellationToken cancellationToken = default, bool showProgress = true)
    {
        Subject = host;
        Results.Clear();
        var list = ports ?? PortScanProfileDefinition.DefaultPorts;
        using var _collector = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "PORTSCAN", target: host) : null;
        using var semaphore = new SemaphoreSlim(MaxConcurrency);
        var total = list.Count();
        var processed = 0;
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
                var done = Interlocked.Increment(ref processed);
                if (showProgress) {
                    logger?.WriteProgress("PortScan", port.ToString(), done * 100d / total, done, total);
                }
            }
        });
        await Task.WhenAll(tasks).ConfigureAwait(false);

        if (!Results.Any(kv => kv.Value.TcpOpen && SensitiveTcpServices.ContainsKey(kv.Key)))
        {
            logger?.WriteInformationCode(PortScanCodes.ExpectedPortsOnly, "Only expected ports open on {0}", host);
        }
    }

    /// <summary>Performs a scan using a predefined profile.</summary>
    public Task Scan(string host, PortScanProfile profile, InternalLogger? logger = null, CancellationToken cancellationToken = default, bool showProgress = true)
    {
        return Scan(host, PortScanProfileDefinition.GetPorts(profile), logger, cancellationToken, showProgress);
    }

    private async Task<ScanResult> ScanPort(string host, int port, InternalLogger? logger, CancellationToken token)
    {
        using var _collector = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "PORTSCAN", target: $"{host}:{port}") : null;
        bool tcpOpen = false;
        bool udpOpen = false;
        string? banner = null;
        var sw = Stopwatch.StartNew();
        string? error = null;

        IPAddress address;
        if (IPAddress.TryParse(host, out var parsedAddress) && parsedAddress != null) {
            address = parsedAddress;
        } else {
            try {
                address = (await Dns.GetHostAddressesAsync(host).ConfigureAwait(false)).First();
            } catch (Exception ex) {
                error = ex.Message;
                return new ScanResult { TcpOpen = false, UdpOpen = false, TcpLatency = sw.Elapsed, Error = error };
            }
        }

        using (var client = TcpClientFactory(address.AddressFamily))
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
            cts.CancelAfter(Timeout);
            try
            {
#if NET6_0_OR_GREATER
                await client.ConnectAsync(address, port, cts.Token).ConfigureAwait(false);
#else
                await client.ConnectAsync(address, port).WaitWithCancellation(cts.Token).ConfigureAwait(false);
#endif
                tcpOpen = true;
                banner = await DetectServiceAsync(client, port, cts.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is SocketException || ex is OperationCanceledException)
            {
                logger?.WriteVerbose("TCP {0}:{1} closed - {2}", address, port, ex.Message);
                error = ex.Message;
            }
        }
        sw.Stop();

        if (await SnmpAnalysis.ProbeAsync(address.ToString(), port, Timeout, logger, token).ConfigureAwait(false))
        {
            udpOpen = true;
            banner = "SNMP";
        }
        else
        {
            using (var udp = new UdpClient(address.AddressFamily))
            {
                try
                {
                    udp.Client.SendTimeout = (int)Timeout.TotalMilliseconds;
                    udp.Client.ReceiveTimeout = (int)Timeout.TotalMilliseconds;
                    udp.Connect(address, port);
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
                    cts.CancelAfter(Timeout);
                    await udp.SendAsync(Array.Empty<byte>(), 0).ConfigureAwait(false);
#if NET8_0_OR_GREATER
                    try
                    {
                        var result = await udp.ReceiveAsync(cts.Token).ConfigureAwait(false);
                        udpOpen = result.Buffer.Length > 0;
                    }
                    catch
                    {
                        // ignore UDP receive failures
                    }
#else
                    var receiveTask = udp.ReceiveAsync();
                    try
                    {
                        var result = await receiveTask.WaitWithCancellation(cts.Token).ConfigureAwait(false);
                        udpOpen = result.Buffer.Length > 0;
                    }
                    catch
                    {
                        // ignore UDP receive failures
                    }
#endif
                }
                catch (Exception ex) when (ex is SocketException || ex is OperationCanceledException)
                {
                    logger?.WriteVerbose("UDP {0}:{1} closed - {2}", address, port, ex.Message);
                    error = ex.Message;
                }
            }
        }

        // Assess sensitive TCP services exposed
        if (tcpOpen && SensitiveTcpServices.TryGetValue(port, out var svc))
        {
            logger?.WriteWarningCode(svc.Code, "{0} service open on {1}:{2}", svc.Name, host, port);
        }

        // Assess banner version leakage for known families
        if (tcpOpen && !string.IsNullOrWhiteSpace(banner) && VersionLeakRegex.IsMatch(banner!))
        {
            logger?.WriteWarningCode(PortScanCodes.BannerVersionLeaked, "Service banner discloses version on {0}:{1}: {2}", host, port, banner!.Trim());
        }

        return new ScanResult { TcpOpen = tcpOpen, UdpOpen = udpOpen, TcpLatency = sw.Elapsed, Error = error, Banner = banner };
    }

    private static IEnumerable<Func<NetworkStream, CancellationToken, Task<string?>>> GetStrategies(int port)
    {
        if (DetectionStrategies.TryGetValue(port, out var specific))
        {
            foreach (var s in specific)
            {
                yield return s;
            }

            foreach (var d in DefaultDetectors)
            {
                if (Array.IndexOf(specific, d) == -1)
                {
                    yield return d;
                }
            }
        }
        else
        {
            foreach (var d in DefaultDetectors)
            {
                yield return d;
            }
        }
    }

    private async Task<string?> DetectServiceAsync(TcpClient client, int port, CancellationToken token)
    {
        var stream = client.GetStream();
        foreach (var strategy in GetStrategies(port))
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
                // Allow banner/protocol detection to run up to the caller's Timeout budget
                // to reduce flakiness on slower CI environments.
                cts.CancelAfter(Timeout);
                var result = await strategy(stream, cts.Token)
                    .WaitWithCancellation(cts.Token)
                    .ConfigureAwait(false);
                if (!string.IsNullOrEmpty(result))
                {
                    return result;
                }
            }
            catch (OperationCanceledException)
            {
                if (token.IsCancellationRequested)
                {
                    throw;
                }

                // Timeout: stop further detection to avoid overlapping reads on NET472.
                break;
            }
            catch
            {
                // ignore and try next strategy
            }

            if (!client.Connected)
            {
                break;
            }
        }

        return null;
    }

    private static async Task<string?> DetectBannerAsync(NetworkStream stream, CancellationToken token)
    {
        var buffer = new byte[256];
        var bytes = await stream.ReadAsync(buffer, 0, buffer.Length, token).ConfigureAwait(false);
        return bytes > 0 ? System.Text.Encoding.ASCII.GetString(buffer, 0, bytes).Trim() : null;
    }

    private static async Task<string?> DetectSshAsync(NetworkStream stream, CancellationToken token)
    {
        var banner = await DetectBannerAsync(stream, token).ConfigureAwait(false);
        return banner is not null && banner.StartsWith("SSH-", StringComparison.OrdinalIgnoreCase) ? banner : null;
    }

    private static async Task<string?> DetectHttpAsync(NetworkStream stream, CancellationToken token)
    {
        var request = System.Text.Encoding.ASCII.GetBytes("HEAD / HTTP/1.0\r\n\r\n");
        await stream.WriteAsync(request, 0, request.Length, token).ConfigureAwait(false);
        var buffer = new byte[256];
        var bytes = await stream.ReadAsync(buffer, 0, buffer.Length, token).ConfigureAwait(false);
        var text = System.Text.Encoding.ASCII.GetString(buffer, 0, bytes);
        return text.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase) ? "HTTP" : null;
    }

    private static async Task<string?> DetectRdpAsync(NetworkStream stream, CancellationToken token)
    {
        var request = new byte[] { 0x03, 0x00, 0x00, 0x0b, 0x06, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00 };
        await stream.WriteAsync(request, 0, request.Length, token).ConfigureAwait(false);
        var buffer = new byte[4];
        var bytes = await stream.ReadAsync(buffer, 0, buffer.Length, token).ConfigureAwait(false);
        return bytes >= 2 && buffer[0] == 0x03 && buffer[1] == 0x00 ? "RDP" : null;
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

