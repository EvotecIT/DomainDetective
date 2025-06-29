using System;
using System.Collections.Generic;
using System.Net.NetworkInformation;
using System.Threading.Tasks;

namespace DomainDetective.Network;

/// <summary>
/// Provides ICMP ping and traceroute capabilities.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public static class PingTraceroute
{
    /// <summary>Represents a single traceroute hop.</summary>
    public class TracerouteHop
    {
        /// <summary>Gets or sets the hop number.</summary>
        public int Hop { get; set; }
        /// <summary>Gets or sets the responding address.</summary>
        public string? Address { get; set; }
        /// <summary>Gets or sets the ICMP status of this hop.</summary>
        public IPStatus Status { get; set; }
        /// <summary>Gets or sets the roundtrip time in milliseconds.</summary>
        public long RoundtripTime { get; set; }
    }

    /// <summary>Sends a single ICMP echo request.</summary>
    /// <param name="host">Target host name or address.</param>
    /// <param name="timeout">Timeout in milliseconds.</param>
    /// <param name="logger">Optional diagnostic logger.</param>
    /// <returns>The <see cref="PingReply"/> from the operation.</returns>
    public static async Task<PingReply> PingAsync(string host, int timeout = 4000, InternalLogger? logger = null)
    {
        using var ping = new Ping();
        logger?.WriteVerbose("Pinging {0}", host);
        var reply = await ping.SendPingAsync(host, timeout);
        logger?.WriteVerbose("Ping status for {0}: {1}", host, reply.Status);
        return reply;
    }

    /// <summary>Runs a traceroute to the specified host.</summary>
    /// <param name="host">Target host name or address.</param>
    /// <param name="maxHops">Maximum number of hops.</param>
    /// <param name="timeout">Timeout per hop in milliseconds.</param>
    /// <param name="logger">Optional diagnostic logger.</param>
    /// <returns>Collection of traceroute hops.</returns>
    public static async Task<IReadOnlyList<TracerouteHop>> TracerouteAsync(string host, int maxHops = 30, int timeout = 4000, InternalLogger? logger = null)
    {
        using var ping = new Ping();
        var buffer = Array.Empty<byte>();
        var hops = new List<TracerouteHop>(maxHops);

        for (var ttl = 1; ttl <= maxHops; ttl++)
        {
            var options = new PingOptions(ttl, true);
            var reply = await ping.SendPingAsync(host, timeout, buffer, options);
            hops.Add(new TracerouteHop
            {
                Hop = ttl,
                Address = reply.Address?.ToString(),
                Status = reply.Status,
                RoundtripTime = reply.RoundtripTime
            });
            logger?.WriteVerbose("Hop {0} -> {1} {2}", ttl, reply.Address, reply.Status);
            if (reply.Status == IPStatus.Success)
            {
                break;
            }
        }

        return hops;
    }
}

