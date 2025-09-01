namespace DomainDetective;

internal static class PortScanCodes {
    public const string RdpOpen = "PORTSCAN.RDP.Open";
    public const string VncOpen = "PORTSCAN.VNC.Open";
    public const string TelnetOpen = "PORTSCAN.Telnet.Open";
    public const string SmbOpen = "PORTSCAN.SMB.Open";
    public const string RedisOpen = "PORTSCAN.Redis.Open";
    public const string MongoOpen = "PORTSCAN.MongoDB.Open";
    public const string ElasticOpen = "PORTSCAN.Elasticsearch.Open";
    public const string MemcachedOpen = "PORTSCAN.Memcached.Open";

    public const string BannerVersionLeaked = "PORTSCAN.Banner.VersionLeaked";
}

