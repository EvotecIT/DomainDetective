using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class PortScanRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[PortScanCodes.RdpOpen] = new RecommendationAdvice {
            Code = PortScanCodes.RdpOpen,
            Title = "RDP exposed on the internet",
            Why = "RDP services are frequent targets for brute-force and exploitation.",
            How = "Restrict RDP to VPN or private networks; require MFA; enable network-level authentication.",
            Links = new [] { "https://learn.microsoft.com/windows-server/remote/remote-desktop-services/rds-plan-security" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "rdp", "exposure" },
            Impact = "High risk of compromise via credential stuffing or RCE.",
            Effort = RecommendationEffort.Medium,
            Verify = "Block 3389/TCP from the internet and verify with a port scan."
        };

        map[PortScanCodes.VncOpen] = new RecommendationAdvice {
            Code = PortScanCodes.VncOpen,
            Title = "VNC exposed on the internet",
            Why = "VNC often lacks strong authentication and encryption.",
            How = "Disable or restrict VNC to VPN; enforce encryption and strong auth if required.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc6143" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "vnc", "exposure" },
            Impact = "High risk of unauthorized remote access.",
            Effort = RecommendationEffort.Medium,
            Verify = "Ensure 5900/TCP is not reachable from untrusted networks."
        };

        map[PortScanCodes.TelnetOpen] = new RecommendationAdvice {
            Code = PortScanCodes.TelnetOpen,
            Title = "Telnet exposed on the internet",
            Why = "Telnet transmits credentials in plaintext and is obsolete.",
            How = "Disable Telnet; use SSH with key-based auth.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc854" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "telnet", "plaintext" },
            Impact = "Credentials can be intercepted; remote command execution risk.",
            Effort = RecommendationEffort.Low,
            Verify = "Port 23/TCP must be closed externally."
        };

        map[PortScanCodes.SmbOpen] = new RecommendationAdvice {
            Code = PortScanCodes.SmbOpen,
            Title = "SMB exposed on the internet",
            Why = "SMB exposure enables lateral movement and worms (e.g., WannaCry).",
            How = "Block 445/TCP at perimeter; restrict SMB to internal networks only.",
            Links = new [] { "https://learn.microsoft.com/windows-server/storage/file-server/file-server-smb-security" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "smb", "wormable" },
            Impact = "Severe compromise risk and data exposure.",
            Effort = RecommendationEffort.Low,
            Verify = "Verify 445/TCP is unreachable from the internet."
        };

        map[PortScanCodes.RedisOpen] = new RecommendationAdvice {
            Code = PortScanCodes.RedisOpen,
            Title = "Redis exposed without network isolation",
            Why = "Redis is not designed for exposure and may lack auth/TLS by default.",
            How = "Bind to localhost/private IP; enable AUTH and TLS; restrict via firewall.",
            Links = new [] { "https://redis.io/docs/latest/operate/oss_and_stack/security/" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "redis", "datastore" },
            Impact = "Data theft or remote config execution.",
            Effort = RecommendationEffort.Medium,
            Verify = "Port 6379/TCP should not be reachable externally."
        };

        map[PortScanCodes.MongoOpen] = new RecommendationAdvice {
            Code = PortScanCodes.MongoOpen,
            Title = "MongoDB exposed without proper controls",
            Why = "Past incidents show unauthenticated MongoDB led to mass data exposure.",
            How = "Enable auth & TLS; bind to private interfaces; firewall external access.",
            Links = new [] { "https://www.mongodb.com/docs/manual/administration/security-checklist/" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "mongodb", "datastore" },
            Impact = "Database compromise and data loss.",
            Effort = RecommendationEffort.Medium,
            Verify = "Port 27017/TCP must be closed to the internet."
        };

        map[PortScanCodes.ElasticOpen] = new RecommendationAdvice {
            Code = PortScanCodes.ElasticOpen,
            Title = "Elasticsearch exposed without protections",
            Why = "Default clusters may allow indexing/search without auth; frequent breach vector.",
            How = "Enable security features; require TLS & auth; restrict via network policy.",
            Links = new [] { "https://www.elastic.co/guide/en/elasticsearch/reference/current/secure-cluster.html" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "elasticsearch", "datastore" },
            Impact = "Sensitive data disclosure at scale.",
            Effort = RecommendationEffort.Medium,
            Verify = "Port 9200/TCP should not be publicly reachable."
        };

        map[PortScanCodes.MemcachedOpen] = new RecommendationAdvice {
            Code = PortScanCodes.MemcachedOpen,
            Title = "Memcached exposed on the internet",
            Why = "Memcached is UDP/TCP accessible and abused for reflection attacks.",
            How = "Bind to localhost/private; restrict via firewall; disable UDP if not needed.",
            Links = new [] { "https://memcached.org/" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "memcached", "amplification" },
            Impact = "Service abuse and potential data exposure.",
            Effort = RecommendationEffort.Low,
            Verify = "Port 11211 must not be exposed."
        };

        map[PortScanCodes.BannerVersionLeaked] = new RecommendationAdvice {
            Code = PortScanCodes.BannerVersionLeaked,
            Title = "Service banner leaks software version",
            Why = "Revealing versions eases targeted exploitation using known CVEs.",
            How = "Suppress version in banners; configure generic greetings or obfuscate version tokens.",
            Links = new [] { "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/07-Fingerprint_Web_Server" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "banner", "information-disclosure" },
            Impact = "Increased likelihood of targeted attacks.",
            Effort = RecommendationEffort.Low,
            Verify = "Reconnect and confirm banners no longer expose versions."
        };

        map[PortScanCodes.ExpectedPortsOnly] = new RecommendationAdvice {
            Code = PortScanCodes.ExpectedPortsOnly,
            Title = "Only expected ports are open",
            Why = "Restricting services to necessary ports minimizes attack surface.",
            How = "Document required services (e.g., 80/443 for web) and close all other ports via firewall rules; monitor for unexpected openings.",
            Links = new [] { "https://nmap.org/book/man-port-scanning-basics.html" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "portscan", "hardening" },
            Impact = "Reduced exposure from extraneous services.",
            Effort = RecommendationEffort.Low,
            Verify = "Regularly scan to ensure only required ports remain open."
        };
    }
}

