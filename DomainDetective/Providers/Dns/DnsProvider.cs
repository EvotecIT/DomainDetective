using System.ComponentModel.DataAnnotations;

namespace DomainDetective.Providers.Dns;

public enum DnsProvider
{
    Unknown = 0,

    [Display(Name = "Cloudflare")]
    Cloudflare = 1,

    [Display(Name = "Amazon Route 53")]
    AmazonRoute53 = 2,

    [Display(Name = "Azure DNS")]
    AzureDns = 3,

    [Display(Name = "Google Cloud DNS")]
    GoogleCloudDns = 4,

    [Display(Name = "GoDaddy")]
    GoDaddy = 5,

    [Display(Name = "Namecheap")]
    Namecheap = 6,

    [Display(Name = "DigitalOcean")]
    DigitalOcean = 7
}

