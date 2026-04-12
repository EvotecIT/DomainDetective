using System.ComponentModel.DataAnnotations;

namespace DomainDetective.Providers.Dns;

/// <summary>Defines values for dns provider.</summary>
public enum DnsProvider
{
    /// <summary>Represents the unknown value.</summary>
    Unknown = 0,

    /// <summary>Represents the cloudflare value.</summary>
    [Display(Name = "Cloudflare")]
    Cloudflare = 1,

    /// <summary>Represents the amazon route53 value.</summary>
    [Display(Name = "Amazon Route 53")]
    AmazonRoute53 = 2,

    /// <summary>Represents the azure dns value.</summary>
    [Display(Name = "Azure DNS")]
    AzureDns = 3,

    /// <summary>Represents the google cloud dns value.</summary>
    [Display(Name = "Google Cloud DNS")]
    GoogleCloudDns = 4,

    /// <summary>Represents the go daddy value.</summary>
    [Display(Name = "GoDaddy")]
    GoDaddy = 5,

    /// <summary>Represents the namecheap value.</summary>
    [Display(Name = "Namecheap")]
    Namecheap = 6,

    /// <summary>Represents the digital ocean value.</summary>
    [Display(Name = "DigitalOcean")]
    DigitalOcean = 7
}

