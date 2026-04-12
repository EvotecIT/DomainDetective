using System.ComponentModel.DataAnnotations;

namespace DomainDetective.Providers.Email;

/// <summary>Defines values for mail provider kind.</summary>
public enum MailProviderKind
{
    /// <summary>Represents the unknown value.</summary>
    Unknown = 0,

    /// <summary>Represents the microsoft365 value.</summary>
    [Display(Name = "Microsoft 365")]
    Microsoft365 = 1,

    /// <summary>Represents the google workspace value.</summary>
    [Display(Name = "Google Workspace")]
    GoogleWorkspace = 2,

    /// <summary>Represents the mimecast value.</summary>
    [Display(Name = "Mimecast")]
    Mimecast = 3,

    /// <summary>Represents the barracuda email gateway defense value.</summary>
    [Display(Name = "Barracuda Email Gateway Defense")]
    BarracudaEmailGatewayDefense = 4,

    /// <summary>Represents the proofpoint essentials value.</summary>
    [Display(Name = "Proofpoint Essentials")]
    ProofpointEssentials = 5,

    /// <summary>Represents the zoho mail value.</summary>
    [Display(Name = "Zoho Mail")]
    ZohoMail = 6,

    /// <summary>Represents the send grid value.</summary>
    [Display(Name = "SendGrid")]
    SendGrid = 7,

    /// <summary>Represents the amazon ses value.</summary>
    [Display(Name = "Amazon SES")]
    AmazonSes = 8,

    /// <summary>Represents the mailgun value.</summary>
    [Display(Name = "Mailgun")]
    Mailgun = 9,

    /// <summary>Represents the postmark value.</summary>
    [Display(Name = "Postmark")]
    Postmark = 10,

    /// <summary>Represents the fastmail value.</summary>
    [Display(Name = "Fastmail")]
    Fastmail = 11,

    /// <summary>Represents the proton mail value.</summary>
    [Display(Name = "Proton Mail")]
    ProtonMail = 12,

    /// <summary>Represents the cloudflare email routing value.</summary>
    [Display(Name = "Cloudflare Email Routing")]
    CloudflareEmailRouting = 13,

    /// <summary>Represents the cisco secure email value.</summary>
    [Display(Name = "Cisco Secure Email")]
    CiscoSecureEmail = 14
}

