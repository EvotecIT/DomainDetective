using System.ComponentModel.DataAnnotations;

namespace DomainDetective.Providers.Email;

public enum MailProviderKind
{
    Unknown = 0,

    [Display(Name = "Microsoft 365")]
    Microsoft365 = 1,

    [Display(Name = "Google Workspace")]
    GoogleWorkspace = 2,

    [Display(Name = "Mimecast")]
    Mimecast = 3,

    [Display(Name = "Barracuda Email Gateway Defense")]
    BarracudaEmailGatewayDefense = 4,

    [Display(Name = "Proofpoint Essentials")]
    ProofpointEssentials = 5,

    [Display(Name = "Zoho Mail")]
    ZohoMail = 6,

    [Display(Name = "SendGrid")]
    SendGrid = 7,

    [Display(Name = "Amazon SES")]
    AmazonSes = 8,

    [Display(Name = "Mailgun")]
    Mailgun = 9,

    [Display(Name = "Postmark")]
    Postmark = 10,

    [Display(Name = "Fastmail")]
    Fastmail = 11,

    [Display(Name = "Proton Mail")]
    ProtonMail = 12,

    [Display(Name = "Cloudflare Email Routing")]
    CloudflareEmailRouting = 13,

    [Display(Name = "Cisco Secure Email")]
    CiscoSecureEmail = 14
}

