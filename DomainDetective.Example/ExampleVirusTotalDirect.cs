using System;
using System.Text;
using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program
{
    /// <summary>Shows direct VirusTotalClient usage.</summary>
    public static async Task ExampleVirusTotalDirect()
    {
        var client = new VirusTotalClient("YOUR_API_KEY");

        var domain = await client.GetDomain("example.com");
        Console.WriteLine($"Domain reputation: {domain?.Data?.Attributes?.Reputation}");
        if (domain?.Data?.Attributes?.LastAnalysisStats is { } domainStats)
        {
            Helpers.ShowPropertiesTable("Domain stats", domainStats);
        }

        var ip = await client.GetIpAddress("8.8.8.8");
        Console.WriteLine($"IP reputation: {ip?.Data?.Attributes?.Reputation}");
        if (ip?.Data?.Attributes?.LastAnalysisStats is { } ipStats)
        {
            Helpers.ShowPropertiesTable("IP stats", ipStats);
        }

        var url = "https://example.com/";
        var urlId = Convert.ToBase64String(Encoding.UTF8.GetBytes(url))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        var urlResp = await client.GetUrl(urlId);
        if (urlResp?.Data?.Attributes?.LastAnalysisStats is { } urlStats)
        {
            Helpers.ShowPropertiesTable("URL stats", urlStats);
        }
    }
}
