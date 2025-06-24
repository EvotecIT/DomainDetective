using DomainDetective;
using System.Text.Json;

if (args.Length == 0 || args.All(a => a.StartsWith("-")))
{
    Console.WriteLine("Usage: DomainDetective.CLI <domain> [--json]");
    return;
}

var outputJson = args.Contains("--json");
var domain = args.First(a => !a.StartsWith("-"));

var healthCheck = new DomainHealthCheck();
await healthCheck.Verify(domain);

if (outputJson)
{
    Console.WriteLine(healthCheck.ToJson());
}
else
{
    Console.WriteLine($"Health check completed for {domain}");
}
