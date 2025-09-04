using System;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using DomainDetective.CLI;
using Xunit;

namespace DomainDetective.CLI.Tests;

public class TestCliHelp
{
    private static async Task<string> CaptureOutputAsync(params string[] args)
    {
        var sw = new StringWriter();
        var original = Console.Out;
        Console.SetOut(sw);
        try
        {
            await Program.Main(args);
        }
        finally
        {
            Console.SetOut(original);
        }
        return Regex.Replace(sw.ToString(), @"\u001b\[[0-9;]*[A-Za-z]", string.Empty);
    }

    [Fact]
    public async Task RootHelp_IncludesExamples()
    {
        var output = await CaptureOutputAsync("--help");
        Assert.Contains("EXAMPLES:", output);
        Assert.Contains("DomainDetective check example.com", output);
    }

}
