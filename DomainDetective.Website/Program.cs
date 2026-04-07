using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using DomainDetective.Toolbox.Services;
using DomainDetective.Website.Services;
using DomainDetective.Website;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

builder.Services.AddScoped(sp => new HttpClient {
    BaseAddress = new Uri(builder.HostEnvironment.BaseAddress),
    Timeout = TimeSpan.FromMinutes(5)
});
builder.Services.AddSingleton<ToolRegistry>();
builder.Services.AddScoped<ToolAvailabilityService>();
builder.Services.AddScoped<BrowserDnsService>();
builder.Services.AddScoped<BrowserOverviewService>();
builder.Services.AddScoped<HostedAnalysisService>();
builder.Services.AddScoped<SiteNavigationService>();

await builder.Build().RunAsync();
