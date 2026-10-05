using DomainDetective.Toolbox.Components.Tools.EmailSecurity;

namespace DomainDetective.Website.Tests;

public sealed class MessageAnalyzerToolComponentTests : BunitContext {
    [Fact]
    public void PastedHeadersShowEvidenceAndClearRemovesMessage() {
        var component = Render<MessageAnalyzerTool>();
        component.Find("#message-text").Input("From: sender@example.com\r\nSubject: <img src=x onerror=alert(1)>\r\nAuthentication-Results: mx.example; dkim=pass header.d=example.com\r\nX-Note: \u202Econtrol\r\n");
        component.Find("#message-trust").Input("mx.example");
        component.Find("form").Submit();
        component.WaitForAssertion(() => {
            Assert.Contains("Configured", component.Markup);
            Assert.Contains("Not performed", component.Markup);
            Assert.Contains("sender@example.com", component.Markup);
            Assert.Contains("[U+202E]", component.Markup);
            Assert.Empty(component.FindAll("img"));
        });
        component.FindAll("button").Single(button => button.TextContent == "Clear message").Click();
        Assert.Empty(component.FindAll(".result-table"));
        Assert.DoesNotContain("sender@example.com", component.Markup);
    }

    [Fact]
    public void VerificationWithoutOriginalFileShowsActionableError() {
        var component = Render<MessageAnalyzerTool>();
        component.Find("#message-text").Input("From: sender@example.com\r\n");
        component.Find("input[type=checkbox]").Change(true);
        component.Find("form").Submit();
        component.WaitForAssertion(() => Assert.Contains("Choose the original .eml file", component.Find("[role=alert]").TextContent));
        Assert.Empty(component.FindAll(".result-table"));
    }
}
