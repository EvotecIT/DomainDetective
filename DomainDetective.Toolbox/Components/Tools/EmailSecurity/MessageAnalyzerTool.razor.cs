using System.Text;
using System.Text.Json;
using DomainDetective.Reports;
using Microsoft.AspNetCore.Components.Forms;

namespace DomainDetective.Toolbox.Components.Tools.EmailSecurity;

public partial class MessageAnalyzerTool {
    private const string OfflineKeyPlaceholder = "{\"s1._domainkey.example.com\":\"v=DKIM1; k=rsa; p=BASE64_PUBLIC_KEY\"}";
    private readonly CancellationTokenSource _lifetime = new();
    private string _headerText = string.Empty;
    private string _trustedIds = string.Empty;
    private string _expectedMx = string.Empty;
    private string _publicKeys = string.Empty;
    private bool _verifySignatures;
    private bool _busy;
    private string? _error;
    private string? _fileName;
    private byte[]? _fileBytes;
    private IReadOnlyList<MessageHeaderReport.Section>? _sections;
    private MessageHeaderReportBrief? _brief;
    private string? _reportText;

    private async Task ReadFileAsync(InputFileChangeEventArgs args) {
        _error = null;
        _sections = null;
        _brief = null;
        _reportText = null;
        ClearFile();
        _busy = true;
        try {
            await using var stream = args.File.OpenReadStream(25 * 1024 * 1024, _lifetime.Token);
            using var output = new MemoryStream();
            await stream.CopyToAsync(output, _lifetime.Token);
            _fileBytes = output.ToArray();
            _fileName = args.File.Name;
            _headerText = string.Empty;
        } catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
        catch (Exception ex) when (ex is IOException || ex is ArgumentException) { _error = ex.Message; }
        finally { _busy = false; }
    }

    private async Task AnalyzeAsync() {
        _error = null;
        _sections = null;
        _brief = null;
        _reportText = null;
        _busy = true;
        try {
            if (_fileBytes == null && string.IsNullOrWhiteSpace(_headerText)) { throw new ArgumentException("Choose a file or paste header text."); }
            if (_verifySignatures && _fileBytes == null) { throw new ArgumentException("Choose the original .eml file to verify its signatures."); }
            var options = new MessageVerificationOptions { HeaderOptions = new MessageHeaderAnalysisOptions { TrustedAuthServIds = SplitNames(_trustedIds) } };
            if (_verifySignatures && !string.IsNullOrWhiteSpace(_publicKeys)) {
                options.PublicKeyRecords = JsonSerializer.Deserialize<Dictionary<string, string>>(_publicKeys) ?? throw new ArgumentException("Public keys must be a JSON dictionary.");
            }
            using var health = new DomainHealthCheck();
            health.DnsConfiguration.QueryDnsOverride = (_, _) => throw new InvalidOperationException("Browser message analysis cannot use DNS.");
            var result = _verifySignatures
                ? await health.AnalyzeMessageAsync(_fileBytes!, options, _lifetime.Token)
                : health.AnalyzeMessageHeaders(_fileBytes == null ? _headerText : Encoding.UTF8.GetString(_fileBytes), options.HeaderOptions, SplitNames(_expectedMx), _lifetime.Token);
            if (_verifySignatures) { result.CompareExpectedMx(SplitNames(_expectedMx)); }
            result.Source = _fileName;
            _brief = MessageHeaderReportBrief.Build(result);
            _sections = MessageHeaderReport.Build(result);
            _reportText = MessageHeaderReport.ToText(result);
        } catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
        catch (Exception ex) when (ex is ArgumentException || ex is JsonException || ex is FormatException || ex is InvalidOperationException || ex is IOException) { _error = ex.Message; }
        finally { _busy = false; }
    }

    private static string[] SplitNames(string value) => value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private void ClearFile() {
        if (_fileBytes != null) { Array.Clear(_fileBytes); }
        _fileBytes = null;
        _fileName = null;
    }

    private void Clear() {
        ClearFile();
        _headerText = string.Empty;
        _publicKeys = string.Empty;
        _sections = null;
        _brief = null;
        _reportText = null;
        _error = null;
    }

    public ValueTask DisposeAsync() {
        _lifetime.Cancel();
        _lifetime.Dispose();
        Clear();
        return ValueTask.CompletedTask;
    }
}
