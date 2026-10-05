# Analyze email messages

DomainDetective analyzes pasted headers and local `.eml` files without uploading message content. The C# engine, PowerShell cmdlet, CLI, and browser tool share the same parsing and evidence model.

## Authentication evidence

Receiver-reported SPF, DKIM, DMARC, ARC, and Microsoft composite authentication are claims contained in the message. Every observation retains its field, writer (`authserv-id`), properties, original value, and provenance:

- `Configured`: the writer exactly matches an identifier supplied by the caller. Use this only with a receiving gateway that removes forged authentication fields at its trust boundary.
- `RouteMatched`: the writer matches a reported Received `by` host. This is a useful consistency check, but both fields can be forged.
- `Unverified`: an identified writer has no configured trust or route match.
- `Absent`: the observation has no writer identifier.
- `None`: no authentication observation supplies the summary.

The summary prefers configured ordinary Authentication-Results observations, then the topmost ordinary field. Preserved Authentication-Results-Original fields remain evidence of earlier claims and never supply the selected summary, even when no ordinary field has usable methods. Lower fields do not overwrite that summary. Conflicting observations for the same authentication identity produce an ambiguous result and a finding. Received-SPF supplies a fallback with its own writer and provenance; it cannot override configured receiver evidence. This changes the older behavior that selected the last Authentication-Results field.

SPF and DKIM identity alignment reports `Strict`, `Relaxed`, `None`, or an unknown/null result when evidence is insufficient. Duplicate From fields leave alignment unknown because clients may select different identities. Relaxed alignment uses the bundled full Public Suffix List, including private suffixes, wildcard rules, exceptions, and IDN normalization. Alignment is separate from successful authentication and does not evaluate a delivery-time DMARC policy.

For a reported null reverse path, SPF alignment uses the reported HELO identity, including `Received-SPF` evidence. A HELO-only observation without evidence of a null reverse path leaves MAIL FROM alignment unknown.

## Original-message verification

`AnalyzeMessageAsync` and `AnalyzeMessageFileAsync(..., verifySignatures: true)` verify DKIM and ARC cryptographically through MimeKit. Supply original message bytes, including the body. Reconstructing a MIME message from displayed headers can change signed content.

Verification is offline by default. Public keys are a dictionary from `selector._domainkey.domain` to the complete public-key TXT value. Native C#, CLI, and PowerShell callers can explicitly enable DNS key acquisition. The browser tool accepts offline keys and performs no DNS lookups.

Each signature outcome is separate from receiver-reported authentication:

- `Valid`: the supplied message validates against the available public key. This does not prove sender intent, delivery-time DNS, or trust in an ARC sealer.
- `Invalid`: cryptographic verification completed and the supplied content or chain did not validate.
- `Inconclusive`: a key, algorithm, parsing prerequisite, or verification deadline prevented completion.
- `NotPerformed`: a body boundary is unavailable or a configured signature limit was reached.

ARC structure analysis requires one ARC-Seal, ARC-Message-Signature, and ARC-Authentication-Results field per sequential instance, consistent instance ordering, and appropriate `cv` values. `ValidChain` and `ArcChainState.Valid` describe header structure only. `ChainValidationFailed` retains a seal's reported `cv=fail`; cryptographic ARC results appear in `SignatureVerification`.

## C#

```csharp
using var health = new DomainDetective.DomainHealthCheck();
var options = new DomainDetective.MessageVerificationOptions {
    HeaderOptions = new DomainDetective.MessageHeaderAnalysisOptions {
        TrustedAuthServIds = new[] { "mx.example.com" }
    }
};
options.PublicKeyRecords["s1._domainkey.example.com"] = "v=DKIM1; k=rsa; p=...";
var message = await health.AnalyzeMessageFileAsync("message.eml", verifySignatures: true, options: options);
Console.WriteLine(DomainDetective.Reports.MessageHeaderReport.ToText(message));
```

For pasted headers, use `AnalyzeMessageHeaders(text, options.HeaderOptions)`. A header-only file is read only through its header/body separator, so a large body does not need to be loaded.

## PowerShell

```powershell
Get-Content -LiteralPath './headers.txt' -Raw |
    Get-DDEmailMessageHeaderInfo -TrustedAuthServId 'mx.example.com'

# Clipboard input uses the same text pipeline.
Get-Clipboard -Raw | Get-DDEmailMessageHeaderInfo

# FileInfo pipeline and Path arrays support multiple messages.
Get-ChildItem -Path './messages' -Filter '*.eml' |
    Get-DDEmailMessageHeaderInfo -TrustedAuthServId 'mx.example.com' -ExportFormat Markdown -ExportPath './message-report.md'

$keys = @{ 's1._domainkey.example.com' = 'v=DKIM1; k=rsa; p=...' }
Get-DDEmailMessageHeaderInfo -Path './message.eml' -VerifySignatures -PublicKeyRecords $keys

# Explicitly permit public-key DNS queries instead of supplying offline keys.
Get-DDEmailMessageHeaderInfo -Path './message.eml' -VerifySignatures -AllowDnsLookups
```

Use `Path` for byte-preserving verification. `HeaderText -VerifySignatures` encodes the supplied text as UTF-8 and cannot restore original bytes lost through copying. The friendly alias is `Get-EmailHeaderInfo`. The cmdlet supports Windows PowerShell 5.1 and PowerShell 7. Reports support HTML, Markdown, MarkdownHtml, Word, and Excel; batch exports include each message's source and evidence.

## CLI

```text
DomainDetective.CLI AnalyzeMessageHeader --file headers.txt --trusted-authserv-id mx.example.com --json
DomainDetective.CLI AnalyzeMessageHeader --file message.eml --verify-signatures --public-keys public-keys.json --report message-report.txt
DomainDetective.CLI AnalyzeMessageHeader --file message.eml --verify-signatures --allow-dns --json
```

The public-key JSON file contains a dictionary such as `{"s1._domainkey.example.com":"v=DKIM1; k=rsa; p=..."}`. Supply exactly one of `--file` and `--header`. Signature verification requires an original `--file`; key and DNS options require `--verify-signatures`.

## Browser and reports

The Message Analyzer tool at `/tools/message-analyzer` accepts pasted headers or a local file. It shows authentication provenance, identity alignment, route timing and TLS, DKIM metadata, ARC instances, Exchange classification, filtering verdicts, mailing-list fields, anomalies, and the original field inventory. Enable verification and supply offline public keys for an original `.eml` file. Clear message removes the loaded content and results from the component.

The reusable report projection powers the browser, CLI text output, and dedicated `MessageHeaderHtmlReport`, `MessageHeaderMarkdownReport`, and `MessageHeaderOfficeReport` writers. Reports render header values as text, make Unicode direction controls visible, and do not fetch unsubscribe links or execute header-supplied markup. Reports begin with an executive brief, the limits of the supplied evidence, prioritized findings, and recommended next steps with reasons and verification guidance. Excel includes navigation and separate evidence worksheets with wrapped cells, fixed widths, frozen headings, and input identifiers for batch filtering. Long values continue across numbered text parts so Excel cell limits do not discard evidence. Header content is stored as values rather than formulas. Word renders wide evidence as readable field/evidence records instead of compressing many columns onto a page.

## Diagnostics and limits

Received timestamps retain delivery order. Negative adjacent delays flag clock skew rather than reorder the route. TLS versions and ciphers are reported evidence from Microsoft, Postfix, and Exim syntax. HELO, reported reverse DNS, private addresses, RFC 3848 protocol classes, and provider hints remain observations rather than live verification.

Diagnostics include duplicate singleton fields, Unicode direction controls, differing Reply-To domains, malformed DKIM metadata, deprecated hashes, limited signed-body length, expiry at analysis time, unsigned From, configured-result conflicts, omitted route hops, incomplete ARC sets, and forwarding witnesses. Exchange and Microsoft filtering fields retain raw values alongside documented meanings. Undocumented authentication mechanism codes remain unknown; an unsupported interpretation is never guessed.

One-click unsubscribe metadata requires the post token and a single HTTPS target in an unambiguous header pair. This describes the advertised mechanism; DKIM coverage, signature validity, and endpoint behavior remain separate. Unsubscribe URLs are never fetched. Public-key DNS outcomes, including failed lookups, are reused per host within one verification operation so repeated signatures do not exhaust the query budget on the same key.

Default resource bounds are 2 MiB of header characters, 200 Received hops, 25 MiB of original MIME bytes, 50 DKIM verifications, 50 public-key DNS query requests, and a 30-second verification deadline. C# callers can configure these limits. Omitted hops and skipped signatures are explicit; oversized inputs are rejected. The browser limits files to 25 MiB, pasted headers to 2 MiB characters, key JSON to 1 MiB characters, and displayed rows to 200 per section; its complete text report retains all parsed rows. CLI key files are limited to 1 MiB.

No analyzer can prove a forged header's author from header text alone. Current DNS keys can differ from delivery-time keys, reported route clocks can be wrong, a valid ARC signature does not make its sealer trustworthy, and a copied message may no longer match its original signatures. These evidence boundaries remain visible in the results.
