# Endpoint rule packs

`EndpointRulePackEvaluator` evaluates versioned data against an explicitly identified endpoint observation. It does not probe a server, delete inventory, or approve migration exceptions. Pack data and its schema ship under `EndpointRulePacks` in the package; generic built-ins are also embedded so ordinary consumers require no external file.

```csharp
var options = new EndpointRulePackOptions();
options.Packs.Add(new EndpointRulePack { Id = "hosting-stubs", Enabled = false });
var evaluator = new EndpointRulePackEvaluator(options);
var endpoint = CertificateEndpointIdentity.Create("www.example.test", 443, "tls");
var identity = new CertificateObservationIdentity("tls-live", fingerprint, endpoint, observationId, "https-443", "outside");
var hits = evaluator.Evaluate(input, identity, observedAtUtc);
var counts = evaluator.Summarize(hits);
```

Set `UseBuiltInPacks = false` to start without defaults. Pack overrides inherit built-in version and rules; definitions with the same rule id replace that rule. Disabled packs and rules remain deployment configuration, but do not participate in evaluation. Additional packs require a three-part version. Invalid ids, versions, matcher types, CIDRs, regular expressions and effects fail before inventory processing. Regular expressions have a 100 ms budget per match.

Each rule combines every `allOf` matcher with at least one `anyOf` matcher when alternatives are present. Matcher values are alternatives. DNS suffixes require label boundaries. A missing live issuer never satisfies a `live-issuer` condition. Current Azure service tags may be supplied through `EndpointAttributionInput.AzureServiceTags`; point-in-time seeds retain the pack's version/provenance.

Provider packs default to `tag-only`. An explicit deployment `expected` value is metadata for organizational policy, not a result of technical detection. A consumer may remove healthy expected endpoints from a migration queue, but must still raise expiry and certificate/hostname/chain-validation failures. `exclude-from-owner-views` and `quarantine` describe reversible projections over retained observations.

Hits retain pack/rule versions, actual signals, source identity, fingerprint, endpoint, profile, vantage and observation time. `Summarize` reports every enabled rule, including zero-hit rules; it counts distinct observations, endpoints and hosts independently. Duplicate hit inputs are idempotent. Exclusion totals are unique across rules, and `OverlappingHits` records the extra hits instead of inflating inventory totals. Summarize one explicit population/snapshot at a time.

The existing `EndpointAttributionDetector` scorer consumes the same provider data. Its confidence/candidate semantics remain distinct from exact pack predicates and consumer policy. Front Door, CDN and Traffic Manager retain different service identities even when a deployment groups them for reporting.

A matcher's `attributionEnabled` value defaults to `true`. Set it to `false` when a predicate belongs only to pack classification. The Front Door point-in-time address seeds use this distinction: they remain available to classification with live issuer evidence, while legacy attribution continues to use the caller's current Azure service-tag catalog without scoring the same address twice.

An optional rule `attributionServices` list preserves a different service scope for legacy scoring. When omitted, scoring uses `services`. The built-in HTTP provider rules keep `HTTPS` and `HTTPS-Alt` for legacy attribution while their classification predicates also accept raw `tls` observations. A timed-out hostname or CNAME regular expression counts as a non-match for that operand; later operands and other rules still run.

Issuance/name assertions set `CertificateObservationIdentity.IsEndpointObservation` to false. They may match name rules, but never contribute live issuer, address or CNAME evidence, service-scoped rules, or endpoint counts. Summaries count all supplied source assertions once regardless of other live evidence for that host. A report leaves the issuance port empty and labels the observation scope.

The `cname-regex` matcher applies a bounded, case-insensitive expression to each observed CNAME target. It preserves exact and wildcard target patterns when adapting an earlier configuration; it does not broaden an exact target into a suffix rule.
