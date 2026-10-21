# Certificate probe profiles

`CertificateProbeProfile` describes protocol negotiation independently of hostname observations. `StandardProfiles()` returns fresh definitions for the 443 TLS baseline, direct TLS 8443, SMTP 25 STARTTLS, FTP 21 explicit AUTH TLS, implicit FTPS 990 and LDAPS 636. Only the baseline is enabled by default. A consumer selects enabled profiles and its own scheduling policy.

```csharp
var profiles = CertificateProbeProfile.StandardProfiles();
var smtp = profiles.Single(profile => profile.Id == "smtp-starttls-25");
smtp.Enabled = true;
using var result = await CertificateProfileProbe.ProbeAsync("mail.example.test", smtp, TimeSpan.FromSeconds(10), cancellationToken);
// result.ProfileId, EndpointService, RemoteAddress and RemotePort identify the assertion.
// Certificate/hostname/chain validity remain separate facts even when the handshake succeeds.
```

`Resolve` validates ids, unique definitions, port boundaries, transport modes and nonempty service/vantage labels before a consumer queues work. It returns independent enabled snapshots. Configure a new id when a profile's meaning changes. The portable JSON transport names are `DirectTls`, `SmtpStartTls`, `FtpExplicitTls` and `FtpImplicitTls`; numeric and unknown modes are rejected by JSON parsing/validation.

The dispatcher reuses `TlsProbe`, `MailTlsAnalysis` and `FtpTlsAnalysis`. SMTP and explicit FTP negotiate their clear-text upgrade before TLS; implicit FTP uses its existing TLS engine. No profile authenticates or opens a data channel. Certificate-only SMTP probes disable auxiliary protocol enumeration and optional OpenSSL stapling checks; ordinary MailTlsAnalysis callers retain their existing defaults.

Dispose the result after consuming it. Certificate and chain copies are owned by the returned `TlsProbe.Result`. IPv4-mapped addresses are normalized consistently. Protocol-engine failures retain their normalized failure kind and captured endpoint, so connection refusal and timeouts do not turn into handshake failures in worker backoff policies. Caller cancellation propagates through the protocol engine.

Profile/vantage are observation dimensions. `CertificateObservationIdentity` preserves source, fingerprint, normalized endpoint, exact source observation id, profile and vantage. It never treats a reused certificate or a second port as a duplicate observation. Technical provider tags and deployment exceptions remain separate from protocol collection.
