# Certificate Transparency ingestion

`CtLogIngestionClient` reads RFC 6962 JSON logs and Static CT data tiles. A caller can require cryptographic verification and complete certificate decoding for each batch:

```csharp
CtSignedTreeHead head = await client.GetVerifiedSignedTreeHeadAsync(
    log, previousDurableHead, TimeSpan.FromSeconds(30), cancellationToken);

CtLogIngestionBatch batch = await client.ReadBatchAsync(new CtLogIngestionBatchRequest {
    LogUrl = log.Url,
    SubmissionUrl = log.SubmissionUrl,
    MonitoringUrl = log.MonitoringUrl,
    ApiKind = log.ApiKind,
    PublicKey = log.PublicKey,
    LogId = log.LogId,
    PreviousTreeHead = head,
    RequireIntegrityVerification = true,
    RequireCompleteDecoding = true,
    StartIndex = nextIndex,
    BatchSize = 256
}, cancellationToken);
```

Obtain the descriptor's key and log ID from a trusted catalog. The reader checks that the key hashes to the log ID, verifies the signed tree head or checkpoint, and verifies every returned raw leaf against its Merkle root. Passing a previous verified head also requires a consistency proof when the tree grows and rejects rollback or a changed root at the same size. Persist the verified head with optimistic concurrency so another worker's newer anchor cannot be overwritten. The reader's short-lived cache does not provide restart persistence.

Verification uses a signed head for range bounds and ignores `KnownTreeSize`. RFC logs may return a shorter prefix than requested; use the actual `EndIndex` and retain the unreturned range. Static data and hash tile reads support partial tiles and their full-tile fallback.

Complete decoding throws `CtEntryDecodingException` with the failed index and original leaf/extra data. Static entry failures also retain the original tile entry. A malformed static tile throws `CtDataTileDecodingException` with its first failed index and original tile bytes. Persist that evidence before retrying; a failed read does not return a partially decoded batch that can safely advance a cursor.

Precertificate names and metadata must match the signed TBSCertificate. The reader removes CT poison/SCT-list extensions and supports the issuer and Authority Key Identifier transformation for dedicated precertificate signers. This verifies the logged fields; it does not establish Web PKI trust, certificate validity, or acceptance by a browser. Inclusion and consistency from one retained anchor also do not establish agreement with independent witnesses.

Certificate bytes must contain exactly one DER-encoded X.509 certificate. The reader rejects PKCS#7 containers, PEM, BER and trailing data, including in dedicated precertificate signer chains. The certificate materialized into the record must match the checked DER bytes.

Verification and complete decoding are opt-in to preserve existing ingestion behavior. Applications that leave complete decoding disabled receive diagnostics for skipped certificates and must decide whether advancing over those entries meets their delivery contract.
