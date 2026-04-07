# Certificate Inventory Minimal Service Contract

## Purpose

This document defines the minimal reusable contract that `DomainDetective` should provide to service hosts such as DomainDetectivePlus.

The goal is to keep `DomainDetective` reusable and mostly stateless, while allowing service hosts to apply their own persistence, scheduling, retry, and operator-facing policy.

## Product intent

For certificate monitoring, the reusable layer should make this simple:

1. discover relevant host names from seed domains
2. probe live TLS where it makes sense
3. look up CT-backed certificate evidence when live TLS cannot answer
4. normalize the result into source-aware certificate facts

That is the reusable contract.

## What DomainDetective should own

`DomainDetective` should own the protocol and evidence primitives.

### 1. CT discovery primitives

Responsibilities:

- discover host names from CT
- support native CT and passive CT providers
- preserve discovery lineage and provider diagnostics

The existing CT discovery logic in:

- `DomainDetective/CertificateInventoryCapture.CtDiscovery.cs`

is the right kind of responsibility for the reusable layer.

### 2. Live certificate probe primitives

Responsibilities:

- probe HTTPS and mail TLS endpoints
- classify probe failures
- normalize certificate fields, SANs, EKUs, and validity

The core probe orchestration in:

- `DomainDetective/CertificateInventoryCapture.cs`

belongs in the reusable layer as long as it remains host- and evidence-oriented rather than service-policy-oriented.

### 3. CT evidence lookup primitives

Responsibilities:

- hydrate missing CT metadata for discovered or exact hosts
- support exact-host CT evidence lookup
- normalize provider responses into one certificate-evidence shape

The reusable part of this exists in:

- `DomainDetective/CertificateInventoryCapture.CtMetadataBackfill.cs`
- `DomainDetective/PassiveCtSourceClient.cs`

### 4. Certificate normalization

Responsibilities:

- produce one reusable, source-aware certificate evidence shape
- keep source identity clear: live TLS vs CT
- preserve provider diagnostics without turning them into service-state policy

## What DomainDetective should not own

`DomainDetective` should not become the place where service-specific queue policy lives.

It should not own:

- monitored-estate backlog policy
- first-pass versus steady-state scheduling
- domain cooldown multipliers
- archive/admission/promotion lanes
- service-specific repair punishment state
- tenant-specific manual-review semantics
- Windows-service or SQLite-specific persistence concerns

Those belong in the service host.

## Minimal output contract for service hosts

Service hosts do not need many different CT-related flows from the reusable layer.

They need four reusable outputs.

### 1. Discovered names

For each discovered host:

- `HostName`
- `SourceDomain`
- `DiscoverySource`
- `FirstSeenUtc`
- `LastSeenUtc`
- `ResolutionStatus`
- latest CT certificate identity when known
- CT provider/source list

### 2. Live endpoint observations

For each probed endpoint:

- normalized endpoint identity
- live certificate metadata when available
- failure classification when not available
- observed DNS/web/TLS facts that explain the outcome

### 3. CT evidence observations

For each CT evidence lookup:

- host identity
- certificate identity
- observed/source timestamp
- source kind and source name
- enough normalized certificate fields to populate last-known evidence

### 4. Provider diagnostics

For CT and probe work:

- source/provider
- state
- retry suggestion
- cooldown or rate-limit hints when applicable

Diagnostics are useful. They should stay diagnostics, not become long-lived service state by themselves.

## Recommended internal simplification

`CertificateInventoryCapture` currently carries too much responsibility in one object.

It should be treated as a composition of a few explicit reusable jobs:

1. `CT discovery`
2. `target planning`
3. `live probe execution`
4. `CT evidence hydration`
5. `result normalization`

That can still remain behind a single high-level capture entry point, but the reusable contract should make those jobs obvious.

## Recommended future shape

### Keep one high-level convenience API

It is still useful to keep one orchestrator for callers who want:

- seeds in
- normalized capture result out

### Also expose the smaller reusable jobs cleanly

Service hosts benefit when they can call smaller pieces directly:

- discover names from CT without immediately probing everything
- run live TLS over a bounded endpoint set
- hydrate CT evidence for exact hosts only

That is the boundary DDPlus needs.

## Design rules for future work

### Rule 1: separate discovery from proof

- CT discovery creates candidates
- live TLS proves current truth
- CT evidence fills historical or last-known truth

### Rule 2: prefer stateless return values over hidden service policy

The reusable layer should return:

- observations
- normalized evidence
- diagnostics

The service host should decide:

- retry timing
- suppression windows
- manual-review transitions

### Rule 3: keep exact-host CT evidence lookup explicit

Exact-host CT evidence is a distinct reusable need and should not be hidden behind broad portfolio capture logic.

### Rule 4: keep provider problems as diagnostics

Rate limits, cooldowns, and invalid responses matter, but they should not force service-specific backlog semantics into the reusable library.

## What this enables for DomainDetectivePlus

If `DomainDetective` stays focused on reusable discovery and evidence collection, DDPlus can become much simpler:

- scope host state in DDPlus
- run simpler DNS/TLS/CT service lanes in DDPlus
- keep operator-facing dispositions in DDPlus
- avoid embedding service-specific rescue logic back into the reusable layer

## Success definition

This contract is working when a service host can do all of the following without inventing new reusable-layer policy:

- discover names from CT
- probe a chosen set of live endpoints
- request exact-host CT evidence for unresolved or unreachable hosts
- receive normalized certificate evidence plus diagnostics

If a future feature needs archive admission, first-pass catch-up heuristics, or service-specific repair state inside `DomainDetective`, that is a sign the boundary has started to blur again.
