# Typed assessment page

I render an illustrative `DomainAssessmentReport` through `AssessmentHtmlReport.BuildPage`, while keeping the existing renderer available for comparison. The fixture covers findings, facts, metrics, guidance, narrative and tabular evidence. `domain-parity.json` records the fields found in the classic document and complete page print projection; the run fails if the page loses a checked value.

The run also checks that repeated summary inputs appear once within a check, guidance metadata uses labelled facts, and finding codes resolve through a display-label pack. A mapped strict pack succeeds, an unmapped strict value fails, and normal rendering humanises an unmapped value.

I point the existing local-source switches at the HtmlForgeX page-core and CanopyX checkouts:

```sh
dotnet run --project Prototypes/HtmlForgeX3/DomainDetective.PageProof.csproj -c Release \
  -p:UseLocalHtmlForgeX=true -p:HtmlForgeXProjectPath="$HFX_ROOT/HtmlForgeX/HtmlForgeX.csproj" \
  -p:UseLocalCanopyX=true -p:CanopyXRoot="$CX_ROOT" -- "$OUTPUT_DIRECTORY"
```

The output includes light, dark, classic and complete script-free print pages. The input is synthetic and makes no claim about the public domain's current configuration. The report's data model and existing package pins remain unchanged.
