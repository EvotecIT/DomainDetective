---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# New-DDDmarcRecord
## SYNOPSIS
Builds a DMARC record string.

## SYNTAX
### __AllParameterSets
```powershell
New-DDDmarcRecord [[-Policy] <string>] [-SubPolicy <string>] [-AggregateUri <string>] [-ForensicUri <string>] [-Percent <Int32>] [-DkimAlignment <string>] [-SpfAlignment <string>] [-FailureOptions <string>] [-ReportingInterval <Int32>] [-DomainName <string>] [-DnsApiUrl <uri>] [-Publish] [-StepByStep] [<CommonParameters>]
```

## DESCRIPTION
Part of the DomainDetective project.

## EXAMPLES

### EXAMPLE 1
```powershell
New-DDDmarcRecord -Policy reject -AggregateUri mailto:reports@example.com
```


## PARAMETERS

### -AggregateUri
Aggregate report URI(s).

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DkimAlignment
DKIM alignment mode.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values: r, s

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DnsApiUrl
DNS provider API endpoint.

```yaml
Type: Uri
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DomainName
Domain name for publishing.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -FailureOptions
Failure reporting options.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ForensicUri
Forensic report URI(s).

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Percent
Percentage of mail subjected to the policy.

```yaml
Type: Int32
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Policy
Main DMARC policy.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values: none, quarantine, reject

Required: False
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Publish
Publish the record via DNS provider.

```yaml
Type: SwitchParameter
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ReportingInterval
Reporting interval in seconds.

```yaml
Type: Int32
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SpfAlignment
SPF alignment mode.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values: r, s

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -StepByStep
Prompt step by step for all options.

```yaml
Type: SwitchParameter
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SubPolicy
Policy applied to subdomains.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values: none, quarantine, reject

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

- `None`

## OUTPUTS

- `System.String`

## RELATED LINKS

- None
