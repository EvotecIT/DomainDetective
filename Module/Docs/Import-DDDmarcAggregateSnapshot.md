---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Import-DDDmarcAggregateSnapshot
## SYNOPSIS
Imports DMARC aggregate reports into a time-series store.

## SYNTAX
### Path (Default)
```powershell
Import-DDDmarcAggregateSnapshot [-Path] <string> -StorePath <string> [-NoDeduplicate] [-AsResult] [<CommonParameters>]
```

### Imap
```powershell
Import-DDDmarcAggregateSnapshot -StorePath <string> -ImapHost <string> -Credential <pscredential> [-ImapPort <int>] [-ImapUseSsl <bool>] [-Mailbox <string>] [-SubjectContains <string>] [-SinceUtc <datetime>] [-MaxMessages <int>] [-MaxAttachmentMb <int>] [-OnlyUnseen <bool>] [-NoDeduplicate] [-AsResult] [<CommonParameters>]
```

## DESCRIPTION
Parses .xml/.gz/.zip DMARC aggregate feedback reports and stores normalized snapshots on disk.

## EXAMPLES

### EXAMPLE 1
```powershell
Import-DDDmarcAggregateSnapshot -Path .\Reports -StorePath .\Store
```


### EXAMPLE 2
```powershell
Import-DDDmarcAggregateSnapshot -StorePath .\Store -ImapHost imap.example.com -Credential (Get-Credential) -Mailbox INBOX -SinceUtc (Get-Date).ToUniversalTime().AddDays(-7)
```


## PARAMETERS

### -AsResult
Return the ingest result wrapper instead of snapshots.

```yaml
Type: SwitchParameter
Parameter Sets: Path, Imap
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
Credential for IMAP authentication.

```yaml
Type: PSCredential
Parameter Sets: Imap
Aliases: None
Possible values:

Required: True
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ImapHost
IMAP host used for mailbox ingestion.

```yaml
Type: String
Parameter Sets: Imap
Aliases: None
Possible values:

Required: True
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ImapPort
IMAP port (default 993).

```yaml
Type: Int32
Parameter Sets: Imap
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ImapUseSsl
Use SSL/TLS for IMAP connection (default true).

```yaml
Type: Boolean
Parameter Sets: Imap
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Mailbox
Mailbox folder name (default INBOX).

```yaml
Type: String
Parameter Sets: Imap
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MaxAttachmentMb
Maximum attachment size to decode in MB (0 for unlimited).

```yaml
Type: Int32
Parameter Sets: Imap
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MaxMessages
Maximum number of messages to scan (default 500).

```yaml
Type: Int32
Parameter Sets: Imap
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -NoDeduplicate
Disable in-run deduplication (by report-id/date-range/org/domain).

```yaml
Type: SwitchParameter
Parameter Sets: Path, Imap
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -OnlyUnseen
Only consider unseen messages (default true).

```yaml
Type: Boolean
Parameter Sets: Imap
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Path
Path to a report file/folder/wildcard.

```yaml
Type: String
Parameter Sets: Path
Aliases: None
Possible values:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByValue, ByPropertyName)
Accept wildcard characters: False
```

### -SinceUtc
Only fetch messages delivered since this UTC date/time.

```yaml
Type: Nullable`1
Parameter Sets: Imap
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -StorePath
Root directory for snapshot storage.

```yaml
Type: String
Parameter Sets: Path, Imap
Aliases: None
Possible values:

Required: True
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SubjectContains
Only scan messages with a subject containing this string.

```yaml
Type: String
Parameter Sets: Imap
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

- `System.String`

## OUTPUTS

- `DomainDetective.TimeSeries.DmarcAggregate.DmarcAggregateSnapshot`

## RELATED LINKS

- None
