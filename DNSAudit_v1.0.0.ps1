<# 
DNSAudit_v1.0.0_Public.ps1
Public release build.

Purpose:
- Single-file PowerShell DNS audit tool with WPF GUI
- Designed for fast operational diagnostics and CSV export
- Sanitized for public GitHub release

Notes:
- Run from PowerShell with: .\DNSAudit_v1.0.0_Public.ps1
- In ISE, open the file and run the full script with F5
#>

Set-StrictMode -Version Latest

$script:AppVersion = '1.0.0'
$script:AppAuthor  = 'Rafael Alba'
$script:LogPath = $null
$script:LastAuditZoneSummaries = @()

function Get-DnsAuditExceptionText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [object]$ErrorObject
    )
    try {
        if($null -eq $ErrorObject){ return 'Unknown error (null).' }
        if($ErrorObject -is [System.Management.Automation.ErrorRecord]){
            $msg = [string]$ErrorObject.Exception.Message
            if(-not [string]::IsNullOrWhiteSpace($msg)){ return $msg }
            return ([string]$ErrorObject)
        }
        if($ErrorObject.PSObject.Properties['Exception']){
            $msg = [string]$ErrorObject.Exception.Message
            if(-not [string]::IsNullOrWhiteSpace($msg)){ return $msg }
        }
        return ([string]$ErrorObject)
    }
    catch {
        return 'Unable to extract exception text.'
    }
}

function Write-DnsAuditLog {
    [CmdletBinding()]
    param(
        [string]$Level = 'INFO',
        [string]$Message,
        [object]$Data
    )
    try {
        if([string]::IsNullOrWhiteSpace($script:LogPath)){ return }
        $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
        $line = '[{0}] [{1}] {2}' -f $ts, $Level.ToUpperInvariant(), $Message
        if($null -ne $Data){
            try {
                if($Data -is [string]){
                    $line += ' | ' + $Data
                }
                else {
                    $json = $Data | ConvertTo-Json -Depth 6 -Compress
                    if(-not [string]::IsNullOrWhiteSpace($json)){
                        $line += ' | ' + $json
                    }
                }
            }
            catch {
                $line += ' | <data serialization failed>'
            }
        }
        Add-Content -LiteralPath $script:LogPath -Value $line -Encoding UTF8
    }
    catch { }
}

function Initialize-DnsAuditLog {
    [CmdletBinding()]
    param(
        [string]$OutputDir
    )
    try {
        $baseDir = $OutputDir
        if([string]::IsNullOrWhiteSpace($baseDir)){
            $baseDir = Join-Path $env:USERPROFILE 'Desktop\DNS_Audit_Output'
        }
        if(-not (Test-Path -LiteralPath $baseDir)){
            New-Item -ItemType Directory -Path $baseDir -Force | Out-Null
        }
        $logDir = Join-Path $baseDir 'Logs'
        if(-not (Test-Path -LiteralPath $logDir)){
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        $script:LogPath = Join-Path $logDir ('DnsAudit_Debug_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
        '=== DNS Audit Debug Log ===' | Set-Content -LiteralPath $script:LogPath -Encoding UTF8
        Write-DnsAuditLog -Level 'INFO' -Message 'Log initialized'
        return $script:LogPath
    }
    catch {
        $script:LogPath = $null
        return $null
    }
}

function Test-DnsAuditPing {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$HostName,

        [int]$TimeoutSeconds = 1
    )

    if([string]::IsNullOrWhiteSpace($HostName)){
        return 'Failed'
    }

    if($TimeoutSeconds -le 0){
        return 'Skipped'
    }

    try {
        $params = @{
            Count       = 1
            Quiet       = $true
            ErrorAction = 'Stop'
        }

        if((Get-Command Test-Connection -ErrorAction Stop).Parameters.ContainsKey('TargetName')){
            $params['TargetName'] = $HostName
        }
        else {
            $params['ComputerName'] = $HostName
        }

        if((Get-Command Test-Connection -ErrorAction Stop).Parameters.ContainsKey('TimeoutSeconds')){
            $params['TimeoutSeconds'] = $TimeoutSeconds
        }

        $ok = Test-Connection @params
        if($ok){ return 'Success' }
        return 'Failed'
    }
    catch {
        try {
            $ping = New-Object System.Net.NetworkInformation.Ping
            $reply = $ping.Send($HostName, ($TimeoutSeconds * 1000))
            if($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success){
                return 'Success'
            }
            return 'Failed'
        }
        catch {
            return 'Failed'
        }
    }
}

function Set-DnsAuditConfigValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$Config,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [object]$Value
    )

    if($Config.PSObject.Properties[$Name]){
        $Config.$Name = $Value
    }
    else {
        $Config | Add-Member -NotePropertyName $Name -NotePropertyValue $Value
    }
}

$script:DefaultReportSelection = @{
    Missing_PTR                  = $true
    PTR_Mismatch                 = $true
    Stale_Record                 = $true
    Potential_Stale_Unreachable  = $true
    Multiple_Aliases_Same_Target = $true
    Shared_IP                    = $true
    Forward_Drift                = $true
    PTR_Multiple                 = $true
}

function Merge-DnsAuditReportSelection {
    [CmdletBinding()]
    param(
        [hashtable]$Selection
    )

    $merged = @{}
    foreach($key in $script:DefaultReportSelection.Keys){
        $merged[$key] = if($Selection -and $Selection.ContainsKey($key)) {
            [bool]$Selection[$key]
        } else {
            [bool]$script:DefaultReportSelection[$key]
        }
    }
    return $merged
}

function New-DnsAuditIssueText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Row,
        [bool]$PingDisabled
    )

    $recommended = New-Object System.Collections.Generic.List[string]
    $whatToCheck = New-Object System.Collections.Generic.List[string]
    $severity = 'Info'
    $category = 'OK'

    if($Row.RecordType -eq 'A'){
        if($Row.PTR_Status -eq 'None'){
            $severity = 'High'
            $category = 'Missing_PTR'
            $recommended.Add('Create or restore a reverse record if this host is still active and expected to have DNS reverse registration.') | Out-Null
            $whatToCheck.Add('Review the reverse zone delegation, secure dynamic update settings, and whether reverse registration is part of the expected standard for this subnet.') | Out-Null
        }
        elseif($Row.PTR_Status -eq 'Multiple'){
            $severity = 'High'
            $category = 'PTR_Multiple'
            $recommended.Add('Review whether the IP should keep a single canonical PTR and remove stale reverse entries if they are no longer valid.') | Out-Null
            $whatToCheck.Add('Inspect all PTR records for this IP and confirm which hostname should remain authoritative.') | Out-Null
        }
        elseif($Row.Forward_Status -eq 'Drift'){
            $severity = 'High'
            $category = 'Forward_Drift'
            $recommended.Add('Review why the hostname resolves to a different IPv4 address than the audited A record and correct the source of inconsistency if needed.') | Out-Null
            $whatToCheck.Add('Check record ownership, replication state, DHCP or client registration, and whether multiple valid A records are expected for this host.') | Out-Null
        }
        elseif($Row.PtrMismatch){
            $severity = 'Medium'
            $category = 'PTR_Mismatch'
            $recommended.Add('Review whether the forward and reverse records should reference the same canonical hostname or whether this is an accepted legacy naming case.') | Out-Null
            $whatToCheck.Add('Validate hostname standard, alias strategy, and whether the PTR currently points to an obsolete or alternate name.') | Out-Null
        }
        elseif($Row.Potential_Stale_Unreachable){
            $severity = 'Medium'
            $category = 'Potential_Stale_Unreachable'
            $recommended.Add('Treat this as a review candidate: the record is aged and ICMP reachability failed, but that does not prove the host is decommissioned.') | Out-Null
            $whatToCheck.Add('Check whether ICMP is blocked, whether the asset is still in service, and whether the record still receives expected updates.') | Out-Null
        }
        elseif($Row.Stale_Record){
            $severity = 'Low'
            $category = 'Stale_Record'
            $recommended.Add('Review whether the record is still expected to update. Clean it only if the host or service is no longer needed.') | Out-Null
            $whatToCheck.Add('Check DNS aging/scavenging behaviour, asset lifecycle state, and whether this record is intentionally static.') | Out-Null
        }
        elseif($Row.Shared_IP){
            $severity = 'Review'
            $category = 'Shared_IP'
            $recommended.Add('Review whether multiple hostnames sharing this IPv4 address is intentional, such as VIP, service naming, migration overlap, or legacy residue.') | Out-Null
            $whatToCheck.Add('Confirm whether the shared IP design is expected before treating this as cleanup work.') | Out-Null
        }
        elseif(-not $PingDisabled -and $Row.PingStatus -eq 'Failed'){
            $severity = 'Info'
            $category = 'Unreachable_NoFinding'
            $recommended.Add('No DNS conclusion from ICMP alone. Investigate reachability only if this host is expected to answer ping.') | Out-Null
            $whatToCheck.Add('Validate host firewall, network path, and whether ICMP is intentionally blocked.') | Out-Null
        }
    }

    if($Row.RecordType -eq 'CNAME' -and $Row.Multiple_Aliases_Same_Target){
        $severity = 'Review'
        $category = 'Multiple_Aliases_Same_Target'
        $recommended.Add('Review whether multiple aliases pointing to the same canonical target are still required. This may be normal, but it can also indicate naming drift.') | Out-Null
        $whatToCheck.Add('Confirm whether each alias is still in use before consolidating them.') | Out-Null
    }

    if($PingDisabled){
        $whatToCheck.Add('Quick mode skipped ICMP testing, so reachability was not part of this assessment.') | Out-Null
    }

    if($Row.Forward_Status -eq 'NotResolved'){
        if($category -eq 'OK'){
            $severity = 'High'
            $category = 'Forward_NotResolved'
        }
        $recommended.Add('Verify why the hostname does not resolve from the selected DNS server.') | Out-Null
        $whatToCheck.Add('Confirm zone data visibility, replication, and whether the queried DNS server is authoritative for this record.') | Out-Null
    }

    if($recommended.Count -eq 0){
        $recommended.Add('OK - no specific finding was classified for this record.') | Out-Null
    }
    if($whatToCheck.Count -eq 0){
        $whatToCheck.Add('Routine DNS verification only.') | Out-Null
    }

    [pscustomobject]@{
        FindingSeverity   = $severity
        FindingCategory   = $category
        RecommendedAction = ($recommended -join ' ')
        WhatToCheck       = ($whatToCheck -join ' ')
    }
}

function Test-DnsAuditInput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputDir,

        [Parameter(Mandatory)]
        [System.Collections.IEnumerable]$ZoneMap,

        [int]$StaleDays = 14,
        [int]$PingTimeoutSeconds = 1
    )

    $errors = New-Object System.Collections.Generic.List[string]

    if([string]::IsNullOrWhiteSpace($OutputDir)){
        $errors.Add('OutputDir is required.') | Out-Null
    }

    if($StaleDays -lt 1){
        $errors.Add('StaleDays must be greater than or equal to 1.') | Out-Null
    }

    if($PingTimeoutSeconds -lt 0 -or $PingTimeoutSeconds -gt 60){
        $errors.Add('PingTimeoutSeconds must be between 0 and 60.') | Out-Null
    }

    $zoneList = @($ZoneMap)
    if($zoneList.Count -eq 0){
        $errors.Add('At least one zone definition is required.') | Out-Null
    }

    $seenZoneServer = @{}
    $seenZoneOnly = @{}
    foreach($zone in $zoneList){
        if(-not $zone.PSObject.Properties.Match('Zone')){
            $errors.Add('Each zone entry must include a Zone property.') | Out-Null
            continue
        }
        if(-not $zone.PSObject.Properties.Match('DnsServer')){
            $errors.Add("Zone '$($zone.Zone)' is missing DnsServer.") | Out-Null
            continue
        }
        if([string]::IsNullOrWhiteSpace([string]$zone.Zone)){
            $errors.Add('Zone name cannot be empty.') | Out-Null
            continue
        }
        if([string]::IsNullOrWhiteSpace([string]$zone.DnsServer)){
            $errors.Add("DnsServer cannot be empty for zone '$($zone.Zone)'.") | Out-Null
            continue
        }

        $zoneKey = ([string]$zone.Zone).Trim().ToLowerInvariant()
        $zoneServerKey = ('{0}|{1}' -f $zoneKey, ([string]$zone.DnsServer).Trim().ToLowerInvariant())

        if($seenZoneOnly.ContainsKey($zoneKey)){
            $errors.Add("Zone '$($zone.Zone)' is defined more than once. Use a unique zone name per run or refactor the internal keys to support multiple DNS servers for the same zone.") | Out-Null
        }
        else {
            $seenZoneOnly[$zoneKey] = $true
        }

        if($seenZoneServer.ContainsKey($zoneServerKey)){
            $errors.Add("Duplicate zone/server combination detected: $($zone.Zone) / $($zone.DnsServer).") | Out-Null
        }
        else {
            $seenZoneServer[$zoneServerKey] = $true
        }
    }

    [pscustomobject]@{
        IsValid = ($errors.Count -eq 0)
        Errors  = @($errors)
    }
}

function Import-DnsAuditConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if(-not (Test-Path -LiteralPath $Path)){
        throw "Config file not found: $Path"
    }

    $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    $cfg = $raw | ConvertFrom-Json -ErrorAction Stop

    if([string]::IsNullOrWhiteSpace([string]$cfg.OutputDir)){
        Set-DnsAuditConfigValue -Config $cfg -Name 'OutputDir' -Value (Join-Path $env:USERPROFILE 'Desktop\DnsAudit')
    }
    if($null -eq $cfg.StaleDays -or [int]$cfg.StaleDays -lt 1){
        Set-DnsAuditConfigValue -Config $cfg -Name 'StaleDays' -Value 14
    }
    if($null -eq $cfg.PingTimeoutSeconds){
        Set-DnsAuditConfigValue -Config $cfg -Name 'PingTimeoutSeconds' -Value 1
    }
    if($null -eq $cfg.ProgressUpdateEvery -or [int]$cfg.ProgressUpdateEvery -lt 1){
        Set-DnsAuditConfigValue -Config $cfg -Name 'ProgressUpdateEvery' -Value 25
    }
    if([string]::IsNullOrWhiteSpace([string]$cfg.CsvDelimiter)){
        Set-DnsAuditConfigValue -Config $cfg -Name 'CsvDelimiter' -Value ';'
    }

    if($null -eq $cfg.ReportSelection){
        Set-DnsAuditConfigValue -Config $cfg -Name 'ReportSelection' -Value $script:DefaultReportSelection
    }

    return $cfg
}

function Invoke-DnsAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputDir,

        [int]$StaleDays = 14,
        [int]$PingTimeoutSeconds = 1,
        [int]$ProgressUpdateEvery = 25,
        [string]$CsvDelimiter = ';',
        [switch]$SkipCsvExport,
        [switch]$PassThru,
        [scriptblock]$ProgressCallback,

        [Parameter(Mandatory)]
        [System.Collections.IEnumerable]$ZoneMap,

        [hashtable]$ReportSelection
    )

    Write-DnsAuditLog -Level 'INFO' -Message 'Invoke-DnsAudit called' -Data @{
        OutputDir = $OutputDir
        StaleDays = $StaleDays
        PingTimeoutSeconds = $PingTimeoutSeconds
        ProgressUpdateEvery = $ProgressUpdateEvery
        CsvDelimiter = $CsvDelimiter
        SkipCsvExport = [bool]$SkipCsvExport
        PassThru = [bool]$PassThru
        ZoneCount = @($ZoneMap).Count
    }

    $validation = Test-DnsAuditInput -OutputDir $OutputDir -ZoneMap $ZoneMap -StaleDays $StaleDays -PingTimeoutSeconds $PingTimeoutSeconds
    if(-not $validation.IsValid){
        Write-DnsAuditLog -Level 'ERROR' -Message 'Input validation failed inside Invoke-DnsAudit' -Data $validation.Errors
        throw ($validation.Errors -join [Environment]::NewLine)
    }

    if(-not (Test-Path -LiteralPath $OutputDir)){
        $null = New-Item -ItemType Directory -Path $OutputDir -Force
        Write-DnsAuditLog -Level 'INFO' -Message 'Created output directory' -Data $OutputDir
    }

    $effectiveReportSelection = Merge-DnsAuditReportSelection -Selection $ReportSelection
    $zoneList = @($ZoneMap)
    $pingDisabled = ($PingTimeoutSeconds -le 0)

    $allRows = New-Object System.Collections.Generic.List[object]
    $recordErrors = New-Object System.Collections.Generic.List[object]
    $zoneErrors = New-Object System.Collections.Generic.List[object]
    $zoneSummaries = New-Object System.Collections.Generic.List[object]
    $recordsByZone = @{}
    $resultsByZone = @{}

    $ptrCache = @{}
    $aCache = @{}
    $pingCache = @{}

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $phaseTimings = [ordered]@{}

    function Publish-Progress {
        param(
            [int]$Percent = 0,
            [string]$Activity = '',
            [string]$Status = ''
        )

        if($ProgressCallback){
            & $ProgressCallback $Percent $Activity $Status
        }
    }

    Publish-Progress -Percent 0 -Activity 'Starting' -Status 'Preparing DNS audit'
    $enumSw = [System.Diagnostics.Stopwatch]::StartNew()
    $zoneCount = @($zoneList).Count
    $zoneIndex = 0
    foreach($zone in $zoneList){
        $zoneIndex++
        $enumPct = if($zoneCount -gt 0){ [int][math]::Round(($zoneIndex / $zoneCount) * 10,0) } else { 10 }
        Publish-Progress -Percent $enumPct -Activity 'Enumerating DNS records' -Status ("Zone {0}/{1}: {2}" -f $zoneIndex,$zoneCount,$zone.Zone)
        $prefix = if($zone.PSObject.Properties.Match('Prefix') -and -not [string]::IsNullOrWhiteSpace([string]$zone.Prefix)) {
            [string]$zone.Prefix
        }
        else {
            '*'
        }

        try {
            Write-DnsAuditLog -Level 'INFO' -Message 'Enumerating zone' -Data @{ Zone = $zone.Zone; DnsServer = $zone.DnsServer; Prefix = $prefix }
            $aRecords = @(Get-DnsServerResourceRecord -ComputerName $zone.DnsServer -ZoneName $zone.Zone -RRType A -ErrorAction Stop | Where-Object HostName -like $prefix)
            $cnameRecords = @(Get-DnsServerResourceRecord -ComputerName $zone.DnsServer -ZoneName $zone.Zone -RRType CNAME -ErrorAction Stop | Where-Object HostName -like $prefix)
            $recordsByZone[$zone.Zone] = @($aRecords + $cnameRecords)
            Write-DnsAuditLog -Level 'INFO' -Message 'Zone enumeration completed' -Data @{ Zone = $zone.Zone; ACount = $aRecords.Count; CNameCount = $cnameRecords.Count }
        }
        catch {
            Write-DnsAuditLog -Level 'ERROR' -Message 'Zone enumeration failed' -Data @{ Zone = $zone.Zone; DnsServer = $zone.DnsServer; Error = (Get-DnsAuditExceptionText $_) }
            $recordsByZone[$zone.Zone] = @()
            $zoneErrors.Add([pscustomobject]@{
                When      = Get-Date
                Zone      = $zone.Zone
                DnsServer = $zone.DnsServer
                Phase     = 'Enumeration'
                Message   = $_.Exception.Message
            }) | Out-Null
        }
    }
    $enumSw.Stop()
    $phaseTimings['EnumerationMs'] = [math]::Round($enumSw.Elapsed.TotalMilliseconds,2)
    Publish-Progress -Percent 10 -Activity 'Enumeration completed' -Status 'Starting record analysis'

    Write-DnsAuditLog -Level 'INFO' -Message 'Starting analysis phase' -Data @{ ZoneCount = @($zoneList).Count }
    $analysisSw = [System.Diagnostics.Stopwatch]::StartNew()
    $totalRecords = ($zoneList | ForEach-Object { @($recordsByZone[$_.Zone]).Count } | Measure-Object -Sum).Sum
    if(-not $totalRecords){ $totalRecords = 0 }
    $processed = 0

    foreach($zone in $zoneList){
        $zoneName = [string]$zone.Zone
        $dnsServer = [string]$zone.DnsServer
        $responsibility = if($zone.PSObject.Properties.Match('Responsibility') -and $zone.Responsibility) { [string]$zone.Responsibility } else { 'Unknown' }
        Write-DnsAuditLog -Level 'INFO' -Message 'Starting zone analysis' -Data @{ Zone = $zoneName; DnsServer = $dnsServer }
        $zoneRows = New-Object System.Collections.Generic.List[object]

        $duplicateCnameTargets = @{}
        $zoneCnameRecords = @($recordsByZone[$zoneName] | Where-Object RecordType -eq 'CNAME')
        foreach($group in ($zoneCnameRecords | Group-Object { $_.RecordData.HostNameAlias.ToString().TrimEnd([char[]]@([char]'.')).ToLowerInvariant() })){
            if($group.Count -gt 1){
                $duplicateCnameTargets[$group.Name] = $true
            }
        }

        foreach($record in @($recordsByZone[$zoneName])){
            $processed++
            if($ProgressUpdateEvery -gt 0 -and (($processed % $ProgressUpdateEvery) -eq 0 -or $processed -eq $totalRecords)){
                $analysisPct = if($totalRecords -gt 0){ [int][math]::Round(10 + (($processed / $totalRecords) * 75),0) } else { 85 }
                Write-Progress -Activity 'DNS audit analysis' -Status ("$processed / $totalRecords") -PercentComplete $analysisPct
                Publish-Progress -Percent $analysisPct -Activity 'Analysing DNS records' -Status ("{0}/{1} processed" -f $processed,$totalRecords)
            }

            try {
                $recordZone = $zoneName
                $hostShort = [string]$record.HostName
                $fqdn = if([string]::IsNullOrWhiteSpace($hostShort)) { $recordZone } else { '{0}.{1}' -f $hostShort, $recordZone }

                $timestampRaw = $record.TimeStamp
                $recordAgeDays = $null
                $isStale = $false
                if($timestampRaw -and $timestampRaw -ne 0){
                    try {
                        $recordAgeDays = [math]::Round((New-TimeSpan -Start $timestampRaw -End (Get-Date)).TotalDays,2)
                        $isStale = ($recordAgeDays -ge $StaleDays)
                    }
                    catch {
                        $recordAgeDays = $null
                        $isStale = $false
                    }
                }

                $ip = $null
                $cnameTarget = $null
                if($record.RecordType -eq 'A'){
                    $ip = $record.RecordData.IPv4Address.IPAddressToString
                }
                elseif($record.RecordType -eq 'CNAME'){
                    $cnameTarget = [string]$record.RecordData.HostNameAlias
                }

                $ptrAllList = @()
                $ptrStatus = 'NotApplicable'
                $ptrMismatch = $false
                if($record.RecordType -eq 'A' -and $ip){
                    $ptrKey = ('{0}|{1}' -f $dnsServer.ToLowerInvariant(), $ip)
                    if(-not $ptrCache.ContainsKey($ptrKey)){
                        try {
                            $ptrCache[$ptrKey] = @(
                                Resolve-DnsName -Type PTR -Name $ip -Server $dnsServer -ErrorAction Stop |
                                Where-Object QueryType -eq 'PTR' |
                                Select-Object -ExpandProperty NameHost
                            )
                        }
                        catch {
                            $ptrCache[$ptrKey] = @()
                        }
                    }
                    $ptrAllList = @($ptrCache[$ptrKey])
                    switch ($ptrAllList.Count) {
                        0 { $ptrStatus = 'None' }
                        1 { $ptrStatus = 'Single' }
                        default { $ptrStatus = 'Multiple' }
                    }

                    if($ptrAllList.Count -gt 0 -and $fqdn){
                        $canonFqdn = $fqdn.TrimEnd([char[]]@([char]'.')).ToLowerInvariant()
                        $ptrMismatch = -not ($ptrAllList | Where-Object { $_.TrimEnd([char[]]@([char]'.')).ToLowerInvariant() -eq $canonFqdn })
                    }
                }

                $pingStatus = 'Skipped'
                if($record.RecordType -eq 'A' -and $fqdn){
                    if($pingDisabled){
                        $pingStatus = 'Skipped'
                    }
                    else {
                        $pingKey = $fqdn.ToLowerInvariant()
                        if(-not $pingCache.ContainsKey($pingKey)){
                            $pingCache[$pingKey] = Test-DnsAuditPing -HostName $fqdn -TimeoutSeconds $PingTimeoutSeconds
                        }
                        $pingStatus = [string]$pingCache[$pingKey]
                    }
                }

                $forwardStatus = 'NotApplicable'
                $forwardIps = @()
                $forwardHasIp = $false
                if($record.RecordType -eq 'A' -and $fqdn){
                    $forwardKey = ('{0}|{1}' -f $dnsServer.ToLowerInvariant(), $fqdn.ToLowerInvariant())
                    if(-not $aCache.ContainsKey($forwardKey)){
                        try {
                            $aCache[$forwardKey] = @(
                                Resolve-DnsName -Type A -Name $fqdn -Server $dnsServer -ErrorAction Stop |
                                Where-Object QueryType -eq 'A' |
                                Select-Object -ExpandProperty IPAddress
                            )
                        }
                        catch {
                            $aCache[$forwardKey] = @()
                        }
                    }
                    $forwardIps = @($aCache[$forwardKey])
                    if($forwardIps.Count -eq 0){
                        $forwardStatus = 'NotResolved'
                    }
                    elseif($ip -and ($forwardIps -contains $ip)){
                        $forwardStatus = 'OK'
                        $forwardHasIp = $true
                    }
                    else {
                        $forwardStatus = 'Drift'
                    }
                }

                $duplicateCname = $false
                if($record.RecordType -eq 'CNAME' -and $cnameTarget){
                    $cnameKey = $cnameTarget.TrimEnd([char[]]@([char]'.')).ToLowerInvariant()
                    $duplicateCname = $duplicateCnameTargets.ContainsKey($cnameKey)
                }

                $row = [pscustomobject]@{
                    Zone               = $recordZone
                    Responsibility     = $responsibility
                    Host               = $fqdn
                    RecordType         = [string]$record.RecordType
                    IP                 = $ip
                    CNAME_Target       = $cnameTarget
                    PTR_All            = ($ptrAllList -join ',')
                    PTR_Status         = $ptrStatus
                    PingStatus         = $pingStatus
                    IsStale            = [bool]$isStale
                    RecordAgeDays      = $recordAgeDays
                    PtrMismatch        = [bool]$ptrMismatch
                    Duplicate_CNAME              = [bool]$duplicateCname
                    Multiple_Aliases_Same_Target = [bool]$duplicateCname
                    DupIP                        = $false
                    Shared_IP                    = $false
                    Forward_Status               = $forwardStatus
                    Forward_IPs        = ($forwardIps -join ',')
                    ForwardHasIP       = [bool]$forwardHasIp
                    TimeStampRaw                 = if($timestampRaw){ $timestampRaw } else { 0 }
                    Stale_Record                 = [bool]$isStale
                    Potential_Stale_Unreachable  = [bool]($isStale -and $pingStatus -eq 'Failed')
                    FindingSeverity              = ''
                    FindingCategory              = ''
                    RecommendedAction            = ''
                    WhatToCheck                  = ''
                }

                $zoneRows.Add($row) | Out-Null
                $allRows.Add($row) | Out-Null
            }
            catch {
                $recordErrors.Add([pscustomobject]@{
                    When      = Get-Date
                    Zone      = $zoneName
                    DnsServer = $dnsServer
                    Host      = $(try { [string]$record.HostName } catch { '' })
                    Type      = $(try { [string]$record.RecordType } catch { '' })
                    Message   = $_.Exception.Message
                }) | Out-Null
                if($recordErrors.Count -le 5){
                    Write-DnsAuditLog -Level 'WARN' -Message 'Record analysis error' -Data @{
                        Zone = $zoneName
                        Host = $(try { [string]$record.HostName } catch { '' })
                        Type = $(try { [string]$record.RecordType } catch { '' })
                        Message = $_.Exception.Message
                    }
                }
            }
        }

        $aRows = @($zoneRows | Where-Object { $_.RecordType -eq 'A' -and $_.IP })
        $duplicateIpSet = @{}
        foreach($group in ($aRows | Group-Object IP)){
            if($group.Count -gt 1){
                $duplicateIpSet[$group.Name] = $true
            }
        }

        foreach($row in $zoneRows){
            if($row.RecordType -eq 'A' -and $row.IP -and $duplicateIpSet.ContainsKey($row.IP)){
                $row.DupIP = $true
                $row.Shared_IP = $true
            }
            $row.Potential_Stale_Unreachable = [bool]($row.RecordType -eq 'A' -and $row.Stale_Record -and $row.PingStatus -eq 'Failed')
            $issueText = New-DnsAuditIssueText -Row $row -PingDisabled:$pingDisabled
            $row.FindingSeverity = $issueText.FindingSeverity
            $row.FindingCategory = $issueText.FindingCategory
            $row.RecommendedAction = $issueText.RecommendedAction
            $row.WhatToCheck = $issueText.WhatToCheck
        }

        $missingPtr = @($zoneRows | Where-Object { $_.RecordType -eq 'A' -and $_.PTR_Status -eq 'None' })
        $ptrMismatchRows = @($zoneRows | Where-Object { $_.PtrMismatch })
        $staleRecordRows = @($zoneRows | Where-Object { $_.RecordType -eq 'A' -and $_.Stale_Record })
        $potentialStaleUnreachableRows = @($zoneRows | Where-Object { $_.RecordType -eq 'A' -and $_.Potential_Stale_Unreachable })
        $multipleAliasRows = @($zoneRows | Where-Object { $_.RecordType -eq 'CNAME' -and $_.Multiple_Aliases_Same_Target })
        $sharedIpRows = @($zoneRows | Where-Object { $_.RecordType -eq 'A' -and $_.Shared_IP })
        $forwardDriftRows = @($zoneRows | Where-Object { $_.RecordType -eq 'A' -and $_.Forward_Status -eq 'Drift' })
        $multiplePtrRows = @($zoneRows | Where-Object { $_.RecordType -eq 'A' -and $_.PTR_Status -eq 'Multiple' })

        $zoneSummary = [pscustomobject]@{
            Zone             = $zoneName
            DnsServer        = $dnsServer
            Total            = $zoneRows.Count
            MissingPTR       = $missingPtr.Count
            PtrMismatch      = $ptrMismatchRows.Count
            StaleRecord      = $staleRecordRows.Count
            PotentialStaleUnreachable = $potentialStaleUnreachableRows.Count
            MultipleAliasesSameTarget = $multipleAliasRows.Count
            SharedIP         = $sharedIpRows.Count
            ForwardDrift     = $forwardDriftRows.Count
            PtrMultiple      = $multiplePtrRows.Count
            RecordErrors     = (@($recordErrors | Where-Object { $_.Zone -eq $zoneName })).Count
            ZoneErrors       = (@($zoneErrors | Where-Object { $_.Zone -eq $zoneName })).Count
        }
        $zoneSummaries.Add($zoneSummary) | Out-Null

        $resultsByZone[$zoneName] = @($zoneRows.ToArray())
    }

    Write-DnsAuditLog -Level 'INFO' -Message 'Analysis phase completed' -Data @{ ZoneCount = @($zoneList).Count }
    Write-Progress -Activity 'DNS audit analysis' -Completed
    $analysisSw.Stop()
    $phaseTimings['AnalysisMs'] = [math]::Round($analysisSw.Elapsed.TotalMilliseconds,2)
    Publish-Progress -Percent 85 -Activity 'Analysis completed' -Status 'Starting CSV export'

    $exportSw = [System.Diagnostics.Stopwatch]::StartNew()
    if(-not $SkipCsvExport){
        $exportZoneCount = @($zoneList).Count
        $exportZoneIndex = 0
        $csvParams = @{
            NoTypeInformation = $true
            Encoding          = 'UTF8'
            Delimiter         = $CsvDelimiter
        }

        foreach($zone in $zoneList){
            $exportZoneIndex++
            $exportPct = if($exportZoneCount -gt 0){ [int][math]::Round(85 + (($exportZoneIndex / $exportZoneCount) * 15),0) } else { 100 }
            Publish-Progress -Percent $exportPct -Activity 'Exporting CSV reports' -Status ("Zone {0}/{1}: {2}" -f $exportZoneIndex,$exportZoneCount,$zone.Zone)

            $zoneName = [string]$zone.Zone
            $zoneDir = Join-Path $OutputDir $zoneName
            if(-not (Test-Path -LiteralPath $zoneDir)){
                $null = New-Item -ItemType Directory -Path $zoneDir -Force
            }

            $zoneRows = @($resultsByZone[$zoneName])
            $missingPtr = @($zoneRows | Where-Object { $_.RecordType -eq 'A' -and $_.PTR_Status -eq 'None' })
            $ptrMismatchRows = @($zoneRows | Where-Object { $_.PtrMismatch })
            $staleRecordRows = @($zoneRows | Where-Object { $_.RecordType -eq 'A' -and $_.Stale_Record })
            $potentialStaleUnreachableRows = @($zoneRows | Where-Object { $_.RecordType -eq 'A' -and $_.Potential_Stale_Unreachable })
            $multipleAliasRows = @($zoneRows | Where-Object { $_.RecordType -eq 'CNAME' -and $_.Multiple_Aliases_Same_Target })
            $sharedIpRows = @($zoneRows | Where-Object { $_.RecordType -eq 'A' -and $_.Shared_IP })
            $forwardDriftRows = @($zoneRows | Where-Object { $_.RecordType -eq 'A' -and $_.Forward_Status -eq 'Drift' })
            $multiplePtrRows = @($zoneRows | Where-Object { $_.RecordType -eq 'A' -and $_.PTR_Status -eq 'Multiple' })

            @(
                [pscustomobject]@{ Metric = 'Zone'; Value = $zoneName },
                [pscustomobject]@{ Metric = 'DNS server'; Value = $zone.DnsServer },
                [pscustomobject]@{ Metric = 'Total analyzed'; Value = $zoneRows.Count },
                [pscustomobject]@{ Metric = 'Missing PTR'; Value = $missingPtr.Count },
                [pscustomobject]@{ Metric = 'PTR mismatch'; Value = $ptrMismatchRows.Count },
                [pscustomobject]@{ Metric = 'Stale record'; Value = $staleRecordRows.Count },
                [pscustomobject]@{ Metric = 'Potential stale + unreachable'; Value = $potentialStaleUnreachableRows.Count },
                [pscustomobject]@{ Metric = 'Multiple aliases same target'; Value = $multipleAliasRows.Count },
                [pscustomobject]@{ Metric = 'Shared IP'; Value = $sharedIpRows.Count },
                [pscustomobject]@{ Metric = 'Forward drift'; Value = $forwardDriftRows.Count },
                [pscustomobject]@{ Metric = 'Multiple PTR'; Value = $multiplePtrRows.Count }
            ) | Export-Csv -Path (Join-Path $zoneDir 'Summary.csv') @csvParams

            $zoneRows | Export-Csv -Path (Join-Path $zoneDir 'All_Records.csv') @csvParams

            if($effectiveReportSelection['Missing_PTR'])    { $missingPtr         | Export-Csv -Path (Join-Path $zoneDir 'Missing_PTR.csv') @csvParams }
            if($effectiveReportSelection['PTR_Mismatch'])   { $ptrMismatchRows    | Export-Csv -Path (Join-Path $zoneDir 'PTR_Mismatch.csv') @csvParams }
            if($effectiveReportSelection['Stale_Record'])                 { $staleRecordRows                | Export-Csv -Path (Join-Path $zoneDir 'Stale_Record.csv') @csvParams }
            if($effectiveReportSelection['Potential_Stale_Unreachable']) { $potentialStaleUnreachableRows | Export-Csv -Path (Join-Path $zoneDir 'Potential_Stale_Unreachable.csv') @csvParams }
            if($effectiveReportSelection['Multiple_Aliases_Same_Target']){ $multipleAliasRows            | Export-Csv -Path (Join-Path $zoneDir 'Multiple_Aliases_Same_Target.csv') @csvParams }
            if($effectiveReportSelection['Shared_IP'])                    { $sharedIpRows                 | Export-Csv -Path (Join-Path $zoneDir 'Shared_IP.csv') @csvParams }
            if($effectiveReportSelection['Forward_Drift'])  { $forwardDriftRows   | Export-Csv -Path (Join-Path $zoneDir 'Forward_Drift.csv') @csvParams }
            if($effectiveReportSelection['PTR_Multiple'])   { $multiplePtrRows    | Export-Csv -Path (Join-Path $zoneDir 'PTR_Multiple.csv') @csvParams }
        }

        if($recordErrors.Count -gt 0){
            $recordErrors | Export-Csv -Path (Join-Path $OutputDir 'Record_Errors.csv') @csvParams
        }
        if($zoneErrors.Count -gt 0){
            $zoneErrors | Export-Csv -Path (Join-Path $OutputDir 'Zone_Errors.csv') @csvParams
        }
        $zoneSummaries | Export-Csv -Path (Join-Path $OutputDir 'Zone_Summary.csv') @csvParams
    }
    $exportSw.Stop()
    $phaseTimings['ExportMs'] = [math]::Round($exportSw.Elapsed.TotalMilliseconds,2)
    Publish-Progress -Percent 100 -Activity 'Completed' -Status 'DNS audit finished'

    $stopwatch.Stop()
    $phaseTimings['TotalMs'] = [math]::Round($stopwatch.Elapsed.TotalMilliseconds,2)

    if($zoneSummaries -and $zoneSummaries.GetType().GetMethod('ToArray')){
        $script:LastAuditZoneSummaries = [object[]]$zoneSummaries.ToArray()
    }
    else {
        $script:LastAuditZoneSummaries = @($zoneSummaries)
    }

    if($PassThru){
        return [pscustomobject]@{
            ZoneSummaries   = @($script:LastAuditZoneSummaries)
            AllRows         = @($allRows.ToArray())
            RecordErrors    = @($recordErrors.ToArray())
            ZoneErrors      = @($zoneErrors.ToArray())
            PhaseTimings    = [pscustomobject]$phaseTimings
            OutputDir       = $OutputDir
            CsvExported     = (-not [bool]$SkipCsvExport)
            PingDisabled    = [bool]$pingDisabled
            ReportSelection = $effectiveReportSelection
        }
    }

    return
}


# ---------------- GUI ----------------

Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase,System.Windows.Forms | Out-Null

$script:LastOutputDir = $null
$script:LastZoneSummaries = @()

[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="DNS Audit Tool" Height="700" Width="860"
        MinHeight="620" MinWidth="820"
        WindowStartupLocation="CenterScreen">
  <Grid Margin="10">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <StackPanel Grid.Row="0" Orientation="Vertical">
      <TextBlock Text="DNS Audit - Configuration" FontWeight="Bold" FontSize="16" Margin="0,0,0,8"/>
      <StackPanel Orientation="Horizontal" Margin="0,0,0,4">
        <TextBlock Text="Output folder:" Width="110" VerticalAlignment="Center"/>
        <TextBox x:Name="txtOutputDir" Width="470" Margin="4,0,4,0"/>
        <Button x:Name="btnBrowse" Content="Browse..." Width="80" Margin="0,0,4,0"/>
        <Button x:Name="btnOpenOut" Content="Open" Width="60" Margin="0,0,4,0"/>
      </StackPanel>

      <StackPanel Orientation="Horizontal" Margin="0,0,0,4">
        <TextBlock Text="Stale days:" Width="110" VerticalAlignment="Center"/>
        <TextBox x:Name="txtStaleDays" Width="60" Text="14" Margin="4,0,12,0"/>
        <TextBlock Text="Ping timeout (s):" Width="130" VerticalAlignment="Center"/>
        <TextBox x:Name="txtPingTimeout" Width="60" Text="1" Margin="4,0,12,0"/>
        <CheckBox x:Name="chkQuickMode" Content="Quick mode (skip ping)" VerticalAlignment="Center" Margin="4,0,12,0"/>
        <TextBlock Text="CSV delimiter:" Width="90" VerticalAlignment="Center"/>
        <TextBox x:Name="txtDelimiter" Width="40" Text=";" Margin="4,0,0,0"/>
      </StackPanel>

      <StackPanel Orientation="Horizontal" Margin="0,0,0,4">
        <TextBlock Text="Host prefix:" Width="110" VerticalAlignment="Center"/>
        <TextBox x:Name="txtPrefix" Width="120" Text="*" Margin="4,0,12,0"/>
        <TextBlock Text="Progress update every:" Width="140" VerticalAlignment="Center"/>
        <TextBox x:Name="txtProgressUpdateEvery" Width="60" Text="25" Margin="4,0,12,0"/>
      </StackPanel>
    </StackPanel>

    <GroupBox Grid.Row="1" Header="Zones" Margin="0,8,0,4">
      <Grid Margin="4">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>

        <TextBlock Grid.Row="0" Grid.Column="0" Text="Zone 1:" VerticalAlignment="Center" Margin="0,0,4,0"/>
        <TextBox x:Name="txtZone1" Grid.Row="0" Grid.Column="1" Text="contoso.local" Margin="0,0,8,2"/>
        <TextBlock Grid.Row="0" Grid.Column="2" Text="DNS server:" VerticalAlignment="Center" Margin="0,0,4,0"/>
        <TextBox x:Name="txtDns1" Grid.Row="0" Grid.Column="3" Text="dns01.contoso.local" Margin="0,0,4,2"/>

        <TextBlock Grid.Row="1" Grid.Column="0" Text="Zone 2:" VerticalAlignment="Center" Margin="0,4,4,0"/>
        <TextBox x:Name="txtZone2" Grid.Row="1" Grid.Column="1" Text="example.local" Margin="0,4,8,0"/>
        <TextBlock Grid.Row="1" Grid.Column="2" Text="DNS server:" VerticalAlignment="Center" Margin="0,4,4,0"/>
        <TextBox x:Name="txtDns2" Grid.Row="1" Grid.Column="3" Text="dns02.example.local" Margin="0,4,4,0"/>
      </Grid>
    </GroupBox>

    <GroupBox Grid.Row="2" Header="Reports to generate" Margin="0,4,0,4">
      <WrapPanel Margin="4">
        <CheckBox x:Name="chkMissingPTR" IsChecked="True" Content="Missing PTR" Margin="0,0,14,4"/>
        <CheckBox x:Name="chkPTRMismatch" IsChecked="True" Content="PTR mismatch" Margin="0,0,14,4"/>
        <CheckBox x:Name="chkStaleRecord" IsChecked="True" Content="Stale record" Margin="0,0,14,4"/>
        <CheckBox x:Name="chkPotentialStaleUnreachable" IsChecked="True" Content="Potential stale + unreachable" Margin="0,0,14,4"/>
        <CheckBox x:Name="chkMultipleAliases" IsChecked="True" Content="Multiple aliases same target" Margin="0,0,14,4"/>
        <CheckBox x:Name="chkSharedIP" IsChecked="True" Content="Shared IP" Margin="0,0,14,4"/>
        <CheckBox x:Name="chkForwardDrift" IsChecked="True" Content="Forward drift" Margin="0,0,14,4"/>
        <CheckBox x:Name="chkPTRMultiple" IsChecked="True" Content="Multiple PTR" Margin="0,0,14,4"/>
      </WrapPanel>
    </GroupBox>

    <GroupBox Grid.Row="3" Header="Visual summary (per zone)" Margin="0,4,0,4" MinHeight="260">
      <ScrollViewer VerticalScrollBarVisibility="Auto">
        <StackPanel x:Name="spSummary" Margin="4"/>
      </ScrollViewer>
    </GroupBox>

    <StackPanel Grid.Row="4" Orientation="Vertical" Margin="0,4,0,0">
      <TextBlock x:Name="lblProgress" Text="Progress: idle."
                 Margin="0,0,0,3" Foreground="Gray"/>
      <ProgressBar x:Name="pbRunProgress" Minimum="0" Maximum="100" Height="16" Value="0"/>
    </StackPanel>

    <TextBlock Grid.Row="5" x:Name="lblStatus" Text="Last run: not executed yet."
               Margin="0,4,0,0" FontStyle="Italic" Foreground="Gray"/>

    <Grid Grid.Row="6" Margin="0,8,0,0">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>

      <TextBlock Grid.Column="0" x:Name="lblFooter" VerticalAlignment="Center"/>
      <StackPanel Grid.Column="1" Orientation="Horizontal" HorizontalAlignment="Right">
        <Button x:Name="btnRun" Content="Run audit" Width="100" Margin="0,0,8,0"/>
        <Button x:Name="btnExportSummary" Content="Export summary" Width="120" Margin="0,0,8,0" IsEnabled="False"/>
        <Button x:Name="btnClose" Content="Close" Width="80"/>
      </StackPanel>
    </Grid>
  </Grid>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)
$window.Title = "DNS Audit Tool - v$($script:AppVersion)"

$txtOutputDir = $window.FindName('txtOutputDir')
$btnBrowse = $window.FindName('btnBrowse')
$btnOpenOut = $window.FindName('btnOpenOut')
$txtStaleDays = $window.FindName('txtStaleDays')
$txtPingTimeout = $window.FindName('txtPingTimeout')
$chkQuickMode = $window.FindName('chkQuickMode')
$txtDelimiter = $window.FindName('txtDelimiter')
$txtPrefix = $window.FindName('txtPrefix')
$txtProgressUpdateEvery = $window.FindName('txtProgressUpdateEvery')
$txtZone1 = $window.FindName('txtZone1')
$txtDns1 = $window.FindName('txtDns1')
$txtZone2 = $window.FindName('txtZone2')
$txtDns2 = $window.FindName('txtDns2')
$chkMissingPTR = $window.FindName('chkMissingPTR')
$chkPTRMismatch = $window.FindName('chkPTRMismatch')
$chkStaleRecord = $window.FindName('chkStaleRecord')
$chkPotentialStaleUnreachable = $window.FindName('chkPotentialStaleUnreachable')
$chkMultipleAliases = $window.FindName('chkMultipleAliases')
$chkSharedIP = $window.FindName('chkSharedIP')
$chkForwardDrift = $window.FindName('chkForwardDrift')
$chkPTRMultiple = $window.FindName('chkPTRMultiple')
$spSummary = $window.FindName('spSummary')
$lblProgress = $window.FindName('lblProgress')
$pbRunProgress = $window.FindName('pbRunProgress')
$lblStatus = $window.FindName('lblStatus')
$lblFooter = $window.FindName('lblFooter')
$btnRun = $window.FindName('btnRun')
$btnExportSummary = $window.FindName('btnExportSummary')
$btnClose = $window.FindName('btnClose')

$txtOutputDir.Text = Join-Path $env:USERPROFILE 'Desktop\DNS_Audit_Output'
$lblFooter.Text = "Author: $($script:AppAuthor) - DNS Audit Tool v$($script:AppVersion)"

function Process-UiEvents {
    try {
        [System.Windows.Forms.Application]::DoEvents()
    }
    catch {
        Start-Sleep -Milliseconds 10
    }
}

function Update-RunProgress {
    param(
        [int]$Percent = 0,
        [string]$Activity = '',
        [string]$Status = ''
    )

    if($Percent -lt 0){ $Percent = 0 }
    if($Percent -gt 100){ $Percent = 100 }

    $pbRunProgress.Value = $Percent
    $lblProgress.Text = if([string]::IsNullOrWhiteSpace($Activity)) {
        "Progress: $Percent%"
    }
    else {
        "Progress: $Percent% - $Activity - $Status"
    }

    Process-UiEvents
}

function Reset-RunProgress {
    $pbRunProgress.Value = 0
    $lblProgress.Text = 'Progress: idle.'
    Process-UiEvents
}

function Update-SummaryUI {
    param(
        [System.Windows.Controls.StackPanel]$Panel,
        [object[]]$ZoneSummaries
    )

    $Panel.Children.Clear()
    if(-not $ZoneSummaries -or $ZoneSummaries.Count -eq 0){
        $tb = New-Object System.Windows.Controls.TextBlock
        $tb.Text = 'No summary available yet. Run an audit to see per-zone metrics here.'
        $tb.Foreground = 'Gray'
        $tb.Margin = '4,20,4,4'
        $tb.FontStyle = 'Italic'
        $tb.HorizontalAlignment = 'Center'
        $Panel.Children.Add($tb) | Out-Null
        return
    }

    foreach($summary in $ZoneSummaries){
        $total = [double]$summary.Total
        if($total -le 0){ $total = 1 }

        $gb = New-Object System.Windows.Controls.GroupBox
        $gb.Header = "{0} - total {1}" -f $summary.Zone, $summary.Total
        $gb.Margin = '0,0,0,6'

        $stack = New-Object System.Windows.Controls.StackPanel
        $stack.Margin = '4'

        $metrics = @(
            @{ Label='Missing PTR'; Key='MissingPTR' },
            @{ Label='PTR mismatch'; Key='PtrMismatch' },
            @{ Label='Stale record'; Key='StaleRecord' },
            @{ Label='Potential stale + unreachable'; Key='PotentialStaleUnreachable' },
            @{ Label='Multiple aliases same target'; Key='MultipleAliasesSameTarget' },
            @{ Label='Shared IP'; Key='SharedIP' },
            @{ Label='Forward drift'; Key='ForwardDrift' },
            @{ Label='Multiple PTR'; Key='PtrMultiple' }
        )

        foreach($metric in $metrics){
            $count = [double]$summary.($metric.Key)
            if($count -lt 0){ $count = 0 }
            $pct = [math]::Round(($count / $total) * 100,1)

            $dock = New-Object System.Windows.Controls.DockPanel
            $dock.Margin = '0,0,0,2'

            $label = New-Object System.Windows.Controls.TextBlock
            $label.Text = "{0}: {1} ({2}%)" -f $metric.Label, [int]$count, $pct
            $label.Width = 210
            [System.Windows.Controls.DockPanel]::SetDock($label,'Left')
            $dock.Children.Add($label) | Out-Null

            $bar = New-Object System.Windows.Controls.ProgressBar
            $bar.Minimum = 0
            $bar.Maximum = 100
            $bar.Value = $pct
            $bar.Height = 14
            $bar.Margin = '4,0,0,0'
            $dock.Children.Add($bar) | Out-Null

            $stack.Children.Add($dock) | Out-Null
        }

        $meta = New-Object System.Windows.Controls.TextBlock
        $meta.Text = "DNS server: {0} | record errors: {1} | zone errors: {2}" -f $summary.DnsServer, $summary.RecordErrors, $summary.ZoneErrors
        $meta.Foreground = 'Gray'
        $meta.Margin = '0,4,0,0'
        $stack.Children.Add($meta) | Out-Null

        $gb.Content = $stack
        $Panel.Children.Add($gb) | Out-Null
    }
}

function Get-UiZoneMap {
    $zoneMap = New-Object System.Collections.Generic.List[object]

    if(-not [string]::IsNullOrWhiteSpace($txtZone1.Text) -and -not [string]::IsNullOrWhiteSpace($txtDns1.Text)){
        $zoneMap.Add([pscustomobject]@{
            Zone = $txtZone1.Text.Trim()
            DnsServer = $txtDns1.Text.Trim()
            Responsibility = 'Zone 1'
            Prefix = if([string]::IsNullOrWhiteSpace($txtPrefix.Text)) { '*' } else { $txtPrefix.Text.Trim() }
        }) | Out-Null
    }

    if(-not [string]::IsNullOrWhiteSpace($txtZone2.Text) -and -not [string]::IsNullOrWhiteSpace($txtDns2.Text)){
        $zoneMap.Add([pscustomobject]@{
            Zone = $txtZone2.Text.Trim()
            DnsServer = $txtDns2.Text.Trim()
            Responsibility = 'Zone 2'
            Prefix = if([string]::IsNullOrWhiteSpace($txtPrefix.Text)) { '*' } else { $txtPrefix.Text.Trim() }
        }) | Out-Null
    }

    $zoneMap
}

function Set-UiBusyState {
    param([bool]$IsBusy)
    $window.Cursor = if($IsBusy){ 'Wait' } else { 'Arrow' }
    $btnRun.IsEnabled = -not $IsBusy
    $btnClose.IsEnabled = -not $IsBusy
    if($IsBusy){
        $btnExportSummary.IsEnabled = $false
    }
    else {
        $btnClose.IsEnabled = $true
    }
    Process-UiEvents
}

Update-SummaryUI -Panel $spSummary -ZoneSummaries @()
Reset-RunProgress

$btnBrowse.Add_Click({
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.Description = 'Select the output folder for CSV files'
    $dialog.SelectedPath = $txtOutputDir.Text
    if($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK){
        $txtOutputDir.Text = $dialog.SelectedPath
    }
})

$btnOpenOut.Add_Click({
    if(-not [string]::IsNullOrWhiteSpace($txtOutputDir.Text) -and (Test-Path -LiteralPath $txtOutputDir.Text)){
        Start-Process -FilePath $txtOutputDir.Text
    }
    else {
        [System.Windows.MessageBox]::Show('The output folder does not exist yet.','Output folder','OK','Warning') | Out-Null
    }
})

$btnRun.Add_Click({
    try {
        $null = Initialize-DnsAuditLog -OutputDir $txtOutputDir.Text
        Write-DnsAuditLog -Level 'INFO' -Message 'Run audit button clicked'
        Write-DnsAuditLog -Level 'INFO' -Message 'GUI raw values' -Data @{
            OutputDir = $txtOutputDir.Text
            StaleDays = $txtStaleDays.Text
            PingTimeout = $txtPingTimeout.Text
            QuickMode = [bool]$chkQuickMode.IsChecked
            StaleRecord = [bool]$chkStaleRecord.IsChecked
            PotentialStaleUnreachable = [bool]$chkPotentialStaleUnreachable.IsChecked
            MultipleAliases = [bool]$chkMultipleAliases.IsChecked
            SharedIP = [bool]$chkSharedIP.IsChecked
            Delimiter = $txtDelimiter.Text
            Prefix = $txtPrefix.Text
            ProgressUpdateEvery = $txtProgressUpdateEvery.Text
            Zone1 = $txtZone1.Text
            Dns1 = $txtDns1.Text
            Zone2 = $txtZone2.Text
            Dns2 = $txtDns2.Text
        }

        $staleDays = 14
        [void][int]::TryParse($txtStaleDays.Text,[ref]$staleDays)
        if($staleDays -lt 1){ $staleDays = 14 }
        Write-DnsAuditLog -Level 'INFO' -Message 'Parsed staleDays' -Data $staleDays

        $pingTimeout = 1
        [void][int]::TryParse($txtPingTimeout.Text,[ref]$pingTimeout)
        if($pingTimeout -lt 0){ $pingTimeout = 1 }
        if([bool]$chkQuickMode.IsChecked){ $pingTimeout = 0 }
        Write-DnsAuditLog -Level 'INFO' -Message 'Parsed pingTimeout' -Data $pingTimeout

        $progressUpdateEvery = 25
        [void][int]::TryParse($txtProgressUpdateEvery.Text,[ref]$progressUpdateEvery)
        if($progressUpdateEvery -lt 1){ $progressUpdateEvery = 25 }
        Write-DnsAuditLog -Level 'INFO' -Message 'Parsed progressUpdateEvery' -Data $progressUpdateEvery

        $zoneMap = Get-UiZoneMap
        Write-DnsAuditLog -Level 'INFO' -Message 'Built zoneMap' -Data @($zoneMap)
        $validation = Test-DnsAuditInput -OutputDir $txtOutputDir.Text -ZoneMap $zoneMap -StaleDays $staleDays -PingTimeoutSeconds $pingTimeout
        Write-DnsAuditLog -Level 'INFO' -Message 'Validation result' -Data $validation
        if(-not $validation.IsValid){
            [System.Windows.MessageBox]::Show(($validation.Errors -join [Environment]::NewLine),'Validation','OK','Warning') | Out-Null
            return
        }

        $reports = @{
            Missing_PTR     = [bool]$chkMissingPTR.IsChecked
            PTR_Mismatch    = [bool]$chkPTRMismatch.IsChecked
            Stale_Record                 = [bool]$chkStaleRecord.IsChecked
            Potential_Stale_Unreachable  = [bool]$chkPotentialStaleUnreachable.IsChecked
            Multiple_Aliases_Same_Target = [bool]$chkMultipleAliases.IsChecked
            Shared_IP                    = [bool]$chkSharedIP.IsChecked
            Forward_Drift                = [bool]$chkForwardDrift.IsChecked
            PTR_Multiple                 = [bool]$chkPTRMultiple.IsChecked
        }

        Write-DnsAuditLog -Level 'INFO' -Message 'Report selection built' -Data $reports

        $payload = [pscustomobject]@{
            OutputDir = $txtOutputDir.Text
            StaleDays = $staleDays
            PingTimeoutSeconds = $pingTimeout
            ProgressUpdateEvery = $progressUpdateEvery
            CsvDelimiter = if([string]::IsNullOrWhiteSpace($txtDelimiter.Text)) { ';' } else { $txtDelimiter.Text.Substring(0,1) }
            ZoneMap = @($zoneMap)
            ReportSelection = $reports
        }

        Write-DnsAuditLog -Level 'INFO' -Message 'Payload prepared' -Data $payload
        Set-UiBusyState -IsBusy $true
        Reset-RunProgress
        $modeText = if([bool]$chkQuickMode.IsChecked){ 'quick' } else { 'full' }
        $lblStatus.Text = "Running audit in $modeText mode..."
        Update-RunProgress -Percent 0 -Activity 'Starting' -Status "Mode: $modeText"

        $progressCallback = {
            param($percent, $activity, $status)
            Update-RunProgress -Percent $percent -Activity $activity -Status $status
        }

        Write-DnsAuditLog -Level 'INFO' -Message 'Calling Invoke-DnsAudit'
        $null = Invoke-DnsAudit `
            -OutputDir $payload.OutputDir `
            -StaleDays $payload.StaleDays `
            -PingTimeoutSeconds $payload.PingTimeoutSeconds `
            -ProgressUpdateEvery $payload.ProgressUpdateEvery `
            -CsvDelimiter $payload.CsvDelimiter `
            -ZoneMap $payload.ZoneMap `
            -ReportSelection $payload.ReportSelection `
            -ProgressCallback $progressCallback `
            -PassThru

        $zoneSummaries = @($script:LastAuditZoneSummaries)
        $script:LastZoneSummaries = $zoneSummaries
        $script:LastOutputDir = $payload.OutputDir

        Write-DnsAuditLog -Level 'INFO' -Message 'Invoke-DnsAudit completed successfully'
        Update-RunProgress -Percent 100 -Activity 'Completed' -Status 'Refreshing summary'
        Update-SummaryUI -Panel $spSummary -ZoneSummaries $zoneSummaries
        Set-UiBusyState -IsBusy $false
        $btnExportSummary.IsEnabled = ($zoneSummaries.Count -gt 0)
        $lblStatus.Text = "Last run OK ($(Get-Date -Format 'yyyy-MM-dd HH:mm')) - mode: $modeText - output: $($payload.OutputDir)"
        Write-DnsAuditLog -Level 'INFO' -Message 'Run completed successfully' -Data @{ OutputDir = $payload.OutputDir; LogPath = $script:LogPath; ZoneSummaryCount = $zoneSummaries.Count }
        [System.Windows.MessageBox]::Show("DNS audit completed.`nOutput folder:`n$($payload.OutputDir)`n`nDebug log:`n$($script:LogPath)",'Completed','OK','Information') | Out-Null
    }
    catch {
        $errText = Get-DnsAuditExceptionText $_
        Write-DnsAuditLog -Level 'ERROR' -Message 'Run audit failed' -Data @{
            Error = $errText
            ScriptStackTrace = $_.ScriptStackTrace
            PositionMessage = $_.InvocationInfo.PositionMessage
            LogPath = $script:LogPath
        }
        Set-UiBusyState -IsBusy $false
        Update-RunProgress -Percent 0 -Activity 'Failed' -Status $errText
        $lblStatus.Text = "Last run failed: $(Get-Date -Format 'yyyy-MM-dd HH:mm') - $errText"
        [System.Windows.MessageBox]::Show("Error preparing DNS audit:`n$errText`n`nDebug log:`n$($script:LogPath)",'Error','OK','Error') | Out-Null
    }
})

$btnExportSummary.Add_Click({
    if((@($script:LastZoneSummaries).Count -eq 0) -or [string]::IsNullOrWhiteSpace($script:LastOutputDir)){
        [System.Windows.MessageBox]::Show('No summary is available yet.','Export summary','OK','Warning') | Out-Null
        return
    }

    try {
        Write-DnsAuditLog -Level 'INFO' -Message 'Export summary clicked'
        $path = Join-Path $script:LastOutputDir ('Zone_Summary_{0}.csv' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
        @($script:LastZoneSummaries) | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        [System.Windows.MessageBox]::Show("Summary exported to:`n$path",'Export summary','OK','Information') | Out-Null
    }
    catch {
        [System.Windows.MessageBox]::Show("Error exporting summary:`n$($_.Exception.Message)",'Export summary','OK','Error') | Out-Null
    }
})

$btnClose.Add_Click({ $window.Close() })
$window.ShowDialog() | Out-Null
