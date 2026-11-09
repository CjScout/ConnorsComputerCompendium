<#
.SYNOPSIS
  Collects everything needed to troubleshoot Ansible -> WinRM (Kerberos) access to this PC.

.USAGE
  Run in an elevated PowerShell on the target PC, right AFTER a failed win_ping:
    powershell -ExecutionPolicy Bypass -File .\Get-AnsibleWinRMDiag.ps1
  Optional live test as the service account (prompts for its password, then
  connects back to this PC over WinRM and records the exact error):
    powershell -ExecutionPolicy Bypass -File .\Get-AnsibleWinRMDiag.ps1 -TestLogon

  Output: C:\Temp\winrm-diag-<COMPUTER>-<timestamp>.txt
#>
param(
    [string]$ServiceAccount = 'ansible-svc',
    [string]$ControlServerIP = '192.168.30.16',
    [switch]$TestLogon
)

$ErrorActionPreference = 'Continue'
$outDir = 'C:\Temp'
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
$outFile = Join-Path $outDir ("winrm-diag-{0}-{1}.txt" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss'))

function Section {
    param([string]$Title, [scriptblock]$Body)
    $header = "`r`n" + ('=' * 90) + "`r`n== $Title`r`n" + ('=' * 90)
    Add-Content -Path $outFile -Value $header
    try {
        $result = & $Body 2>&1 | Out-String -Width 300
        if ([string]::IsNullOrWhiteSpace($result)) { $result = '(no output)' }
    } catch {
        $result = "ERROR: $($_.Exception.Message)"
    }
    Add-Content -Path $outFile -Value $result.TrimEnd()
    Write-Host "  done: $Title"
}

Write-Host "Writing diagnostics to $outFile"

# ---------------------------------------------------------------- basics
Section 'System / domain' {
    $cs = Get-CimInstance Win32_ComputerSystem
    $os = Get-CimInstance Win32_OperatingSystem
    [pscustomobject]@{
        Computer   = $env:COMPUTERNAME
        Domain     = $cs.Domain
        PartOfDomain = $cs.PartOfDomain
        OS         = "$($os.Caption) $($os.Version) build $($os.BuildNumber)"
        LastBoot   = $os.LastBootUpTime
        RunAs      = whoami
        Collected  = Get-Date
    } | Format-List
}

Section 'Secure channel to domain' { Test-ComputerSecureChannel -Verbose 4>&1 }

Section 'Network: IPs, gateway, DNS servers' {
    Get-NetIPConfiguration | Format-List InterfaceAlias, IPv4Address, IPv4DefaultGateway, DNSServer
}

Section 'Network profile (must be DomainAuthenticated for the Domain firewall profile)' {
    Get-NetConnectionProfile | Format-Table InterfaceAlias, Name, NetworkCategory, IPv4Connectivity -AutoSize
}

Section 'DNS: my own record as the DC sees it' {
    $fqdn = ([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME)).HostName
    "FQDN: $fqdn"
    Resolve-DnsName $fqdn -Type A -DnsOnly | Format-Table Name, IPAddress, TTL -AutoSize
}

Section 'Time sync (Kerberos needs < 5 min skew)' {
    w32tm /query /status
    $dc = (nltest /dsgetdc: 2>$null | Select-String 'DC: \\\\(.+)').Matches.Groups[1].Value
    if ($dc) { "`r`nOffset vs $dc :"; w32tm /stripchart /computer:$dc /samples:1 /dataonly }
}

# ---------------------------------------------------------------- group policy
Section 'Applied computer GPOs' { gpresult /r /scope computer }

# ---------------------------------------------------------------- WinRM service
Section 'WinRM service state' { Get-Service WinRM | Format-List Name, Status, StartType }

Section 'WinRM listeners' { winrm enumerate winrm/config/listener }

Section 'WinRM service config (look at RootSDDL, AllowUnencrypted, Auth, IPv4Filter)' {
    winrm get winrm/config/service
}

Section 'WinRM local self-test' { Test-WSMan -ComputerName localhost -Authentication Default }

Section 'WinRM / WinRS policy registry (GPO-set values)' {
    foreach ($p in 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service',
                   'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS',
                   'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client') {
        "[$p]"
        if (Test-Path $p) { Get-ItemProperty $p | Select-Object * -ExcludeProperty PS* | Format-List }
        else { '  (not set)' }
    }
}

Section 'PowerShell remoting endpoint permissions' {
    Get-PSSessionConfiguration | Format-Table Name, Permission -Wrap -AutoSize
}

Section 'Listening on 5985/5986?' {
    Get-NetTCPConnection -State Listen -LocalPort 5985, 5986 -ErrorAction SilentlyContinue |
        Format-Table LocalAddress, LocalPort, OwningProcess -AutoSize
}

# ---------------------------------------------------------------- firewall
Section 'Firewall profiles' {
    Get-NetFirewallProfile -PolicyStore ActiveStore |
        Format-Table Name, Enabled, DefaultInboundAction, AllowLocalFirewallRules -AutoSize
}

Section 'Inbound firewall rules for WinRM / port 5985 (local + GPO merged)' {
    Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound |
        ForEach-Object {
            $pf = $_ | Get-NetFirewallPortFilter
            if ($_.DisplayGroup -match 'Remote Management' -or $pf.LocalPort -contains '5985') {
                $af = $_ | Get-NetFirewallAddressFilter
                [pscustomobject]@{
                    Name = $_.DisplayName; Enabled = $_.Enabled; Action = $_.Action
                    Profile = $_.Profile; Port = ($pf.LocalPort -join ',')
                    RemoteAddress = ($af.RemoteAddress -join ','); Source = $_.PolicyStoreSourceType
                }
            }
        } | Format-Table -AutoSize -Wrap
}

# ---------------------------------------------------------------- accounts & rights
Section 'Local Administrators members' { net localgroup Administrators }
Section 'Local Remote Management Users members' { net localgroup "Remote Management Users" }

Section 'User rights: network logon allow/deny, batch, service (SIDs resolved)' {
    $cfg = Join-Path $env:TEMP 'ur-diag.cfg'
    secedit /export /cfg $cfg /areas USER_RIGHTS | Out-Null
    Get-Content $cfg | Where-Object { $_ -match '^(SeNetworkLogonRight|SeDenyNetworkLogonRight|SeDenyInteractiveLogonRight|SeBatchLogonRight|SeDenyBatchLogonRight|SeRemoteInteractiveLogonRight)' } |
        ForEach-Object {
            $name, $vals = $_ -split '\s*=\s*', 2
            $resolved = foreach ($v in $vals -split ',') {
                $v = $v.Trim().TrimStart('*')
                try { (New-Object System.Security.Principal.SecurityIdentifier $v).Translate([System.Security.Principal.NTAccount]).Value }
                catch { $v }
            }
            "{0} = {1}" -f $name, ($resolved -join '; ')
        }
    Remove-Item $cfg -ErrorAction SilentlyContinue
}

Section 'UAC / token filtering policy' {
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' |
        Select-Object EnableLUA, LocalAccountTokenFilterPolicy, FilterAdministratorToken, ConsentPromptBehaviorAdmin | Format-List
}

Section "AD: $ServiceAccount account (via LDAP, no RSAT needed)" {
    $s = [adsisearcher]"(sAMAccountName=$ServiceAccount)"
    'samaccountname','userprincipalname','useraccountcontrol','userworkstations','memberof',
        'pwdlastset','lockouttime','badpwdcount','accountexpires','msds-supportedencryptiontypes' |
        ForEach-Object { [void]$s.PropertiesToLoad.Add($_) }
    $u = $s.FindOne()
    if (-not $u) { "Account '$ServiceAccount' NOT FOUND in AD"; return }
    $p = $u.Properties
    $uac = [int]$p['useraccountcontrol'][0]
    [pscustomobject]@{
        sAMAccountName   = $p['samaccountname'][0]
        UPN              = $p['userprincipalname'][0]
        Disabled         = [bool]($uac -band 0x2)
        LockedOut        = ($p['lockouttime'] -and [int64]$p['lockouttime'][0] -gt 0)
        NotDelegated     = [bool]($uac -band 0x100000)
        PwdNeverExpires  = [bool]($uac -band 0x10000)
        LogonWorkstations = if ($p['userworkstations']) { $p['userworkstations'][0] } else { '(any)' }
        BadPwdCount      = $p['badpwdcount'][0]
        PwdLastSet       = [datetime]::FromFileTime([int64]$p['pwdlastset'][0])
        EncTypes         = $p['msds-supportedencryptiontypes'][0]
    } | Format-List
    'MemberOf:'
    $p['memberof'] | ForEach-Object { "  $_" }
    if ($p['memberof'] -match 'CN=Protected Users') { '!! Account is in Protected Users' }
}

Section 'AD: this computer account SPNs (needs HTTP/ or HOST/ for Kerberos)' {
    $c = ([adsisearcher]"(sAMAccountName=$env:COMPUTERNAME`$)").FindOne()
    if ($c) { $c.Properties['serviceprincipalname'] } else { 'computer account not found' }
}

# ---------------------------------------------------------------- logs
Section 'WinRM Operational log - last 40 warnings/errors' {
    Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -MaxEvents 400 -ErrorAction SilentlyContinue |
        Where-Object { $_.LevelDisplayName -ne 'Information' } | Select-Object -First 40 |
        Format-List TimeCreated, Id, LevelDisplayName, Message
}

Section 'Security 4625 (failed logons) - last 5, full text' {
    Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625 } -MaxEvents 5 -ErrorAction SilentlyContinue |
        Format-List TimeCreated, Message
}

Section "Security 4624/4634 for $ServiceAccount - last 5 (did the logon itself succeed?)" {
    Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624 } -MaxEvents 500 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match [regex]::Escape($ServiceAccount) } | Select-Object -First 5 |
        Format-List TimeCreated, Message
}

Section 'System log: Kerberos / KDC / time errors - last 15' {
    Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Security-Kerberos', 'Microsoft-Windows-Time-Service', 'NETLOGON' } -MaxEvents 15 -ErrorAction SilentlyContinue |
        Format-List TimeCreated, Id, ProviderName, Message
}

Section 'Kerberos tickets on this PC (SYSTEM)' { klist -li 0x3e7 }

# ---------------------------------------------------------------- optional live test
if ($TestLogon) {
    Section "LIVE TEST: WinRM to $env:COMPUTERNAME as $ServiceAccount (Kerberos)" {
        $fqdn = ([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME)).HostName
        $cred = Get-Credential -Message "Password for $ServiceAccount" -UserName "$env:USERDOMAIN\$ServiceAccount"
        try {
            Invoke-Command -ComputerName $fqdn -Credential $cred -Authentication Kerberos -ScriptBlock {
                "SUCCESS - connected as: $(whoami)"
                whoami /groups | Select-String 'Administrators|Mandatory Label'
            } -ErrorAction Stop
        } catch {
            "FAILED: $($_.Exception.Message)"
            "FullyQualifiedErrorId: $($_.FullyQualifiedErrorId)"
        }
    }
}

Write-Host "`r`nDone. Send this file: $outFile" -ForegroundColor Green
