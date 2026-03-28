<#
.SYNOPSIS
    Audits Defender for Office 365 Safe Links policies for Microsoft Teams URL scanning coverage.

.DESCRIPTION
    This script connects to Exchange Online and retrieves all Safe Links policies, reporting
    on whether Teams message URL scanning is enabled for each policy. It highlights any policies
    where EnableSafeLinksForTeams is set to False, which represents a security gap allowing
    unscanned URLs to be delivered to users via Microsoft Teams messages.

    Teams-based phishing attacks are an increasing threat vector. Attackers can send messages
    from external federated tenants using spoofed display names and malicious URLs. Safe Links
    coverage for Teams is a critical control to mitigate this risk, but custom policies created
    before the Teams Safe Links feature existed may have it disabled by default.

.PARAMETER ExportPath
    Optional. Full file path to export the results as a CSV file.
    Example: -ExportPath "C:\Reports\SafeLinksAudit.csv"

.EXAMPLE
    .\Audit-TeamseSafeLinksPolicy.ps1
    Connects to Exchange Online and displays Safe Links policy Teams coverage in the console.

.EXAMPLE
    .\Audit-TeamsSafeLinksPolicy.ps1 -ExportPath "C:\Reports\SafeLinksAudit.csv"
    Connects to Exchange Online, displays results, and exports them to the specified CSV file.

.NOTES
    Author       : Security Automation Team
    Version      : 1.0.0
    Requirements : ExchangeOnlineManagement PowerShell module
                   Permissions: Security Administrator or Global Administrator role in Microsoft 365

    Install the required module if not already present:
        Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, HelpMessage = "Optional file path to export results as CSV.")]
    [string]$ExportPath
)

#region Functions

function Test-ExchangeOnlineConnection {
    <#
    .SYNOPSIS
        Checks whether an active Exchange Online session exists.
    #>
    try {
        $null = Get-OrganizationConfig -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Connect-ToExchangeOnline {
    <#
    .SYNOPSIS
        Connects to Exchange Online if not already connected.
    #>
    if (-not (Test-ExchangeOnlineConnection)) {
        Write-Host "[INFO] Connecting to Exchange Online..." -ForegroundColor Cyan
        try {
            Connect-ExchangeOnline -ErrorAction Stop
            Write-Host "[INFO] Successfully connected to Exchange Online." -ForegroundColor Green
        }
        catch {
            Write-Error "[ERROR] Failed to connect to Exchange Online: $_"
            exit 1
        }
    }
    else {
        Write-Host "[INFO] Already connected to Exchange Online." -ForegroundColor Green
    }
}

function Get-SafeLinksPolicyAudit {
    <#
    .SYNOPSIS
        Retrieves all Safe Links policies and evaluates Teams URL scanning coverage.
    .OUTPUTS
        PSCustomObject array containing policy details and a Teams coverage status flag.
    #>
    Write-Host "`n[INFO] Retrieving Safe Links policies..." -ForegroundColor Cyan

    try {
        $policies = Get-SafeLinksPolicy -ErrorAction Stop
    }
    catch {
        Write-Error "[ERROR] Failed to retrieve Safe Links policies: $_"
        return $null
    }

    if (-not $policies) {
        Write-Warning "[WARN] No Safe Links policies were found in this tenant."
        return $null
    }

    $auditResults = foreach ($policy in $policies) {
        # Determine a human-readable coverage status
        $teamsStatus = if ($policy.EnableSafeLinksForTeams -eq $true) {
            "ENABLED"
        }
        else {
            "DISABLED -- ACTION REQUIRED"
        }

        [PSCustomObject]@{
            PolicyName                = $policy.Name
            IsEnabled                 = $policy.IsEnabled
            EnableSafeLinksForTeams   = $policy.EnableSafeLinksForTeams
            TeamsCoverageStatus       = $teamsStatus
            EnableForInternalSenders  = $policy.EnableForInternalSenders
            TrackClicks               = $policy.TrackClicks
            AllowClickThrough         = $policy.AllowClickThrough
            WhenCreated               = $policy.WhenCreated
            WhenChanged               = $policy.WhenChanged
        }
    }

    return $auditResults
}

function Show-AuditSummary {
    <#
    .SYNOPSIS
        Displays a formatted summary of the Safe Links audit results.
    .PARAMETER AuditResults
        The collection of policy audit objects to display.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$AuditResults
    )

    Write-Host "`n===== SAFE LINKS TEAMS COVERAGE AUDIT RESULTS =====" -ForegroundColor Yellow
    $AuditResults | Format-Table -AutoSize -Property PolicyName, IsEnabled, EnableSafeLinksForTeams, TeamsCoverageStatus, TrackClicks, AllowClickThrough

    $gapPolicies = $AuditResults | Where-Object { $_.EnableSafeLinksForTeams -eq $false }

    if ($gapPolicies) {
        Write-Host "`n[WARNING] The following policies have Teams Safe Links scanning DISABLED:" -ForegroundColor Red
        foreach ($gap in $gapPolicies) {
            Write-Host "  - $($gap.PolicyName)" -ForegroundColor Red
        }
        Write-Host "`n[ACTION REQUIRED] Update these policies to enable Teams URL scanning." -ForegroundColor Red
        Write-Host "  Use: Set-SafeLinksPolicy -Identity '<PolicyName>' -EnableSafeLinksForTeams `$true" -ForegroundColor Yellow
    }
    else {
        Write-Host "`n[OK] All Safe Links policies have Teams URL scanning enabled." -ForegroundColor Green
    }

    Write-Host "`n===== SUMMARY =====" -ForegroundColor Yellow
    Write-Host "Total Policies Evaluated : $($AuditResults.Count)"
    Write-Host "Policies with Teams Gap  : $($gapPolicies.Count)" -ForegroundColor $(if ($gapPolicies.Count -gt 0) { 'Red' } else { 'Green' })
}

function Export-AuditResults {
    <#
    .SYNOPSIS
        Exports the audit results to a CSV file.
    .PARAMETER AuditResults
        The collection of policy audit objects to export.
    .PARAMETER FilePath
        The destination file path for the CSV export.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$AuditResults,

        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    try {
        $AuditResults | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Host "`n[INFO] Audit results exported to: $FilePath" -ForegroundColor Green
    }
    catch {
        Write-Error "[ERROR] Failed to export results to CSV: $_"
    }
}

#endregion Functions

#region Main Execution

# Ensure the ExchangeOnlineManagement module is available
if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Write-Error "[ERROR] The 'ExchangeOnlineManagement' module is not installed. Run: Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force"
    exit 1
}

# Connect to Exchange Online
Connect-ToExchangeOnline

# Retrieve and audit Safe Links policies
$auditResults = Get-SafeLinksPolicyAudit

if ($auditResults) {
    # Display results in the console
    Show-AuditSummary -AuditResults $auditResults

    # Export to CSV if a path was provided
    if ($PSBoundParameters.ContainsKey('ExportPath') -and -not [string]::IsNullOrWhiteSpace($ExportPath)) {
        Export-AuditResults -AuditResults $auditResults -FilePath $ExportPath
    }
}
else {
    Write-Warning "[WARN] No audit results to display."
}

#endregion Main Execution
