#Requires -Version 5.0
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    SCCM Agent Diagnostic and Repair Tool

.DESCRIPTION
    This script performs comprehensive diagnostics on the SCCM (Configuration Manager)
    client agent, displays results, and offers repair options.

.NOTES
    - Requires PowerShell 5.0 or later (NOT PowerShell 7)
    - Must be run as Administrator
    - No external modules required
    - Auto-discovers SCCM server

.AUTHOR
    Generated for SCCM Agent Repair Project
#>

# ============================================================================
# GLOBAL VARIABLES
# ============================================================================
$Script:DiagnosticResults = @{}
$Script:SCCMServerInfo = @{}
$Script:ErrorLog = @()

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White",
        [switch]$NoNewLine
    )

    if ($NoNewLine) {
        Write-Host $Message -ForegroundColor $Color -NoNewline
    } else {
        Write-Host $Message -ForegroundColor $Color
    }
}

function Write-Header {
    param([string]$Title)

    $line = "=" * 70
    Write-Host ""
    Write-ColorOutput $line "Cyan"
    Write-ColorOutput "  $Title" "Cyan"
    Write-ColorOutput $line "Cyan"
    Write-Host ""
}

function Write-SubHeader {
    param([string]$Title)

    Write-Host ""
    Write-ColorOutput "--- $Title ---" "Yellow"
    Write-Host ""
}

function Write-TestResult {
    param(
        [string]$TestName,
        [string]$Status,
        [string]$Details = ""
    )

    $statusColor = switch ($Status) {
        "PASS"    { "Green" }
        "FAIL"    { "Red" }
        "WARNING" { "Yellow" }
        "INFO"    { "Cyan" }
        default   { "White" }
    }

    Write-ColorOutput "  [$Status]" $statusColor -NoNewLine
    Write-Host " $TestName"

    if ($Details) {
        Write-Host "         $Details" -ForegroundColor Gray
    }
}

function Test-AdminPrivileges {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Add-ToErrorLog {
    param([string]$Message)
    $Script:ErrorLog += "[$(Get-Date -Format 'HH:mm:ss')] $Message"
}

# ============================================================================
# SCCM SERVER DISCOVERY FUNCTIONS
# ============================================================================

function Get-SCCMServerFromRegistry {
    <#
    .SYNOPSIS
        Attempts to discover SCCM server from registry settings
    #>

    $serverInfo = @{
        ManagementPoint = $null
        SiteCode = $null
        AssignedSite = $null
    }

    try {
        # Check CCM registry path
        $ccmRegPath = "HKLM:\SOFTWARE\Microsoft\CCM"

        if (Test-Path $ccmRegPath) {
            # Get assigned site
            $assignedSite = Get-ItemProperty -Path $ccmRegPath -Name "AssignedSiteCode" -ErrorAction SilentlyContinue
            if ($assignedSite) {
                $serverInfo.AssignedSite = $assignedSite.AssignedSiteCode
                $serverInfo.SiteCode = $assignedSite.AssignedSiteCode
            }
        }

        # Check for Management Point in registry
        $mpRegPath = "HKLM:\SOFTWARE\Microsoft\CCM\LocationServices"
        if (Test-Path $mpRegPath) {
            # Try to get current MP
            $mp = Get-ItemProperty -Path $mpRegPath -ErrorAction SilentlyContinue
            if ($mp.ManagementPoint) {
                $serverInfo.ManagementPoint = $mp.ManagementPoint
            }
        }

    } catch {
        Add-ToErrorLog "Registry discovery error: $($_.Exception.Message)"
    }

    return $serverInfo
}

function Get-SCCMServerFromWMI {
    <#
    .SYNOPSIS
        Attempts to discover SCCM server from WMI classes
    #>

    $serverInfo = @{
        ManagementPoint = $null
        SiteCode = $null
        Authority = $null
    }

    try {
        # Get SMS_Authority for site assignment
        $authority = Get-WmiObject -Namespace "root\ccm" -Class "SMS_Authority" -ErrorAction SilentlyContinue
        if ($authority) {
            $serverInfo.Authority = $authority.Name
            if ($authority.CurrentManagementPoint) {
                $serverInfo.ManagementPoint = $authority.CurrentManagementPoint
            }
            # Extract site code from authority name (format: SMS:SITECODE)
            if ($authority.Name -match "SMS:(\w+)") {
                $serverInfo.SiteCode = $Matches[1]
            }
        }

        # Alternative: Get from SMS_Client
        $smsClient = Get-WmiObject -Namespace "root\ccm" -Class "SMS_Client" -ErrorAction SilentlyContinue
        if ($smsClient -and -not $serverInfo.SiteCode) {
            # Try to get site code another way
            $localMP = Get-WmiObject -Namespace "root\ccm" -Class "SMS_LocalMP" -ErrorAction SilentlyContinue
            if ($localMP) {
                $serverInfo.ManagementPoint = $localMP.MPHostName
            }
        }

    } catch {
        Add-ToErrorLog "WMI discovery error: $($_.Exception.Message)"
    }

    return $serverInfo
}

function Get-SCCMServerFromAD {
    <#
    .SYNOPSIS
        Attempts to discover SCCM server from Active Directory
    #>

    $serverInfo = @{
        ManagementPoint = $null
        SiteCode = $null
    }

    try {
        # Use ADSI to search for SCCM Management Point in AD
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $domainDN = "DC=" + ($domain.Name -replace "\.", ",DC=")

        # Search for SMS container in System
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"LDAP://CN=System,$domainDN"
        $searcher.Filter = "(&(objectClass=mSSMSManagementPoint))"
        $searcher.PropertiesToLoad.Add("mSSMSMPName") | Out-Null
        $searcher.PropertiesToLoad.Add("mSSMSSiteCode") | Out-Null

        $results = $searcher.FindAll()

        if ($results.Count -gt 0) {
            $mp = $results[0]
            $serverInfo.ManagementPoint = $mp.Properties["mssmsmpname"][0]
            $serverInfo.SiteCode = $mp.Properties["mssmssitecode"][0]
        }

    } catch {
        # AD discovery might fail if not domain joined or no permissions
        Add-ToErrorLog "AD discovery not available: $($_.Exception.Message)"
    }

    return $serverInfo
}

function Discover-SCCMServer {
    <#
    .SYNOPSIS
        Main function to auto-discover SCCM server using multiple methods
    #>

    Write-SubHeader "Auto-Discovering SCCM Server"

    $discoveredInfo = @{
        ManagementPoint = $null
        SiteCode = $null
        DiscoveryMethod = $null
    }

    # Method 1: Try WMI first (most reliable if client is installed)
    Write-Host "  Checking WMI..." -NoNewline
    $wmiInfo = Get-SCCMServerFromWMI
    if ($wmiInfo.ManagementPoint) {
        $discoveredInfo.ManagementPoint = $wmiInfo.ManagementPoint
        $discoveredInfo.SiteCode = $wmiInfo.SiteCode
        $discoveredInfo.DiscoveryMethod = "WMI"
        Write-ColorOutput " Found!" "Green"
    } else {
        Write-ColorOutput " Not found" "Yellow"
    }

    # Method 2: Try Registry
    if (-not $discoveredInfo.ManagementPoint) {
        Write-Host "  Checking Registry..." -NoNewline
        $regInfo = Get-SCCMServerFromRegistry
        if ($regInfo.ManagementPoint -or $regInfo.AssignedSite) {
            $discoveredInfo.ManagementPoint = $regInfo.ManagementPoint
            $discoveredInfo.SiteCode = $regInfo.SiteCode ?? $regInfo.AssignedSite
            $discoveredInfo.DiscoveryMethod = "Registry"
            Write-ColorOutput " Found!" "Green"
        } else {
            Write-ColorOutput " Not found" "Yellow"
        }
    }

    # Method 3: Try Active Directory
    if (-not $discoveredInfo.ManagementPoint) {
        Write-Host "  Checking Active Directory..." -NoNewline
        $adInfo = Get-SCCMServerFromAD
        if ($adInfo.ManagementPoint) {
            $discoveredInfo.ManagementPoint = $adInfo.ManagementPoint
            $discoveredInfo.SiteCode = $adInfo.SiteCode
            $discoveredInfo.DiscoveryMethod = "Active Directory"
            Write-ColorOutput " Found!" "Green"
        } else {
            Write-ColorOutput " Not found" "Yellow"
        }
    }

    # Display results
    Write-Host ""
    if ($discoveredInfo.ManagementPoint) {
        Write-TestResult "Management Point" "PASS" $discoveredInfo.ManagementPoint
        Write-TestResult "Site Code" "INFO" $discoveredInfo.SiteCode
        Write-TestResult "Discovery Method" "INFO" $discoveredInfo.DiscoveryMethod
    } else {
        Write-TestResult "SCCM Server Discovery" "WARNING" "Could not auto-discover SCCM server"
    }

    $Script:SCCMServerInfo = $discoveredInfo
    return $discoveredInfo
}

# ============================================================================
# DIAGNOSTIC TEST FUNCTIONS
# ============================================================================

function Test-SCCMClientInstalled {
    <#
    .SYNOPSIS
        Checks if SCCM client is installed
    #>

    $result = @{
        Installed = $false
        Version = $null
        InstallPath = $null
    }

    try {
        # Check if CCM folder exists
        $ccmPath = "$env:windir\CCM"
        if (Test-Path $ccmPath) {
            $result.InstallPath = $ccmPath

            # Get version from ccmexec.exe
            $ccmExec = "$ccmPath\ccmexec.exe"
            if (Test-Path $ccmExec) {
                $fileInfo = Get-Item $ccmExec
                $result.Version = $fileInfo.VersionInfo.FileVersion
                $result.Installed = $true
            }
        }

        # Also check WMI
        $smsClient = Get-WmiObject -Namespace "root\ccm" -Class "SMS_Client" -ErrorAction SilentlyContinue
        if ($smsClient) {
            $result.Installed = $true
            if (-not $result.Version) {
                $result.Version = $smsClient.ClientVersion
            }
        }

    } catch {
        Add-ToErrorLog "Client installation check error: $($_.Exception.Message)"
    }

    return $result
}

function Test-SCCMServices {
    <#
    .SYNOPSIS
        Checks the status of SCCM-related services
    #>

    $services = @(
        @{ Name = "CcmExec"; DisplayName = "SMS Agent Host"; Critical = $true },
        @{ Name = "smstsmgr"; DisplayName = "ConfigMgr Task Sequence Agent"; Critical = $false },
        @{ Name = "BITS"; DisplayName = "Background Intelligent Transfer Service"; Critical = $true },
        @{ Name = "wuauserv"; DisplayName = "Windows Update"; Critical = $true },
        @{ Name = "Winmgmt"; DisplayName = "Windows Management Instrumentation"; Critical = $true }
    )

    $results = @()

    foreach ($svc in $services) {
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue

        $svcResult = @{
            Name = $svc.Name
            DisplayName = $svc.DisplayName
            Status = if ($service) { $service.Status.ToString() } else { "Not Found" }
            StartType = if ($service) { $service.StartType.ToString() } else { "N/A" }
            Critical = $svc.Critical
            Healthy = $false
        }

        if ($service -and $service.Status -eq "Running") {
            $svcResult.Healthy = $true
        } elseif (-not $svc.Critical -and $service) {
            # Non-critical services can be stopped
            $svcResult.Healthy = $true
        }

        $results += $svcResult
    }

    return $results
}

function Test-WMIRepository {
    <#
    .SYNOPSIS
        Checks the health of WMI repository and SCCM namespaces
    #>

    $results = @{
        WMIHealthy = $false
        SCCMNamespaceExists = $false
        Namespaces = @()
        Errors = @()
    }

    try {
        # Test basic WMI connectivity
        $wmiTest = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        if ($wmiTest) {
            $results.WMIHealthy = $true
        }

        # Check SCCM namespaces
        $sccmNamespaces = @(
            "root\ccm",
            "root\ccm\ClientSDK",
            "root\ccm\Policy",
            "root\ccm\SoftMgmtAgent",
            "root\cimv2\sms"
        )

        foreach ($ns in $sccmNamespaces) {
            try {
                $testQuery = Get-WmiObject -Namespace $ns -Class "__NAMESPACE" -ErrorAction Stop
                $results.Namespaces += @{ Namespace = $ns; Exists = $true }
            } catch {
                $results.Namespaces += @{ Namespace = $ns; Exists = $false }
                $results.Errors += "Namespace '$ns' not accessible"
            }
        }

        # Check if main CCM namespace exists
        $ccmNs = $results.Namespaces | Where-Object { $_.Namespace -eq "root\ccm" }
        if ($ccmNs -and $ccmNs.Exists) {
            $results.SCCMNamespaceExists = $true
        }

    } catch {
        $results.Errors += "WMI test failed: $($_.Exception.Message)"
        Add-ToErrorLog "WMI Repository check error: $($_.Exception.Message)"
    }

    return $results
}

function Test-SCCMCommunication {
    <#
    .SYNOPSIS
        Tests communication with the SCCM Management Point
    #>

    $results = @{
        CanReachMP = $false
        MPUrl = $null
        LastPolicyRequest = $null
        LastHWInventory = $null
        LastSWInventory = $null
        Errors = @()
    }

    try {
        # Get Management Point URL
        $mp = Get-WmiObject -Namespace "root\ccm" -Class "SMS_Authority" -ErrorAction SilentlyContinue
        if ($mp -and $mp.CurrentManagementPoint) {
            $results.MPUrl = $mp.CurrentManagementPoint

            # Test connectivity to MP
            $mpHost = $mp.CurrentManagementPoint -replace "https?://", "" -replace "/.*", ""
            $pingResult = Test-Connection -ComputerName $mpHost -Count 1 -Quiet -ErrorAction SilentlyContinue
            $results.CanReachMP = $pingResult

            # Also try TCP connection on 80/443
            if (-not $results.CanReachMP) {
                try {
                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                    $tcpClient.Connect($mpHost, 443)
                    $results.CanReachMP = $tcpClient.Connected
                    $tcpClient.Close()
                } catch {
                    try {
                        $tcpClient = New-Object System.Net.Sockets.TcpClient
                        $tcpClient.Connect($mpHost, 80)
                        $results.CanReachMP = $tcpClient.Connected
                        $tcpClient.Close()
                    } catch {
                        $results.CanReachMP = $false
                    }
                }
            }
        }

        # Get last policy request time
        try {
            $policyAgent = Get-WmiObject -Namespace "root\ccm\Policy\Machine" -Query "SELECT * FROM CCM_PolicyAgent_Configuration" -ErrorAction SilentlyContinue
            if ($policyAgent) {
                $results.LastPolicyRequest = "Policy agent configured"
            }
        } catch { }

        # Get last hardware inventory
        try {
            $hwInv = Get-WmiObject -Namespace "root\ccm\InvAgt" -Class "InventoryActionStatus" -ErrorAction SilentlyContinue |
                     Where-Object { $_.InventoryActionID -eq "{00000000-0000-0000-0000-000000000001}" }
            if ($hwInv -and $hwInv.LastCycleStartedDate) {
                $lastHW = [Management.ManagementDateTimeConverter]::ToDateTime($hwInv.LastCycleStartedDate)
                $results.LastHWInventory = $lastHW.ToString("yyyy-MM-dd HH:mm:ss")
            }
        } catch { }

        # Get last software inventory
        try {
            $swInv = Get-WmiObject -Namespace "root\ccm\InvAgt" -Class "InventoryActionStatus" -ErrorAction SilentlyContinue |
                     Where-Object { $_.InventoryActionID -eq "{00000000-0000-0000-0000-000000000002}" }
            if ($swInv -and $swInv.LastCycleStartedDate) {
                $lastSW = [Management.ManagementDateTimeConverter]::ToDateTime($swInv.LastCycleStartedDate)
                $results.LastSWInventory = $lastSW.ToString("yyyy-MM-dd HH:mm:ss")
            }
        } catch { }

    } catch {
        $results.Errors += $_.Exception.Message
        Add-ToErrorLog "Communication test error: $($_.Exception.Message)"
    }

    return $results
}

function Test-SCCMClientHealth {
    <#
    .SYNOPSIS
        Checks SCCM client health status using built-in health evaluation
    #>

    $results = @{
        HealthEvaluationEnabled = $false
        LastHealthEvaluation = $null
        HealthResult = $null
        ClientActive = $false
        Errors = @()
    }

    try {
        # Check if client is active
        $smsClient = Get-WmiObject -Namespace "root\ccm" -Class "SMS_Client" -ErrorAction SilentlyContinue
        if ($smsClient) {
            $results.ClientActive = $true
        }

        # Check CCMEval results
        $evalResultPath = "$env:windir\CCM\CcmEvalReport.xml"
        if (Test-Path $evalResultPath) {
            $results.HealthEvaluationEnabled = $true

            try {
                [xml]$evalReport = Get-Content $evalResultPath -ErrorAction Stop
                $results.LastHealthEvaluation = $evalReport.ClientHealthReport.ReportTime

                # Check for any failures
                $failures = $evalReport.ClientHealthReport.HealthChecks.HealthCheck | Where-Object { $_.Result -eq "Fail" }
                if ($failures) {
                    $results.HealthResult = "Issues Found"
                    foreach ($fail in $failures) {
                        $results.Errors += "$($fail.Description): $($fail.ResultDetail)"
                    }
                } else {
                    $results.HealthResult = "Healthy"
                }
            } catch {
                $results.HealthResult = "Could not parse health report"
            }
        }

        # Alternative: Check registry for health status
        $healthRegPath = "HKLM:\SOFTWARE\Microsoft\CCM\CcmEval"
        if (Test-Path $healthRegPath) {
            $healthReg = Get-ItemProperty -Path $healthRegPath -ErrorAction SilentlyContinue
            if ($healthReg.LastEvalTime) {
                $results.LastHealthEvaluation = $healthReg.LastEvalTime
            }
        }

    } catch {
        $results.Errors += $_.Exception.Message
        Add-ToErrorLog "Health check error: $($_.Exception.Message)"
    }

    return $results
}

function Test-SCCMCache {
    <#
    .SYNOPSIS
        Checks SCCM client cache status and size
    #>

    $results = @{
        CacheEnabled = $false
        CachePath = $null
        CacheSize = 0
        CacheUsed = 0
        CacheItems = 0
        Errors = @()
    }

    try {
        # Get cache info from WMI
        $cacheConfig = Get-WmiObject -Namespace "root\ccm\SoftMgmtAgent" -Class "CacheConfig" -ErrorAction SilentlyContinue
        if ($cacheConfig) {
            $results.CacheEnabled = $true
            $results.CachePath = $cacheConfig.Location
            $results.CacheSize = [math]::Round($cacheConfig.Size, 2)
        }

        # Get cache items
        $cacheItems = Get-WmiObject -Namespace "root\ccm\SoftMgmtAgent" -Class "CacheInfoEx" -ErrorAction SilentlyContinue
        if ($cacheItems) {
            $results.CacheItems = ($cacheItems | Measure-Object).Count
            $totalSize = ($cacheItems | Measure-Object -Property ContentSize -Sum).Sum
            $results.CacheUsed = [math]::Round($totalSize / 1024, 2)  # Convert to MB
        }

        # Check cache folder
        $defaultCachePath = "$env:windir\ccmcache"
        if (Test-Path $defaultCachePath) {
            $results.CachePath = $defaultCachePath
            $results.CacheEnabled = $true
        }

    } catch {
        $results.Errors += $_.Exception.Message
        Add-ToErrorLog "Cache check error: $($_.Exception.Message)"
    }

    return $results
}

function Test-SCCMCertificates {
    <#
    .SYNOPSIS
        Checks SCCM client certificates
    #>

    $results = @{
        HasClientCert = $false
        CertSubject = $null
        CertExpiry = $null
        CertValid = $false
        Errors = @()
    }

    try {
        # Check for SCCM client certificate in SMS store
        $smsCerts = Get-ChildItem -Path "Cert:\LocalMachine\SMS" -ErrorAction SilentlyContinue
        if ($smsCerts) {
            $clientCert = $smsCerts | Where-Object { $_.Subject -like "*SMS*" -or $_.Subject -like "*CCM*" } | Select-Object -First 1

            if (-not $clientCert) {
                $clientCert = $smsCerts | Select-Object -First 1
            }

            if ($clientCert) {
                $results.HasClientCert = $true
                $results.CertSubject = $clientCert.Subject
                $results.CertExpiry = $clientCert.NotAfter.ToString("yyyy-MM-dd HH:mm:ss")
                $results.CertValid = ($clientCert.NotAfter -gt (Get-Date))
            }
        }

        # Also check Personal store for client auth certs
        if (-not $results.HasClientCert) {
            $personalCerts = Get-ChildItem -Path "Cert:\LocalMachine\My" -ErrorAction SilentlyContinue
            $sccmCert = $personalCerts | Where-Object {
                $_.EnhancedKeyUsageList.FriendlyName -contains "Client Authentication" -and
                ($_.Subject -like "*$env:COMPUTERNAME*")
            } | Select-Object -First 1

            if ($sccmCert) {
                $results.HasClientCert = $true
                $results.CertSubject = $sccmCert.Subject
                $results.CertExpiry = $sccmCert.NotAfter.ToString("yyyy-MM-dd HH:mm:ss")
                $results.CertValid = ($sccmCert.NotAfter -gt (Get-Date))
            }
        }

    } catch {
        $results.Errors += $_.Exception.Message
        Add-ToErrorLog "Certificate check error: $($_.Exception.Message)"
    }

    return $results
}

function Test-SCCMPolicies {
    <#
    .SYNOPSIS
        Checks SCCM policy status
    #>

    $results = @{
        MachinePolicy = $false
        UserPolicy = $false
        PolicyCount = 0
        Errors = @()
    }

    try {
        # Check machine policies
        $machinePolicies = Get-WmiObject -Namespace "root\ccm\Policy\Machine\ActualConfig" -Class "CCM_ComponentClientConfig" -ErrorAction SilentlyContinue
        if ($machinePolicies) {
            $results.MachinePolicy = $true
            $results.PolicyCount = ($machinePolicies | Measure-Object).Count
        }

        # Check if policy namespace has content
        $policyTest = Get-WmiObject -Namespace "root\ccm\Policy" -Class "__Namespace" -ErrorAction SilentlyContinue
        if ($policyTest) {
            $results.MachinePolicy = $true
        }

    } catch {
        $results.Errors += $_.Exception.Message
        Add-ToErrorLog "Policy check error: $($_.Exception.Message)"
    }

    return $results
}

function Test-SCCMLogging {
    <#
    .SYNOPSIS
        Checks SCCM client log files and looks for recent errors
    #>

    $results = @{
        LogPath = $null
        LogFilesExist = $false
        RecentErrors = @()
        CriticalLogs = @()
    }

    try {
        $logPath = "$env:windir\CCM\Logs"
        $results.LogPath = $logPath

        if (Test-Path $logPath) {
            $results.LogFilesExist = $true

            # Critical log files to check
            $criticalLogs = @(
                "CcmExec.log",
                "ClientLocation.log",
                "PolicyAgent.log",
                "StatusAgent.log",
                "DataTransferService.log"
            )

            foreach ($logName in $criticalLogs) {
                $logFile = Join-Path $logPath $logName
                if (Test-Path $logFile) {
                    $fileInfo = Get-Item $logFile
                    $results.CriticalLogs += @{
                        Name = $logName
                        Exists = $true
                        LastModified = $fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                        SizeKB = [math]::Round($fileInfo.Length / 1024, 2)
                    }

                    # Check for recent errors (last 50 lines)
                    try {
                        $content = Get-Content $logFile -Tail 50 -ErrorAction SilentlyContinue
                        $errors = $content | Select-String -Pattern "error|fail|exception" -AllMatches
                        if ($errors) {
                            $results.RecentErrors += @{
                                LogFile = $logName
                                ErrorCount = $errors.Count
                            }
                        }
                    } catch { }
                } else {
                    $results.CriticalLogs += @{
                        Name = $logName
                        Exists = $false
                        LastModified = $null
                        SizeKB = 0
                    }
                }
            }
        }

    } catch {
        Add-ToErrorLog "Log check error: $($_.Exception.Message)"
    }

    return $results
}

# ============================================================================
# MAIN DIAGNOSTIC FUNCTION
# ============================================================================

function Run-AllDiagnostics {
    <#
    .SYNOPSIS
        Runs all diagnostic tests and stores results
    #>

    Write-Header "SCCM Agent Diagnostic Tool"
    Write-Host "  Computer: $env:COMPUTERNAME"
    Write-Host "  User: $env:USERNAME"
    Write-Host "  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

    # Discover SCCM Server
    $serverInfo = Discover-SCCMServer

    # Run all tests
    Write-SubHeader "Checking SCCM Client Installation"
    $clientInstall = Test-SCCMClientInstalled
    if ($clientInstall.Installed) {
        Write-TestResult "SCCM Client Installed" "PASS" "Version: $($clientInstall.Version)"
        Write-TestResult "Install Path" "INFO" $clientInstall.InstallPath
    } else {
        Write-TestResult "SCCM Client Installed" "FAIL" "Client not found on this system"
    }
    $Script:DiagnosticResults.ClientInstall = $clientInstall

    # Services
    Write-SubHeader "Checking SCCM Services"
    $services = Test-SCCMServices
    foreach ($svc in $services) {
        $status = if ($svc.Healthy) { "PASS" } else { "FAIL" }
        Write-TestResult "$($svc.DisplayName) ($($svc.Name))" $status "Status: $($svc.Status), StartType: $($svc.StartType)"
    }
    $Script:DiagnosticResults.Services = $services

    # WMI Repository
    Write-SubHeader "Checking WMI Repository"
    $wmi = Test-WMIRepository
    if ($wmi.WMIHealthy) {
        Write-TestResult "WMI Repository" "PASS" "Core WMI is functional"
    } else {
        Write-TestResult "WMI Repository" "FAIL" "WMI has issues"
    }

    if ($wmi.SCCMNamespaceExists) {
        Write-TestResult "SCCM WMI Namespace" "PASS" "root\ccm is accessible"
    } else {
        Write-TestResult "SCCM WMI Namespace" "FAIL" "root\ccm is not accessible"
    }

    $accessibleNs = ($wmi.Namespaces | Where-Object { $_.Exists }).Count
    $totalNs = $wmi.Namespaces.Count
    Write-TestResult "SCCM Namespaces" "INFO" "$accessibleNs of $totalNs namespaces accessible"
    $Script:DiagnosticResults.WMI = $wmi

    # Communication
    Write-SubHeader "Checking SCCM Communication"
    $comm = Test-SCCMCommunication
    if ($comm.MPUrl) {
        Write-TestResult "Management Point" "INFO" $comm.MPUrl
        if ($comm.CanReachMP) {
            Write-TestResult "MP Connectivity" "PASS" "Management Point is reachable"
        } else {
            Write-TestResult "MP Connectivity" "FAIL" "Cannot reach Management Point"
        }
    } else {
        Write-TestResult "Management Point" "WARNING" "Not configured or not found"
    }

    if ($comm.LastHWInventory) {
        Write-TestResult "Last Hardware Inventory" "INFO" $comm.LastHWInventory
    }
    if ($comm.LastSWInventory) {
        Write-TestResult "Last Software Inventory" "INFO" $comm.LastSWInventory
    }
    $Script:DiagnosticResults.Communication = $comm

    # Client Health
    Write-SubHeader "Checking Client Health"
    $health = Test-SCCMClientHealth
    if ($health.ClientActive) {
        Write-TestResult "Client Active" "PASS" "SMS_Client is responsive"
    } else {
        Write-TestResult "Client Active" "FAIL" "SMS_Client not responding"
    }

    if ($health.HealthEvaluationEnabled) {
        Write-TestResult "Health Evaluation" "INFO" "Enabled"
        if ($health.HealthResult -eq "Healthy") {
            Write-TestResult "Health Status" "PASS" $health.HealthResult
        } else {
            Write-TestResult "Health Status" "WARNING" $health.HealthResult
        }
    }
    $Script:DiagnosticResults.Health = $health

    # Cache
    Write-SubHeader "Checking Client Cache"
    $cache = Test-SCCMCache
    if ($cache.CacheEnabled) {
        Write-TestResult "Cache Status" "PASS" "Cache is enabled"
        Write-TestResult "Cache Path" "INFO" $cache.CachePath
        Write-TestResult "Cache Size" "INFO" "Configured: $($cache.CacheSize) MB, Used: $($cache.CacheUsed) MB"
        Write-TestResult "Cached Items" "INFO" "$($cache.CacheItems) items"
    } else {
        Write-TestResult "Cache Status" "WARNING" "Cache not configured or not accessible"
    }
    $Script:DiagnosticResults.Cache = $cache

    # Certificates
    Write-SubHeader "Checking Certificates"
    $certs = Test-SCCMCertificates
    if ($certs.HasClientCert) {
        if ($certs.CertValid) {
            Write-TestResult "Client Certificate" "PASS" "Valid certificate found"
        } else {
            Write-TestResult "Client Certificate" "FAIL" "Certificate expired!"
        }
        Write-TestResult "Certificate Subject" "INFO" $certs.CertSubject
        Write-TestResult "Certificate Expiry" "INFO" $certs.CertExpiry
    } else {
        Write-TestResult "Client Certificate" "WARNING" "No client certificate found"
    }
    $Script:DiagnosticResults.Certificates = $certs

    # Policies
    Write-SubHeader "Checking Policies"
    $policies = Test-SCCMPolicies
    if ($policies.MachinePolicy) {
        Write-TestResult "Machine Policies" "PASS" "$($policies.PolicyCount) policies found"
    } else {
        Write-TestResult "Machine Policies" "FAIL" "No machine policies found"
    }
    $Script:DiagnosticResults.Policies = $policies

    # Logging
    Write-SubHeader "Checking Log Files"
    $logs = Test-SCCMLogging
    if ($logs.LogFilesExist) {
        Write-TestResult "Log Directory" "PASS" $logs.LogPath

        $existingLogs = ($logs.CriticalLogs | Where-Object { $_.Exists }).Count
        $totalLogs = $logs.CriticalLogs.Count
        Write-TestResult "Critical Log Files" "INFO" "$existingLogs of $totalLogs present"

        if ($logs.RecentErrors.Count -gt 0) {
            $totalErrors = ($logs.RecentErrors | Measure-Object -Property ErrorCount -Sum).Sum
            Write-TestResult "Recent Errors in Logs" "WARNING" "$totalErrors errors found in recent logs"
        } else {
            Write-TestResult "Recent Errors in Logs" "PASS" "No recent errors detected"
        }
    } else {
        Write-TestResult "Log Directory" "FAIL" "Log directory not found"
    }
    $Script:DiagnosticResults.Logging = $logs

    # Summary
    Write-Header "Diagnostic Summary"

    $passCount = 0
    $failCount = 0
    $warningCount = 0

    # Calculate summary
    if ($clientInstall.Installed) { $passCount++ } else { $failCount++ }
    $failCount += ($services | Where-Object { -not $_.Healthy -and $_.Critical }).Count
    $passCount += ($services | Where-Object { $_.Healthy }).Count
    if ($wmi.WMIHealthy) { $passCount++ } else { $failCount++ }
    if ($wmi.SCCMNamespaceExists) { $passCount++ } else { $failCount++ }
    if ($comm.CanReachMP) { $passCount++ } elseif ($comm.MPUrl) { $failCount++ } else { $warningCount++ }
    if ($health.ClientActive) { $passCount++ } else { $failCount++ }
    if ($cache.CacheEnabled) { $passCount++ } else { $warningCount++ }
    if ($certs.HasClientCert -and $certs.CertValid) { $passCount++ }
    elseif ($certs.HasClientCert) { $failCount++ }
    else { $warningCount++ }
    if ($policies.MachinePolicy) { $passCount++ } else { $failCount++ }

    Write-ColorOutput "  Passed:   $passCount" "Green"
    Write-ColorOutput "  Failed:   $failCount" "Red"
    Write-ColorOutput "  Warnings: $warningCount" "Yellow"
    Write-Host ""

    if ($failCount -gt 0) {
        Write-ColorOutput "  RECOMMENDATION: Repair is recommended to fix detected issues." "Yellow"
    } elseif ($warningCount -gt 0) {
        Write-ColorOutput "  RECOMMENDATION: Self-check repair may help resolve warnings." "Yellow"
    } else {
        Write-ColorOutput "  SCCM Agent appears to be healthy!" "Green"
    }

    return @{
        Pass = $passCount
        Fail = $failCount
        Warning = $warningCount
    }
}

# ============================================================================
# REPAIR FUNCTIONS
# ============================================================================

function Repair-SelfCheckAndFix {
    <#
    .SYNOPSIS
        Performs targeted repairs based on diagnostic results
    #>

    Write-Header "Self-Check and Fix Repair"
    Write-Host "  This will attempt to fix detected issues without reinstalling the client."
    Write-Host ""

    $repairsMade = 0

    # Fix 1: Restart stopped critical services
    Write-SubHeader "Checking and Starting Services"
    $criticalServices = @("CcmExec", "BITS", "wuauserv", "Winmgmt")

    foreach ($svcName in $criticalServices) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            if ($svc.Status -ne "Running") {
                Write-Host "  Starting $svcName..." -NoNewline
                try {
                    Start-Service -Name $svcName -ErrorAction Stop
                    Start-Sleep -Seconds 2
                    $svc.Refresh()
                    if ($svc.Status -eq "Running") {
                        Write-ColorOutput " Started!" "Green"
                        $repairsMade++
                    } else {
                        Write-ColorOutput " Failed to start" "Red"
                    }
                } catch {
                    Write-ColorOutput " Error: $($_.Exception.Message)" "Red"
                }
            } else {
                Write-Host "  $svcName is already running" -ForegroundColor Gray
            }
        }
    }

    # Fix 2: Reset WMI repository if issues detected
    if ($Script:DiagnosticResults.WMI -and -not $Script:DiagnosticResults.WMI.WMIHealthy) {
        Write-SubHeader "Repairing WMI Repository"
        Write-Host "  Attempting WMI repository repair..."

        try {
            # Stop WMI service
            Stop-Service -Name Winmgmt -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2

            # Register WMI components
            $wmiPath = "$env:windir\System32\wbem"
            Push-Location $wmiPath

            & "$wmiPath\mofcomp.exe" "$wmiPath\cimwin32.mof" | Out-Null
            & "$wmiPath\mofcomp.exe" "$wmiPath\cimwin32.mfl" | Out-Null

            Pop-Location

            # Restart WMI
            Start-Service -Name Winmgmt -ErrorAction Stop
            Write-ColorOutput "  WMI repair attempted" "Green"
            $repairsMade++
        } catch {
            Write-ColorOutput "  WMI repair failed: $($_.Exception.Message)" "Red"
        }
    }

    # Fix 3: Trigger machine policy refresh
    Write-SubHeader "Refreshing Machine Policies"
    try {
        Write-Host "  Triggering Machine Policy Retrieval..." -NoNewline
        $null = Invoke-WmiMethod -Namespace "root\ccm" -Class "SMS_Client" -Name "TriggerSchedule" -ArgumentList "{00000000-0000-0000-0000-000000000021}" -ErrorAction Stop
        Write-ColorOutput " Triggered!" "Green"
        $repairsMade++
    } catch {
        Write-ColorOutput " Failed: $($_.Exception.Message)" "Yellow"
    }

    try {
        Write-Host "  Triggering Machine Policy Evaluation..." -NoNewline
        $null = Invoke-WmiMethod -Namespace "root\ccm" -Class "SMS_Client" -Name "TriggerSchedule" -ArgumentList "{00000000-0000-0000-0000-000000000022}" -ErrorAction Stop
        Write-ColorOutput " Triggered!" "Green"
        $repairsMade++
    } catch {
        Write-ColorOutput " Failed: $($_.Exception.Message)" "Yellow"
    }

    # Fix 4: Trigger hardware inventory
    Write-SubHeader "Triggering Inventory Cycles"
    try {
        Write-Host "  Triggering Hardware Inventory..." -NoNewline
        $null = Invoke-WmiMethod -Namespace "root\ccm" -Class "SMS_Client" -Name "TriggerSchedule" -ArgumentList "{00000000-0000-0000-0000-000000000001}" -ErrorAction Stop
        Write-ColorOutput " Triggered!" "Green"
        $repairsMade++
    } catch {
        Write-ColorOutput " Failed: $($_.Exception.Message)" "Yellow"
    }

    try {
        Write-Host "  Triggering Software Inventory..." -NoNewline
        $null = Invoke-WmiMethod -Namespace "root\ccm" -Class "SMS_Client" -Name "TriggerSchedule" -ArgumentList "{00000000-0000-0000-0000-000000000002}" -ErrorAction Stop
        Write-ColorOutput " Triggered!" "Green"
        $repairsMade++
    } catch {
        Write-ColorOutput " Failed: $($_.Exception.Message)" "Yellow"
    }

    # Fix 5: Run CCMEval if available
    Write-SubHeader "Running Client Health Evaluation"
    $ccmEvalPath = "$env:windir\CCM\CcmEval.exe"
    if (Test-Path $ccmEvalPath) {
        Write-Host "  Running CcmEval.exe..." -NoNewline
        try {
            Start-Process -FilePath $ccmEvalPath -ArgumentList "/noreboot" -Wait -NoNewWindow
            Write-ColorOutput " Completed!" "Green"
            $repairsMade++
        } catch {
            Write-ColorOutput " Failed: $($_.Exception.Message)" "Red"
        }
    } else {
        Write-Host "  CcmEval.exe not found, skipping..." -ForegroundColor Gray
    }

    # Fix 6: Clear and rebuild policy if no policies found
    if ($Script:DiagnosticResults.Policies -and -not $Script:DiagnosticResults.Policies.MachinePolicy) {
        Write-SubHeader "Resetting Policy Store"
        Write-Host "  Attempting policy store reset..."

        try {
            # Delete policy files
            $policyPath = "$env:windir\CCM\Policy"
            if (Test-Path $policyPath) {
                Stop-Service -Name CcmExec -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2

                # Remove policy files
                Get-ChildItem -Path $policyPath -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue

                # Restart service
                Start-Service -Name CcmExec -ErrorAction Stop
                Start-Sleep -Seconds 5

                # Trigger policy download
                Invoke-WmiMethod -Namespace "root\ccm" -Class "SMS_Client" -Name "TriggerSchedule" -ArgumentList "{00000000-0000-0000-0000-000000000021}" -ErrorAction SilentlyContinue

                Write-ColorOutput "  Policy store reset completed" "Green"
                $repairsMade++
            }
        } catch {
            Write-ColorOutput "  Policy reset failed: $($_.Exception.Message)" "Red"
            # Make sure service is started
            Start-Service -Name CcmExec -ErrorAction SilentlyContinue
        }
    }

    # Summary
    Write-Header "Self-Check Repair Complete"
    Write-Host "  Repairs attempted: $repairsMade"
    Write-Host ""
    Write-ColorOutput "  Please wait a few minutes for changes to take effect." "Yellow"
    Write-ColorOutput "  Run diagnostics again to verify repairs." "Cyan"
}

function Repair-CompleteReinstall {
    <#
    .SYNOPSIS
        Performs complete SCCM client repair/reinstall
    #>

    Write-Header "Complete SCCM Agent Repair"
    Write-Host ""
    Write-ColorOutput "  WARNING: This will completely uninstall and reinstall the SCCM client." "Yellow"
    Write-ColorOutput "  This process may take several minutes." "Yellow"
    Write-Host ""

    # Confirm
    $confirm = Read-Host "  Are you sure you want to proceed? (Y/N)"
    if ($confirm -notmatch "^[Yy]") {
        Write-Host "  Repair cancelled."
        return
    }

    Write-Host ""

    # Step 1: Stop services
    Write-SubHeader "Stopping SCCM Services"
    $servicesToStop = @("CcmExec", "smstsmgr", "ccmsetup")

    foreach ($svcName in $servicesToStop) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") {
            Write-Host "  Stopping $svcName..." -NoNewline
            Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
            Write-ColorOutput " Stopped" "Green"
        }
    }

    # Wait for services to fully stop
    Start-Sleep -Seconds 5

    # Step 2: Uninstall existing client
    Write-SubHeader "Uninstalling SCCM Client"
    $ccmSetupPath = "$env:windir\ccmsetup\ccmsetup.exe"

    if (Test-Path $ccmSetupPath) {
        Write-Host "  Running ccmsetup /uninstall..."
        try {
            $proc = Start-Process -FilePath $ccmSetupPath -ArgumentList "/uninstall" -Wait -PassThru -NoNewWindow

            # Wait for uninstall to complete
            $timeout = 300  # 5 minutes
            $elapsed = 0
            while ((Get-Process -Name "ccmsetup" -ErrorAction SilentlyContinue) -and $elapsed -lt $timeout) {
                Write-Host "." -NoNewline
                Start-Sleep -Seconds 5
                $elapsed += 5
            }
            Write-Host ""
            Write-ColorOutput "  Uninstall command completed" "Green"
        } catch {
            Write-ColorOutput "  Uninstall error: $($_.Exception.Message)" "Red"
        }
    }

    # Step 3: Clean up remnants
    Write-SubHeader "Cleaning Up SCCM Files and Registry"

    # Stop any remaining processes
    Get-Process -Name "Ccm*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3

    # Remove directories
    $dirsToRemove = @(
        "$env:windir\CCM",
        "$env:windir\ccmsetup",
        "$env:windir\ccmcache",
        "$env:windir\SMSCFG.ini"
    )

    foreach ($dir in $dirsToRemove) {
        if (Test-Path $dir) {
            Write-Host "  Removing $dir..." -NoNewline
            try {
                Remove-Item -Path $dir -Recurse -Force -ErrorAction Stop
                Write-ColorOutput " Removed" "Green"
            } catch {
                Write-ColorOutput " Could not remove (may be locked)" "Yellow"
            }
        }
    }

    # Clean registry
    Write-Host "  Cleaning registry..."
    $regKeysToRemove = @(
        "HKLM:\SOFTWARE\Microsoft\CCM",
        "HKLM:\SOFTWARE\Microsoft\CCMSetup",
        "HKLM:\SOFTWARE\Microsoft\SMS"
    )

    foreach ($regKey in $regKeysToRemove) {
        if (Test-Path $regKey) {
            try {
                Remove-Item -Path $regKey -Recurse -Force -ErrorAction SilentlyContinue
            } catch { }
        }
    }
    Write-ColorOutput "  Registry cleaned" "Green"

    # Clean WMI namespaces
    Write-Host "  Cleaning WMI namespaces..."
    try {
        Get-WmiObject -Query "SELECT * FROM __Namespace WHERE Name='ccm'" -Namespace "root" -ErrorAction SilentlyContinue |
            Remove-WmiObject -ErrorAction SilentlyContinue
    } catch { }
    Write-ColorOutput "  WMI namespaces cleaned" "Green"

    # Step 4: Reinstall client
    Write-SubHeader "Reinstalling SCCM Client"

    # Find ccmsetup source
    $ccmsetupSource = $null

    # Check common locations
    $possibleSources = @(
        "$env:windir\ccmsetup\ccmsetup.exe",
        "\\$($Script:SCCMServerInfo.ManagementPoint)\SMS_$($Script:SCCMServerInfo.SiteCode)\Client\ccmsetup.exe",
        "\\$($Script:SCCMServerInfo.ManagementPoint)\ccmsetup$\ccmsetup.exe"
    )

    # Also check for local copy in standard network locations
    $domain = $env:USERDNSDOMAIN
    if ($domain) {
        $possibleSources += "\\$domain\NETLOGON\ccmsetup.exe"
        $possibleSources += "\\$domain\SYSVOL\$domain\scripts\ccmsetup.exe"
    }

    foreach ($source in $possibleSources) {
        if ($source -and (Test-Path $source -ErrorAction SilentlyContinue)) {
            $ccmsetupSource = $source
            break
        }
    }

    if (-not $ccmsetupSource) {
        Write-ColorOutput "  ERROR: Could not locate ccmsetup.exe" "Red"
        Write-Host ""
        Write-Host "  Please provide the path to ccmsetup.exe or the SCCM server share."
        $manualPath = Read-Host "  Enter path (or press Enter to skip)"

        if ($manualPath -and (Test-Path $manualPath)) {
            $ccmsetupSource = $manualPath
        }
    }

    if ($ccmsetupSource) {
        Write-Host "  Using source: $ccmsetupSource"
        Write-Host "  Installing SCCM client..."

        # Build installation arguments
        $installArgs = "/source:$([System.IO.Path]::GetDirectoryName($ccmsetupSource))"

        if ($Script:SCCMServerInfo.ManagementPoint) {
            $installArgs += " /mp:$($Script:SCCMServerInfo.ManagementPoint)"
        }

        if ($Script:SCCMServerInfo.SiteCode) {
            $installArgs += " SMSSITECODE=$($Script:SCCMServerInfo.SiteCode)"
        }

        $installArgs += " /forceinstall"

        Write-Host "  Arguments: $installArgs" -ForegroundColor Gray

        try {
            # Copy ccmsetup locally first
            $localCcmsetup = "$env:TEMP\ccmsetup.exe"
            Copy-Item -Path $ccmsetupSource -Destination $localCcmsetup -Force

            Start-Process -FilePath $localCcmsetup -ArgumentList $installArgs -Wait -NoNewWindow

            Write-Host ""
            Write-ColorOutput "  Installation initiated!" "Green"
            Write-Host ""
            Write-Host "  The SCCM client installation is now running in the background."
            Write-Host "  Check $env:windir\ccmsetup\Logs\ccmsetup.log for progress."
            Write-Host ""
            Write-Host "  Installation typically takes 5-15 minutes to complete."

        } catch {
            Write-ColorOutput "  Installation error: $($_.Exception.Message)" "Red"
        }
    } else {
        Write-ColorOutput "  Skipping installation - no source found" "Yellow"
        Write-Host ""
        Write-Host "  To manually install, run:"
        Write-Host "  ccmsetup.exe /mp:<ManagementPointFQDN> SMSSITECODE=<SiteCode>"
    }

    Write-Header "Complete Repair Process Finished"
    Write-ColorOutput "  Please wait 10-15 minutes for the client to fully install and register." "Yellow"
}

# ============================================================================
# MENU AND MAIN EXECUTION
# ============================================================================

function Show-MainMenu {
    <#
    .SYNOPSIS
        Displays the main menu and handles user selection
    #>

    while ($true) {
        Write-Host ""
        Write-Header "SCCM Agent Repair Options"
        Write-Host ""
        Write-Host "  1. Run Diagnostics Only"
        Write-Host "  2. Self-Check and Fix (Targeted Repairs)"
        Write-Host "  3. Complete SCCM Agent Repair (Uninstall/Reinstall)"
        Write-Host "  4. Exit"
        Write-Host ""

        $choice = Read-Host "  Enter your choice (1-4)"

        switch ($choice) {
            "1" {
                Run-AllDiagnostics

                Write-Host ""
                Write-Host "  Would you like to repair the SCCM Agent?"
                Write-Host ""
                Write-Host "  1. Self-Check and Fix (Quick targeted repairs)"
                Write-Host "  2. Complete Repair (Full reinstall)"
                Write-Host "  3. Return to Main Menu"
                Write-Host ""

                $repairChoice = Read-Host "  Enter your choice (1-3)"

                switch ($repairChoice) {
                    "1" { Repair-SelfCheckAndFix }
                    "2" { Repair-CompleteReinstall }
                    default { }
                }
            }
            "2" {
                # Run diagnostics first to populate results
                Write-Host ""
                Write-Host "  Running diagnostics to identify issues..."
                $null = Run-AllDiagnostics

                Write-Host ""
                $confirm = Read-Host "  Proceed with Self-Check and Fix? (Y/N)"
                if ($confirm -match "^[Yy]") {
                    Repair-SelfCheckAndFix
                }
            }
            "3" {
                # Run diagnostics first
                Write-Host ""
                Write-Host "  Running diagnostics to gather system information..."
                $null = Run-AllDiagnostics

                Repair-CompleteReinstall
            }
            "4" {
                Write-Host ""
                Write-ColorOutput "  Thank you for using SCCM Agent Diagnostic Tool!" "Cyan"
                Write-Host ""
                return
            }
            default {
                Write-ColorOutput "  Invalid choice. Please enter 1-4." "Red"
            }
        }
    }
}

# ============================================================================
# SCRIPT ENTRY POINT
# ============================================================================

# Clear screen
Clear-Host

# Check for admin privileges
if (-not (Test-AdminPrivileges)) {
    Write-ColorOutput "ERROR: This script must be run as Administrator!" "Red"
    Write-Host ""
    Write-Host "Please right-click PowerShell and select 'Run as Administrator'"
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-ColorOutput "ERROR: This script requires PowerShell 5.0 or later." "Red"
    Write-Host "Current version: $($PSVersionTable.PSVersion)"
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

# Display banner
Write-Host ""
Write-ColorOutput "  ============================================================" "Cyan"
Write-ColorOutput "       SCCM Agent Diagnostic and Repair Tool                  " "Cyan"
Write-ColorOutput "  ============================================================" "Cyan"
Write-Host ""
Write-Host "  This tool will diagnose your SCCM client agent and offer"
Write-Host "  repair options if issues are detected."
Write-Host ""

# Run main menu
Show-MainMenu

# End of script
