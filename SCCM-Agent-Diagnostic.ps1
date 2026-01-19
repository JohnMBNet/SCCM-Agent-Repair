#Requires -Version 5.0
#Requires -RunAsAdministrator

# ============================================================================
# SCRIPT METADATA AND DOCUMENTATION
# ============================================================================
<#
.SYNOPSIS
    SCCM Agent Diagnostic and Repair Tool

.DESCRIPTION
    This script performs comprehensive diagnostics on the SCCM (System Center
    Configuration Manager) client agent, also known as the ConfigMgr client.

    The script will:
    1. Auto-discover the SCCM Management Point server using multiple methods
    2. Run diagnostic tests on all critical SCCM client components
    3. Display color-coded results (PASS/FAIL/WARNING) for each test
    4. Offer two repair options:
       - Self-Check and Fix: Targeted repairs for specific issues
       - Complete Repair: Full uninstall and reinstall of the client

.NOTES
    Requirements:
    - PowerShell 5.0 or later (standard Windows PowerShell, NOT PowerShell 7)
    - Must be run as Administrator (elevated privileges required)
    - No external modules or libraries required - uses only built-in Windows features
    - Works on Windows 10, Windows 11, and Windows Server 2016+

.EXAMPLE
    .\SCCM-Agent-Diagnostic.ps1

    Simply run the script from an elevated PowerShell prompt. The interactive
    menu will guide you through the diagnostic and repair options.

.AUTHOR
    Generated for SCCM Agent Repair Project
#>

# ============================================================================
# GLOBAL VARIABLES
# ============================================================================
# These script-scoped variables store data that needs to be accessed across
# multiple functions throughout the script execution.

# Stores the results from all diagnostic tests so they can be referenced
# by the repair functions to determine what needs to be fixed
$Script:DiagnosticResults = @{}

# Stores information about the discovered SCCM server (Management Point,
# Site Code, and how it was discovered)
$Script:SCCMServerInfo = @{}

# Collects error messages throughout execution for troubleshooting purposes
$Script:ErrorLog = @()

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================
# These utility functions provide common functionality used throughout the
# script, such as formatted output and privilege checking.

function Write-ColorOutput {
    <#
    .SYNOPSIS
        Writes colored text to the console.

    .DESCRIPTION
        A wrapper around Write-Host that simplifies writing colored output.
        This function is used throughout the script to provide visual feedback
        with color-coded messages (green for success, red for errors, etc.)

    .PARAMETER Message
        The text message to display

    .PARAMETER Color
        The foreground color to use (defaults to White)

    .PARAMETER NoNewLine
        If specified, doesn't add a newline after the message (useful for
        building up output on a single line)
    #>
    param(
        [string]$Message,
        [string]$Color = "White",
        [switch]$NoNewLine
    )

    # Use Write-Host with the specified color
    # The -NoNewline switch allows us to continue writing on the same line
    if ($NoNewLine) {
        Write-Host $Message -ForegroundColor $Color -NoNewline
    } else {
        Write-Host $Message -ForegroundColor $Color
    }
}

function Write-Header {
    <#
    .SYNOPSIS
        Displays a formatted section header with a title.

    .DESCRIPTION
        Creates a visually distinct header using equals signs (=) to separate
        major sections of the script output. This helps users easily identify
        different phases of the diagnostic/repair process.

    .PARAMETER Title
        The title text to display in the header
    #>
    param([string]$Title)

    # Create a line of 70 equals signs for visual separation
    $line = "=" * 70

    # Add blank line before header for spacing
    Write-Host ""

    # Display the header box in cyan color
    Write-ColorOutput $line "Cyan"
    Write-ColorOutput "  $Title" "Cyan"
    Write-ColorOutput $line "Cyan"

    # Add blank line after header for spacing
    Write-Host ""
}

function Write-SubHeader {
    <#
    .SYNOPSIS
        Displays a formatted sub-section header.

    .DESCRIPTION
        Creates a smaller header using dashes (---) to separate sub-sections
        within a major section. Used to group related diagnostic tests.

    .PARAMETER Title
        The title text to display in the sub-header
    #>
    param([string]$Title)

    Write-Host ""
    Write-ColorOutput "--- $Title ---" "Yellow"
    Write-Host ""
}

function Write-TestResult {
    <#
    .SYNOPSIS
        Displays a single test result with color-coded status.

    .DESCRIPTION
        Formats and displays the result of a diagnostic test with:
        - A color-coded status indicator ([PASS], [FAIL], [WARNING], [INFO])
        - The name of the test
        - Optional additional details in gray text

        Color coding:
        - PASS (Green): Test passed, component is healthy
        - FAIL (Red): Test failed, component has issues that need repair
        - WARNING (Yellow): Test found potential issues but not critical
        - INFO (Cyan): Informational result, no pass/fail determination

    .PARAMETER TestName
        The name/description of the test being reported

    .PARAMETER Status
        The status: PASS, FAIL, WARNING, or INFO

    .PARAMETER Details
        Optional additional information about the test result
    #>
    param(
        [string]$TestName,
        [string]$Status,
        [string]$Details = ""
    )

    # Determine the color based on the status
    # Using a switch statement for clean status-to-color mapping
    $statusColor = switch ($Status) {
        "PASS"    { "Green" }   # Green for successful/healthy
        "FAIL"    { "Red" }     # Red for failures/errors
        "WARNING" { "Yellow" }  # Yellow for warnings/potential issues
        "INFO"    { "Cyan" }    # Cyan for informational messages
        default   { "White" }   # Default to white if unknown status
    }

    # Display the status in brackets with appropriate color
    Write-ColorOutput "  [$Status]" $statusColor -NoNewLine

    # Display the test name in default color
    Write-Host " $TestName"

    # If there are additional details, display them indented and in gray
    # This provides extra context without cluttering the main result
    if ($Details) {
        Write-Host "         $Details" -ForegroundColor Gray
    }
}

function Test-AdminPrivileges {
    <#
    .SYNOPSIS
        Checks if the script is running with Administrator privileges.

    .DESCRIPTION
        Many SCCM client operations require elevated privileges to access
        system directories, services, registry keys, and WMI namespaces.
        This function verifies that the script is running as Administrator
        before attempting any operations that would fail without elevation.

    .OUTPUTS
        [bool] Returns $true if running as Administrator, $false otherwise
    #>

    # Get the Windows identity of the current user
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()

    # Create a WindowsPrincipal object to check role membership
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)

    # Check if the user is in the Administrator role
    # This returns true if running elevated, false otherwise
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Add-ToErrorLog {
    <#
    .SYNOPSIS
        Adds an error message to the script's error log.

    .DESCRIPTION
        Maintains a running log of errors and issues encountered during
        script execution. Each entry is timestamped for troubleshooting.
        This log can be reviewed to understand what went wrong if the
        script encounters problems.

    .PARAMETER Message
        The error message to add to the log
    #>
    param([string]$Message)

    # Add the message with a timestamp to the script-level error log array
    # Format: [HH:mm:ss] Error message
    $Script:ErrorLog += "[$(Get-Date -Format 'HH:mm:ss')] $Message"
}

# ============================================================================
# SCCM SERVER DISCOVERY FUNCTIONS
# ============================================================================
# These functions attempt to automatically discover the SCCM Management Point
# server and Site Code using various methods. This eliminates the need for
# the user to manually enter server information.

function Get-SCCMServerFromRegistry {
    <#
    .SYNOPSIS
        Attempts to discover SCCM server information from the Windows Registry.

    .DESCRIPTION
        When the SCCM client is installed and configured, it stores configuration
        information in the registry. This function reads those registry keys to
        find the Management Point server and Site Code.

        Registry locations checked:
        - HKLM:\SOFTWARE\Microsoft\CCM - Contains AssignedSiteCode
        - HKLM:\SOFTWARE\Microsoft\CCM\LocationServices - Contains ManagementPoint

        This method works even if the SCCM client service is stopped, as long
        as the client was previously installed and configured.

    .OUTPUTS
        [hashtable] Contains:
        - ManagementPoint: The SCCM MP server URL/name (if found)
        - SiteCode: The SCCM site code (if found)
        - AssignedSite: The assigned site code from CCM key
    #>

    # Initialize the result hashtable with null values
    # We'll populate these as we find information
    $serverInfo = @{
        ManagementPoint = $null
        SiteCode = $null
        AssignedSite = $null
    }

    try {
        # Define the main CCM registry path
        # This is where SCCM stores its primary configuration
        $ccmRegPath = "HKLM:\SOFTWARE\Microsoft\CCM"

        # Check if the CCM registry key exists
        # If it doesn't exist, the SCCM client was never installed
        if (Test-Path $ccmRegPath) {

            # Try to read the AssignedSiteCode value
            # This is the SCCM site code (e.g., "PS1", "LAB", "PRD")
            # that this client is assigned to
            $assignedSite = Get-ItemProperty -Path $ccmRegPath -Name "AssignedSiteCode" -ErrorAction SilentlyContinue

            if ($assignedSite) {
                # Store the site code in both AssignedSite and SiteCode
                # AssignedSite is the raw value, SiteCode is what we'll use
                $serverInfo.AssignedSite = $assignedSite.AssignedSiteCode
                $serverInfo.SiteCode = $assignedSite.AssignedSiteCode
            }
        }

        # Check the LocationServices subkey for Management Point information
        # This key stores the current MP that the client is communicating with
        $mpRegPath = "HKLM:\SOFTWARE\Microsoft\CCM\LocationServices"

        if (Test-Path $mpRegPath) {
            # Try to get the Management Point value
            $mp = Get-ItemProperty -Path $mpRegPath -ErrorAction SilentlyContinue

            # If ManagementPoint property exists and has a value, store it
            if ($mp.ManagementPoint) {
                $serverInfo.ManagementPoint = $mp.ManagementPoint
            }
        }

    } catch {
        # If any error occurs during registry access, log it
        # This might happen if registry permissions are restricted
        Add-ToErrorLog "Registry discovery error: $($_.Exception.Message)"
    }

    # Return whatever information we found (may have null values)
    return $serverInfo
}

function Get-SCCMServerFromWMI {
    <#
    .SYNOPSIS
        Attempts to discover SCCM server information from WMI classes.

    .DESCRIPTION
        The SCCM client exposes information through WMI (Windows Management
        Instrumentation) in the root\ccm namespace. This function queries
        WMI classes to find the Management Point and Site Code.

        WMI Classes used:
        - SMS_Authority: Contains site assignment and current MP information
        - SMS_Client: The main client class, confirms client is functional
        - SMS_LocalMP: Contains local Management Point information

        This method is the most reliable when the client is running, as it
        reads live configuration data directly from the SCCM client.

    .OUTPUTS
        [hashtable] Contains:
        - ManagementPoint: The current Management Point URL/name
        - SiteCode: The SCCM site code
        - Authority: The SMS Authority name (format: SMS:SITECODE)
    #>

    # Initialize result hashtable
    $serverInfo = @{
        ManagementPoint = $null
        SiteCode = $null
        Authority = $null
    }

    try {
        # Query the SMS_Authority WMI class
        # This class contains information about the site the client is assigned to
        # The Name property is in format "SMS:SITECODE" (e.g., "SMS:PS1")
        # The CurrentManagementPoint property contains the MP URL
        $authority = Get-WmiObject -Namespace "root\ccm" -Class "SMS_Authority" -ErrorAction SilentlyContinue

        if ($authority) {
            # Store the authority name for reference
            $serverInfo.Authority = $authority.Name

            # Get the current Management Point if available
            if ($authority.CurrentManagementPoint) {
                $serverInfo.ManagementPoint = $authority.CurrentManagementPoint
            }

            # Extract the site code from the authority name
            # Authority name format is "SMS:SITECODE", so we use regex to extract
            # the site code portion after the colon
            if ($authority.Name -match "SMS:(\w+)") {
                # $Matches[1] contains the first capture group (the site code)
                $serverInfo.SiteCode = $Matches[1]
            }
        }

        # Alternative method: Try to get info from SMS_Client class
        # This is a fallback if SMS_Authority didn't provide what we need
        $smsClient = Get-WmiObject -Namespace "root\ccm" -Class "SMS_Client" -ErrorAction SilentlyContinue

        if ($smsClient -and -not $serverInfo.SiteCode) {
            # If we still don't have the site code, try SMS_LocalMP
            # This class contains information about the local Management Point
            $localMP = Get-WmiObject -Namespace "root\ccm" -Class "SMS_LocalMP" -ErrorAction SilentlyContinue

            if ($localMP) {
                # Store the MP hostname
                $serverInfo.ManagementPoint = $localMP.MPHostName
            }
        }

    } catch {
        # Log any WMI query errors
        # Common causes: WMI repository corruption, SCCM client not installed
        Add-ToErrorLog "WMI discovery error: $($_.Exception.Message)"
    }

    return $serverInfo
}

function Get-SCCMServerFromAD {
    <#
    .SYNOPSIS
        Attempts to discover SCCM server information from Active Directory.

    .DESCRIPTION
        When SCCM is configured to publish to Active Directory, it creates
        objects in the System container of the domain. This function searches
        AD for these published Management Point objects.

        This method works even if the SCCM client is not installed, as long
        as the computer is domain-joined and SCCM publishes to AD.

        AD Object searched: mSSMSManagementPoint
        Properties retrieved:
        - mSSMSMPName: The Management Point server name
        - mSSMSSiteCode: The SCCM site code

    .OUTPUTS
        [hashtable] Contains:
        - ManagementPoint: The published MP server name
        - SiteCode: The SCCM site code
    #>

    $serverInfo = @{
        ManagementPoint = $null
        SiteCode = $null
    }

    try {
        # Get the current domain using .NET DirectoryServices
        # This gives us access to domain information without requiring
        # the ActiveDirectory PowerShell module
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

        # Convert the domain name to distinguished name format
        # Example: contoso.com becomes DC=contoso,DC=com
        $domainDN = "DC=" + ($domain.Name -replace "\.", ",DC=")

        # Create a DirectorySearcher to find SCCM Management Point objects
        # These are stored in CN=System under the domain root
        $searcher = New-Object System.DirectoryServices.DirectorySearcher

        # Set the search root to the System container
        $searcher.SearchRoot = [ADSI]"LDAP://CN=System,$domainDN"

        # Filter for SCCM Management Point objects
        # mSSMSManagementPoint is the object class SCCM uses in AD
        $searcher.Filter = "(&(objectClass=mSSMSManagementPoint))"

        # Specify which properties we want to retrieve
        # This improves performance by not retrieving unnecessary data
        $searcher.PropertiesToLoad.Add("mSSMSMPName") | Out-Null
        $searcher.PropertiesToLoad.Add("mSSMSSiteCode") | Out-Null

        # Execute the search
        $results = $searcher.FindAll()

        # If we found any Management Points, use the first one
        if ($results.Count -gt 0) {
            $mp = $results[0]

            # Extract the properties (note: property names are lowercase in results)
            $serverInfo.ManagementPoint = $mp.Properties["mssmsmpname"][0]
            $serverInfo.SiteCode = $mp.Properties["mssmssitecode"][0]
        }

    } catch {
        # AD discovery can fail for several reasons:
        # - Computer is not domain-joined
        # - User doesn't have read access to System container
        # - SCCM is not configured to publish to AD
        # - Network connectivity issues to domain controller
        Add-ToErrorLog "AD discovery not available: $($_.Exception.Message)"
    }

    return $serverInfo
}

function Discover-SCCMServer {
    <#
    .SYNOPSIS
        Main function to auto-discover SCCM server using multiple methods.

    .DESCRIPTION
        This function orchestrates the SCCM server discovery process by
        trying multiple methods in order of reliability:

        1. WMI (Most reliable when client is running)
        2. Registry (Works even if client service is stopped)
        3. Active Directory (Works even if client is not installed)

        The function stops as soon as it successfully discovers the
        Management Point, avoiding unnecessary additional queries.

        Results are stored in the script-level $SCCMServerInfo variable
        for use by other functions.

    .OUTPUTS
        [hashtable] Contains:
        - ManagementPoint: The discovered MP server
        - SiteCode: The SCCM site code
        - DiscoveryMethod: Which method succeeded (WMI/Registry/Active Directory)
    #>

    Write-SubHeader "Auto-Discovering SCCM Server"

    # Initialize the result hashtable
    $discoveredInfo = @{
        ManagementPoint = $null
        SiteCode = $null
        DiscoveryMethod = $null
    }

    # -------------------------------------------------------------------------
    # Method 1: Try WMI first (most reliable if client is installed and running)
    # -------------------------------------------------------------------------
    Write-Host "  Checking WMI..." -NoNewline

    # Call the WMI discovery function
    $wmiInfo = Get-SCCMServerFromWMI

    # Check if we found a Management Point
    if ($wmiInfo.ManagementPoint) {
        # Success! Copy the discovered information
        $discoveredInfo.ManagementPoint = $wmiInfo.ManagementPoint
        $discoveredInfo.SiteCode = $wmiInfo.SiteCode
        $discoveredInfo.DiscoveryMethod = "WMI"
        Write-ColorOutput " Found!" "Green"
    } else {
        Write-ColorOutput " Not found" "Yellow"
    }

    # -------------------------------------------------------------------------
    # Method 2: Try Registry (works even if SCCM service is stopped)
    # -------------------------------------------------------------------------
    # Only try this if WMI didn't find the Management Point
    if (-not $discoveredInfo.ManagementPoint) {
        Write-Host "  Checking Registry..." -NoNewline

        # Call the Registry discovery function
        $regInfo = Get-SCCMServerFromRegistry

        # Check if we found either a Management Point or at least a Site Code
        if ($regInfo.ManagementPoint -or $regInfo.AssignedSite) {
            $discoveredInfo.ManagementPoint = $regInfo.ManagementPoint

            # Use the Site Code if available, otherwise use AssignedSite
            # This is PS5-compatible (no null-coalescing operator)
            if ($regInfo.SiteCode) {
                $discoveredInfo.SiteCode = $regInfo.SiteCode
            } else {
                $discoveredInfo.SiteCode = $regInfo.AssignedSite
            }

            $discoveredInfo.DiscoveryMethod = "Registry"
            Write-ColorOutput " Found!" "Green"
        } else {
            Write-ColorOutput " Not found" "Yellow"
        }
    }

    # -------------------------------------------------------------------------
    # Method 3: Try Active Directory (works even if client not installed)
    # -------------------------------------------------------------------------
    # Only try this if previous methods didn't find the Management Point
    if (-not $discoveredInfo.ManagementPoint) {
        Write-Host "  Checking Active Directory..." -NoNewline

        # Call the AD discovery function
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

    # -------------------------------------------------------------------------
    # Display discovery results
    # -------------------------------------------------------------------------
    Write-Host ""

    if ($discoveredInfo.ManagementPoint) {
        # Show what we found
        Write-TestResult "Management Point" "PASS" $discoveredInfo.ManagementPoint
        Write-TestResult "Site Code" "INFO" $discoveredInfo.SiteCode
        Write-TestResult "Discovery Method" "INFO" $discoveredInfo.DiscoveryMethod
    } else {
        # Couldn't find the server through any method
        Write-TestResult "SCCM Server Discovery" "WARNING" "Could not auto-discover SCCM server"
    }

    # Store the discovered info in the script-level variable for other functions
    $Script:SCCMServerInfo = $discoveredInfo

    return $discoveredInfo
}

# ============================================================================
# DIAGNOSTIC TEST FUNCTIONS
# ============================================================================
# These functions perform individual diagnostic tests on various components
# of the SCCM client. Each function checks a specific aspect and returns
# a hashtable with the results.

function Test-SCCMClientInstalled {
    <#
    .SYNOPSIS
        Checks if the SCCM client is installed on the system.

    .DESCRIPTION
        Verifies that the SCCM client (also known as the ConfigMgr client or
        CCM client) is installed by checking:

        1. The existence of the CCM folder (C:\Windows\CCM)
        2. The presence of ccmexec.exe (the main client executable)
        3. The WMI SMS_Client class (confirms client is functional)

        Also retrieves the client version number from the executable.

    .OUTPUTS
        [hashtable] Contains:
        - Installed: [bool] True if client is installed
        - Version: [string] Client version number (e.g., "5.00.9096.1000")
        - InstallPath: [string] Path to CCM folder
    #>

    # Initialize result hashtable with default values
    $result = @{
        Installed = $false
        Version = $null
        InstallPath = $null
    }

    try {
        # Check if the CCM folder exists
        # This is the main installation directory for the SCCM client
        # Located at C:\Windows\CCM by default
        $ccmPath = "$env:windir\CCM"

        if (Test-Path $ccmPath) {
            # CCM folder exists, store the path
            $result.InstallPath = $ccmPath

            # Check for the main executable: ccmexec.exe
            # This is the SMS Agent Host service executable
            $ccmExec = "$ccmPath\ccmexec.exe"

            if (Test-Path $ccmExec) {
                # Get the file version information
                $fileInfo = Get-Item $ccmExec

                # Extract the version from the file's VersionInfo property
                $result.Version = $fileInfo.VersionInfo.FileVersion
                $result.Installed = $true
            }
        }

        # Additional check: Query WMI for SMS_Client
        # This confirms the client is not just installed but registered in WMI
        $smsClient = Get-WmiObject -Namespace "root\ccm" -Class "SMS_Client" -ErrorAction SilentlyContinue

        if ($smsClient) {
            # Client exists in WMI
            $result.Installed = $true

            # If we didn't get the version from the file, get it from WMI
            if (-not $result.Version) {
                $result.Version = $smsClient.ClientVersion
            }
        }

    } catch {
        # Log any errors encountered during the check
        Add-ToErrorLog "Client installation check error: $($_.Exception.Message)"
    }

    return $result
}

function Test-SCCMServices {
    <#
    .SYNOPSIS
        Checks the status of SCCM-related Windows services.

    .DESCRIPTION
        The SCCM client depends on several Windows services to function properly.
        This function checks the status and start type of each service.

        Services checked:
        - CcmExec (SMS Agent Host): The main SCCM client service - CRITICAL
        - smstsmgr (ConfigMgr Task Sequence Agent): Handles task sequences
        - BITS (Background Intelligent Transfer): Used for content download - CRITICAL
        - wuauserv (Windows Update): Required for patch management - CRITICAL
        - Winmgmt (WMI): Required for WMI operations - CRITICAL

        Critical services should be running for the SCCM client to work properly.

    .OUTPUTS
        [array] Array of hashtables, each containing:
        - Name: Service name
        - DisplayName: Friendly service name
        - Status: Current status (Running, Stopped, etc.)
        - StartType: Startup type (Automatic, Manual, Disabled)
        - Critical: Whether this service is critical for SCCM
        - Healthy: Whether the service is in a healthy state
    #>

    # Define the services to check with their properties
    # Critical = $true means the SCCM client won't work properly without it
    $services = @(
        @{
            Name = "CcmExec"
            DisplayName = "SMS Agent Host"
            Critical = $true  # This is THE main SCCM service
        },
        @{
            Name = "smstsmgr"
            DisplayName = "ConfigMgr Task Sequence Agent"
            Critical = $false  # Only needed during task sequences
        },
        @{
            Name = "BITS"
            DisplayName = "Background Intelligent Transfer Service"
            Critical = $true  # Required for downloading content from SCCM
        },
        @{
            Name = "wuauserv"
            DisplayName = "Windows Update"
            Critical = $true  # Required for software updates/patch management
        },
        @{
            Name = "Winmgmt"
            DisplayName = "Windows Management Instrumentation"
            Critical = $true  # Required for WMI - SCCM uses WMI extensively
        }
    )

    # Array to store results for each service
    $results = @()

    # Check each service
    foreach ($svc in $services) {
        # Try to get the service object
        # Use -ErrorAction SilentlyContinue because the service might not exist
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue

        # Build the result hashtable for this service
        $svcResult = @{
            Name = $svc.Name
            DisplayName = $svc.DisplayName
            # If service exists, get its status; otherwise mark as "Not Found"
            Status = if ($service) { $service.Status.ToString() } else { "Not Found" }
            # If service exists, get its start type; otherwise "N/A"
            StartType = if ($service) { $service.StartType.ToString() } else { "N/A" }
            Critical = $svc.Critical
            Healthy = $false  # Default to unhealthy, we'll set to true if conditions are met
        }

        # Determine if the service is healthy
        if ($service -and $service.Status -eq "Running") {
            # Service exists and is running - healthy
            $svcResult.Healthy = $true
        } elseif (-not $svc.Critical -and $service) {
            # Non-critical services can be stopped and still be considered "healthy"
            # For example, smstsmgr only runs during task sequences
            $svcResult.Healthy = $true
        }
        # If critical service is not running, Healthy remains $false

        # Add this service's result to the array
        $results += $svcResult
    }

    return $results
}

function Test-WMIRepository {
    <#
    .SYNOPSIS
        Checks the health of the WMI repository and SCCM namespaces.

    .DESCRIPTION
        WMI (Windows Management Instrumentation) is fundamental to SCCM operation.
        The client stores configuration and inventory data in WMI, and all
        communication with the client happens through WMI.

        This function tests:
        1. Basic WMI connectivity (can we query Win32_OperatingSystem?)
        2. SCCM-specific namespaces exist and are accessible

        SCCM Namespaces checked:
        - root\ccm: Main SCCM namespace
        - root\ccm\ClientSDK: Client SDK methods
        - root\ccm\Policy: Policy storage
        - root\ccm\SoftMgmtAgent: Software management
        - root\cimv2\sms: SMS inventory classes

        If WMI is corrupted, the SCCM client will not function properly.

    .OUTPUTS
        [hashtable] Contains:
        - WMIHealthy: [bool] True if basic WMI is functional
        - SCCMNamespaceExists: [bool] True if root\ccm is accessible
        - Namespaces: [array] List of namespaces and their accessibility
        - Errors: [array] Any errors encountered
    #>

    $results = @{
        WMIHealthy = $false
        SCCMNamespaceExists = $false
        Namespaces = @()
        Errors = @()
    }

    try {
        # -------------------------------------------------------------------------
        # Test basic WMI connectivity
        # -------------------------------------------------------------------------
        # Query a standard Windows WMI class to verify WMI is working
        # Win32_OperatingSystem should always be available on Windows
        $wmiTest = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop

        if ($wmiTest) {
            # Basic WMI is functional
            $results.WMIHealthy = $true
        }

        # -------------------------------------------------------------------------
        # Check SCCM-specific WMI namespaces
        # -------------------------------------------------------------------------
        # Define the namespaces that SCCM creates and uses
        $sccmNamespaces = @(
            "root\ccm",              # Main namespace - contains SMS_Client and core classes
            "root\ccm\ClientSDK",    # Client SDK - methods for triggering actions
            "root\ccm\Policy",       # Policy storage - machine and user policies
            "root\ccm\SoftMgmtAgent", # Software management - cache and app deployment
            "root\cimv2\sms"         # SMS inventory - hardware/software inventory data
        )

        # Test each namespace
        foreach ($ns in $sccmNamespaces) {
            try {
                # Try to query the __NAMESPACE class in each namespace
                # This is a system class that exists in all WMI namespaces
                $testQuery = Get-WmiObject -Namespace $ns -Class "__NAMESPACE" -ErrorAction Stop

                # If we get here without error, the namespace is accessible
                $results.Namespaces += @{ Namespace = $ns; Exists = $true }
            } catch {
                # Namespace is not accessible (doesn't exist or is corrupted)
                $results.Namespaces += @{ Namespace = $ns; Exists = $false }
                $results.Errors += "Namespace '$ns' not accessible"
            }
        }

        # -------------------------------------------------------------------------
        # Check if the main CCM namespace exists
        # -------------------------------------------------------------------------
        # This is the most important namespace - without it, SCCM won't work
        $ccmNs = $results.Namespaces | Where-Object { $_.Namespace -eq "root\ccm" }

        if ($ccmNs -and $ccmNs.Exists) {
            $results.SCCMNamespaceExists = $true
        }

    } catch {
        # Critical WMI failure - basic WMI query failed
        $results.Errors += "WMI test failed: $($_.Exception.Message)"
        Add-ToErrorLog "WMI Repository check error: $($_.Exception.Message)"
    }

    return $results
}

function Test-SCCMCommunication {
    <#
    .SYNOPSIS
        Tests communication with the SCCM Management Point.

    .DESCRIPTION
        The SCCM client must be able to communicate with the Management Point (MP)
        to receive policies, report inventory, and get content locations.

        This function tests:
        1. Whether a Management Point is configured
        2. Network connectivity to the MP (ping and TCP ports)
        3. Last policy request time
        4. Last hardware/software inventory times

        If the client can't reach the MP, it can't receive new policies or
        report back to the SCCM server.

    .OUTPUTS
        [hashtable] Contains:
        - CanReachMP: [bool] True if MP is reachable
        - MPUrl: [string] Management Point URL
        - LastPolicyRequest: [string] Last policy request info
        - LastHWInventory: [string] Last hardware inventory date
        - LastSWInventory: [string] Last software inventory date
        - Errors: [array] Any errors encountered
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
        # -------------------------------------------------------------------------
        # Get Management Point URL from WMI
        # -------------------------------------------------------------------------
        $mp = Get-WmiObject -Namespace "root\ccm" -Class "SMS_Authority" -ErrorAction SilentlyContinue

        if ($mp -and $mp.CurrentManagementPoint) {
            # Store the MP URL
            $results.MPUrl = $mp.CurrentManagementPoint

            # -------------------------------------------------------------------------
            # Test connectivity to the Management Point
            # -------------------------------------------------------------------------
            # First, extract just the hostname from the URL
            # The URL might be like "https://sccm.contoso.com" or just "sccm.contoso.com"
            $mpHost = $mp.CurrentManagementPoint -replace "https?://", "" -replace "/.*", ""

            # Try ping first (ICMP)
            $pingResult = Test-Connection -ComputerName $mpHost -Count 1 -Quiet -ErrorAction SilentlyContinue
            $results.CanReachMP = $pingResult

            # If ping fails, try TCP connection
            # Many networks block ICMP but allow HTTP/HTTPS
            if (-not $results.CanReachMP) {
                try {
                    # Try HTTPS port (443)
                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                    $tcpClient.Connect($mpHost, 443)
                    $results.CanReachMP = $tcpClient.Connected
                    $tcpClient.Close()
                } catch {
                    try {
                        # Try HTTP port (80) as fallback
                        $tcpClient = New-Object System.Net.Sockets.TcpClient
                        $tcpClient.Connect($mpHost, 80)
                        $results.CanReachMP = $tcpClient.Connected
                        $tcpClient.Close()
                    } catch {
                        # Neither port is reachable
                        $results.CanReachMP = $false
                    }
                }
            }
        }

        # -------------------------------------------------------------------------
        # Get last policy request information
        # -------------------------------------------------------------------------
        try {
            # Query the policy agent configuration
            $policyAgent = Get-WmiObject -Namespace "root\ccm\Policy\Machine" -Query "SELECT * FROM CCM_PolicyAgent_Configuration" -ErrorAction SilentlyContinue

            if ($policyAgent) {
                $results.LastPolicyRequest = "Policy agent configured"
            }
        } catch {
            # Ignore errors - policy info is optional
        }

        # -------------------------------------------------------------------------
        # Get last hardware inventory time
        # -------------------------------------------------------------------------
        try {
            # Query the InventoryActionStatus class for hardware inventory
            # The GUID {00000000-0000-0000-0000-000000000001} identifies hardware inventory
            $hwInv = Get-WmiObject -Namespace "root\ccm\InvAgt" -Class "InventoryActionStatus" -ErrorAction SilentlyContinue |
                     Where-Object { $_.InventoryActionID -eq "{00000000-0000-0000-0000-000000000001}" }

            if ($hwInv -and $hwInv.LastCycleStartedDate) {
                # Convert WMI datetime format to readable format
                # WMI uses a special datetime format that needs conversion
                $lastHW = [Management.ManagementDateTimeConverter]::ToDateTime($hwInv.LastCycleStartedDate)
                $results.LastHWInventory = $lastHW.ToString("yyyy-MM-dd HH:mm:ss")
            }
        } catch {
            # Ignore errors - inventory info is optional
        }

        # -------------------------------------------------------------------------
        # Get last software inventory time
        # -------------------------------------------------------------------------
        try {
            # The GUID {00000000-0000-0000-0000-000000000002} identifies software inventory
            $swInv = Get-WmiObject -Namespace "root\ccm\InvAgt" -Class "InventoryActionStatus" -ErrorAction SilentlyContinue |
                     Where-Object { $_.InventoryActionID -eq "{00000000-0000-0000-0000-000000000002}" }

            if ($swInv -and $swInv.LastCycleStartedDate) {
                $lastSW = [Management.ManagementDateTimeConverter]::ToDateTime($swInv.LastCycleStartedDate)
                $results.LastSWInventory = $lastSW.ToString("yyyy-MM-dd HH:mm:ss")
            }
        } catch {
            # Ignore errors - inventory info is optional
        }

    } catch {
        $results.Errors += $_.Exception.Message
        Add-ToErrorLog "Communication test error: $($_.Exception.Message)"
    }

    return $results
}

function Test-SCCMClientHealth {
    <#
    .SYNOPSIS
        Checks SCCM client health status using built-in health evaluation.

    .DESCRIPTION
        The SCCM client includes a built-in health evaluation tool (CcmEval.exe)
        that runs periodically to check client health and attempt auto-remediation.

        This function checks:
        1. Whether the SMS_Client WMI class is responsive
        2. Whether health evaluation is enabled
        3. The results of the last health evaluation (from CcmEvalReport.xml)

        The CcmEvalReport.xml file contains detailed results of each health
        check performed by CcmEval, including pass/fail status and details.

    .OUTPUTS
        [hashtable] Contains:
        - ClientActive: [bool] True if SMS_Client responds to WMI queries
        - HealthEvaluationEnabled: [bool] True if CcmEval has run
        - LastHealthEvaluation: [string] When health eval last ran
        - HealthResult: [string] Overall health status
        - Errors: [array] Any health check failures
    #>

    $results = @{
        HealthEvaluationEnabled = $false
        LastHealthEvaluation = $null
        HealthResult = $null
        ClientActive = $false
        Errors = @()
    }

    try {
        # -------------------------------------------------------------------------
        # Check if the SMS_Client WMI class is responsive
        # -------------------------------------------------------------------------
        # This is a basic "is the client alive" check
        $smsClient = Get-WmiObject -Namespace "root\ccm" -Class "SMS_Client" -ErrorAction SilentlyContinue

        if ($smsClient) {
            $results.ClientActive = $true
        }

        # -------------------------------------------------------------------------
        # Check the CcmEval health report
        # -------------------------------------------------------------------------
        # CcmEval.exe generates an XML report with the results of its health checks
        $evalResultPath = "$env:windir\CCM\CcmEvalReport.xml"

        if (Test-Path $evalResultPath) {
            # Health evaluation has run at least once
            $results.HealthEvaluationEnabled = $true

            try {
                # Parse the XML report
                [xml]$evalReport = Get-Content $evalResultPath -ErrorAction Stop

                # Get the report timestamp
                $results.LastHealthEvaluation = $evalReport.ClientHealthReport.ReportTime

                # Check for any failed health checks
                # Each HealthCheck node has a Result property (Pass/Fail)
                $failures = $evalReport.ClientHealthReport.HealthChecks.HealthCheck |
                           Where-Object { $_.Result -eq "Fail" }

                if ($failures) {
                    # There are failed health checks
                    $results.HealthResult = "Issues Found"

                    # Add each failure to the errors list
                    foreach ($fail in $failures) {
                        $results.Errors += "$($fail.Description): $($fail.ResultDetail)"
                    }
                } else {
                    # All health checks passed
                    $results.HealthResult = "Healthy"
                }
            } catch {
                # Could not parse the XML file
                $results.HealthResult = "Could not parse health report"
            }
        }

        # -------------------------------------------------------------------------
        # Alternative: Check registry for health status
        # -------------------------------------------------------------------------
        # CcmEval also stores some info in the registry
        $healthRegPath = "HKLM:\SOFTWARE\Microsoft\CCM\CcmEval"

        if (Test-Path $healthRegPath) {
            $healthReg = Get-ItemProperty -Path $healthRegPath -ErrorAction SilentlyContinue

            # Get the last evaluation time if we don't have it already
            if ($healthReg.LastEvalTime -and -not $results.LastHealthEvaluation) {
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
        Checks SCCM client cache status and size.

    .DESCRIPTION
        The SCCM client cache (ccmcache) stores downloaded content such as:
        - Application installation files
        - Software update files
        - Package content
        - Operating system deployment content

        This function checks:
        1. Whether the cache is enabled and accessible
        2. The cache location (usually C:\Windows\ccmcache)
        3. The configured cache size
        4. Current cache usage
        5. Number of cached items

        Cache problems can prevent software installations and updates.

    .OUTPUTS
        [hashtable] Contains:
        - CacheEnabled: [bool] True if cache is configured
        - CachePath: [string] Path to the cache folder
        - CacheSize: [int] Configured cache size in MB
        - CacheUsed: [int] Currently used cache space in MB
        - CacheItems: [int] Number of items in the cache
        - Errors: [array] Any errors encountered
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
        # -------------------------------------------------------------------------
        # Get cache configuration from WMI
        # -------------------------------------------------------------------------
        # The CacheConfig class contains cache settings
        $cacheConfig = Get-WmiObject -Namespace "root\ccm\SoftMgmtAgent" -Class "CacheConfig" -ErrorAction SilentlyContinue

        if ($cacheConfig) {
            $results.CacheEnabled = $true
            $results.CachePath = $cacheConfig.Location
            # Round the cache size to 2 decimal places
            $results.CacheSize = [math]::Round($cacheConfig.Size, 2)
        }

        # -------------------------------------------------------------------------
        # Get cache usage information
        # -------------------------------------------------------------------------
        # CacheInfoEx contains information about each item in the cache
        $cacheItems = Get-WmiObject -Namespace "root\ccm\SoftMgmtAgent" -Class "CacheInfoEx" -ErrorAction SilentlyContinue

        if ($cacheItems) {
            # Count the number of cached items
            $results.CacheItems = ($cacheItems | Measure-Object).Count

            # Sum up the total size of all cached content
            # ContentSize is in KB, so divide by 1024 to get MB
            $totalSize = ($cacheItems | Measure-Object -Property ContentSize -Sum).Sum
            $results.CacheUsed = [math]::Round($totalSize / 1024, 2)
        }

        # -------------------------------------------------------------------------
        # Verify cache folder exists
        # -------------------------------------------------------------------------
        # Default cache location
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
        Checks SCCM client certificates.

    .DESCRIPTION
        SCCM can use certificates for:
        - Client authentication to the Management Point (PKI mode)
        - HTTPS communication with site systems
        - Client identity verification

        This function checks:
        1. The SMS certificate store for SCCM-specific certificates
        2. The Personal (My) certificate store for client auth certificates
        3. Certificate validity (not expired)

        Certificate issues can prevent client-server communication,
        especially in PKI/HTTPS environments.

    .OUTPUTS
        [hashtable] Contains:
        - HasClientCert: [bool] True if a client certificate is found
        - CertSubject: [string] Certificate subject name
        - CertExpiry: [string] Certificate expiration date
        - CertValid: [bool] True if certificate is not expired
        - Errors: [array] Any errors encountered
    #>

    $results = @{
        HasClientCert = $false
        CertSubject = $null
        CertExpiry = $null
        CertValid = $false
        Errors = @()
    }

    try {
        # -------------------------------------------------------------------------
        # Check the SMS certificate store
        # -------------------------------------------------------------------------
        # SCCM creates a dedicated certificate store called "SMS"
        # This store contains the client's self-signed certificate
        $smsCerts = Get-ChildItem -Path "Cert:\LocalMachine\SMS" -ErrorAction SilentlyContinue

        if ($smsCerts) {
            # Look for certificates with SMS or CCM in the subject
            $clientCert = $smsCerts |
                         Where-Object { $_.Subject -like "*SMS*" -or $_.Subject -like "*CCM*" } |
                         Select-Object -First 1

            # If no SMS/CCM cert found, just use the first one
            if (-not $clientCert) {
                $clientCert = $smsCerts | Select-Object -First 1
            }

            if ($clientCert) {
                $results.HasClientCert = $true
                $results.CertSubject = $clientCert.Subject
                $results.CertExpiry = $clientCert.NotAfter.ToString("yyyy-MM-dd HH:mm:ss")
                # Check if the certificate has not expired
                $results.CertValid = ($clientCert.NotAfter -gt (Get-Date))
            }
        }

        # -------------------------------------------------------------------------
        # Check Personal certificate store (fallback)
        # -------------------------------------------------------------------------
        # In PKI environments, the client auth certificate might be in the
        # Personal (My) store instead of the SMS store
        if (-not $results.HasClientCert) {
            $personalCerts = Get-ChildItem -Path "Cert:\LocalMachine\My" -ErrorAction SilentlyContinue

            # Look for certificates that:
            # 1. Have Client Authentication EKU (Extended Key Usage)
            # 2. Have the computer name in the subject
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
        Checks SCCM policy status.

    .DESCRIPTION
        SCCM uses policies to configure and control the client. Policies include:
        - Machine policies (apply to the computer)
        - User policies (apply to logged-in users)
        - Application deployments
        - Software update assignments
        - Compliance settings

        This function checks:
        1. Whether machine policies exist in WMI
        2. The count of policies (indicates healthy policy download)

        If no policies are found, the client may not have successfully
        communicated with the Management Point.

    .OUTPUTS
        [hashtable] Contains:
        - MachinePolicy: [bool] True if machine policies exist
        - UserPolicy: [bool] True if user policies exist
        - PolicyCount: [int] Number of policies found
        - Errors: [array] Any errors encountered
    #>

    $results = @{
        MachinePolicy = $false
        UserPolicy = $false
        PolicyCount = 0
        Errors = @()
    }

    try {
        # -------------------------------------------------------------------------
        # Check for machine policies
        # -------------------------------------------------------------------------
        # Policies are stored in root\ccm\Policy\Machine\ActualConfig
        # CCM_ComponentClientConfig is one of the policy classes
        $machinePolicies = Get-WmiObject -Namespace "root\ccm\Policy\Machine\ActualConfig" -Class "CCM_ComponentClientConfig" -ErrorAction SilentlyContinue

        if ($machinePolicies) {
            $results.MachinePolicy = $true
            # Count the number of policy instances
            $results.PolicyCount = ($machinePolicies | Measure-Object).Count
        }

        # -------------------------------------------------------------------------
        # Verify the policy namespace has content
        # -------------------------------------------------------------------------
        # Check if the Policy namespace has sub-namespaces
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
        Checks SCCM client log files and looks for recent errors.

    .DESCRIPTION
        The SCCM client generates extensive log files that are invaluable
        for troubleshooting. Logs are stored in C:\Windows\CCM\Logs.

        This function checks:
        1. Whether the log directory exists
        2. Whether critical log files are present
        3. Recent error entries in log files

        Critical logs checked:
        - CcmExec.log: Main client service log
        - ClientLocation.log: Management Point location
        - PolicyAgent.log: Policy download and processing
        - StatusAgent.log: State message reporting
        - DataTransferService.log: Content download

    .OUTPUTS
        [hashtable] Contains:
        - LogPath: [string] Path to log directory
        - LogFilesExist: [bool] True if log directory exists
        - CriticalLogs: [array] Status of each critical log file
        - RecentErrors: [array] Recent errors found in logs
    #>

    $results = @{
        LogPath = $null
        LogFilesExist = $false
        RecentErrors = @()
        CriticalLogs = @()
    }

    try {
        # Define the log directory path
        $logPath = "$env:windir\CCM\Logs"
        $results.LogPath = $logPath

        if (Test-Path $logPath) {
            $results.LogFilesExist = $true

            # -------------------------------------------------------------------------
            # Define critical log files to check
            # -------------------------------------------------------------------------
            # These are the most important logs for diagnosing client issues
            $criticalLogs = @(
                "CcmExec.log",           # Main client service - shows startup, shutdown, and major events
                "ClientLocation.log",     # MP location - shows how client finds its MP
                "PolicyAgent.log",        # Policy processing - shows policy download and evaluation
                "StatusAgent.log",        # State messages - shows reporting to server
                "DataTransferService.log" # Content transfer - shows downloads from DPs
            )

            # Check each critical log file
            foreach ($logName in $criticalLogs) {
                $logFile = Join-Path $logPath $logName

                if (Test-Path $logFile) {
                    # Log file exists - get its properties
                    $fileInfo = Get-Item $logFile

                    $results.CriticalLogs += @{
                        Name = $logName
                        Exists = $true
                        LastModified = $fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                        SizeKB = [math]::Round($fileInfo.Length / 1024, 2)
                    }

                    # -------------------------------------------------------------------------
                    # Check for recent errors in the log
                    # -------------------------------------------------------------------------
                    # Read the last 50 lines and search for error indicators
                    try {
                        $content = Get-Content $logFile -Tail 50 -ErrorAction SilentlyContinue

                        # Search for common error patterns (case-insensitive)
                        $errors = $content | Select-String -Pattern "error|fail|exception" -AllMatches

                        if ($errors) {
                            $results.RecentErrors += @{
                                LogFile = $logName
                                ErrorCount = $errors.Count
                            }
                        }
                    } catch {
                        # Ignore errors reading the log file
                    }
                } else {
                    # Log file doesn't exist
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
# This function orchestrates all the individual diagnostic tests and
# compiles the results into a comprehensive report.

function Run-AllDiagnostics {
    <#
    .SYNOPSIS
        Runs all diagnostic tests and stores results.

    .DESCRIPTION
        This is the main diagnostic function that:
        1. Displays system information
        2. Discovers the SCCM server
        3. Runs all individual diagnostic tests
        4. Displays results with color-coded status
        5. Calculates and displays a summary
        6. Provides recommendations based on findings

        Results are stored in the script-level $DiagnosticResults variable
        so they can be used by the repair functions.

    .OUTPUTS
        [hashtable] Summary containing Pass, Fail, and Warning counts
    #>

    # -------------------------------------------------------------------------
    # Display header with system information
    # -------------------------------------------------------------------------
    Write-Header "SCCM Agent Diagnostic Tool"
    Write-Host "  Computer: $env:COMPUTERNAME"
    Write-Host "  User: $env:USERNAME"
    Write-Host "  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

    # -------------------------------------------------------------------------
    # Discover SCCM Server
    # -------------------------------------------------------------------------
    # This must run first as other tests may use this information
    $serverInfo = Discover-SCCMServer

    # -------------------------------------------------------------------------
    # Test 1: Client Installation
    # -------------------------------------------------------------------------
    Write-SubHeader "Checking SCCM Client Installation"

    $clientInstall = Test-SCCMClientInstalled

    if ($clientInstall.Installed) {
        Write-TestResult "SCCM Client Installed" "PASS" "Version: $($clientInstall.Version)"
        Write-TestResult "Install Path" "INFO" $clientInstall.InstallPath
    } else {
        Write-TestResult "SCCM Client Installed" "FAIL" "Client not found on this system"
    }

    # Store results for repair functions
    $Script:DiagnosticResults.ClientInstall = $clientInstall

    # -------------------------------------------------------------------------
    # Test 2: Services
    # -------------------------------------------------------------------------
    Write-SubHeader "Checking SCCM Services"

    $services = Test-SCCMServices

    foreach ($svc in $services) {
        # Determine status based on whether service is healthy
        $status = if ($svc.Healthy) { "PASS" } else { "FAIL" }
        Write-TestResult "$($svc.DisplayName) ($($svc.Name))" $status "Status: $($svc.Status), StartType: $($svc.StartType)"
    }

    $Script:DiagnosticResults.Services = $services

    # -------------------------------------------------------------------------
    # Test 3: WMI Repository
    # -------------------------------------------------------------------------
    Write-SubHeader "Checking WMI Repository"

    $wmi = Test-WMIRepository

    # Check basic WMI health
    if ($wmi.WMIHealthy) {
        Write-TestResult "WMI Repository" "PASS" "Core WMI is functional"
    } else {
        Write-TestResult "WMI Repository" "FAIL" "WMI has issues"
    }

    # Check SCCM-specific namespace
    if ($wmi.SCCMNamespaceExists) {
        Write-TestResult "SCCM WMI Namespace" "PASS" "root\ccm is accessible"
    } else {
        Write-TestResult "SCCM WMI Namespace" "FAIL" "root\ccm is not accessible"
    }

    # Show namespace accessibility summary
    $accessibleNs = ($wmi.Namespaces | Where-Object { $_.Exists }).Count
    $totalNs = $wmi.Namespaces.Count
    Write-TestResult "SCCM Namespaces" "INFO" "$accessibleNs of $totalNs namespaces accessible"

    $Script:DiagnosticResults.WMI = $wmi

    # -------------------------------------------------------------------------
    # Test 4: Communication
    # -------------------------------------------------------------------------
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

    # Show inventory information if available
    if ($comm.LastHWInventory) {
        Write-TestResult "Last Hardware Inventory" "INFO" $comm.LastHWInventory
    }
    if ($comm.LastSWInventory) {
        Write-TestResult "Last Software Inventory" "INFO" $comm.LastSWInventory
    }

    $Script:DiagnosticResults.Communication = $comm

    # -------------------------------------------------------------------------
    # Test 5: Client Health
    # -------------------------------------------------------------------------
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

    # -------------------------------------------------------------------------
    # Test 6: Cache
    # -------------------------------------------------------------------------
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

    # -------------------------------------------------------------------------
    # Test 7: Certificates
    # -------------------------------------------------------------------------
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

    # -------------------------------------------------------------------------
    # Test 8: Policies
    # -------------------------------------------------------------------------
    Write-SubHeader "Checking Policies"

    $policies = Test-SCCMPolicies

    if ($policies.MachinePolicy) {
        Write-TestResult "Machine Policies" "PASS" "$($policies.PolicyCount) policies found"
    } else {
        Write-TestResult "Machine Policies" "FAIL" "No machine policies found"
    }

    $Script:DiagnosticResults.Policies = $policies

    # -------------------------------------------------------------------------
    # Test 9: Logging
    # -------------------------------------------------------------------------
    Write-SubHeader "Checking Log Files"

    $logs = Test-SCCMLogging

    if ($logs.LogFilesExist) {
        Write-TestResult "Log Directory" "PASS" $logs.LogPath

        # Count existing critical logs
        $existingLogs = ($logs.CriticalLogs | Where-Object { $_.Exists }).Count
        $totalLogs = $logs.CriticalLogs.Count
        Write-TestResult "Critical Log Files" "INFO" "$existingLogs of $totalLogs present"

        # Check for recent errors
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

    # -------------------------------------------------------------------------
    # Calculate and Display Summary
    # -------------------------------------------------------------------------
    Write-Header "Diagnostic Summary"

    # Initialize counters
    $passCount = 0
    $failCount = 0
    $warningCount = 0

    # Calculate summary based on test results
    # Each test contributes to pass/fail/warning counts

    # Client installation
    if ($clientInstall.Installed) { $passCount++ } else { $failCount++ }

    # Services (only count critical services as failures)
    $failCount += ($services | Where-Object { -not $_.Healthy -and $_.Critical }).Count
    $passCount += ($services | Where-Object { $_.Healthy }).Count

    # WMI
    if ($wmi.WMIHealthy) { $passCount++ } else { $failCount++ }
    if ($wmi.SCCMNamespaceExists) { $passCount++ } else { $failCount++ }

    # Communication
    if ($comm.CanReachMP) { $passCount++ }
    elseif ($comm.MPUrl) { $failCount++ }  # Has MP but can't reach it
    else { $warningCount++ }  # No MP configured

    # Health
    if ($health.ClientActive) { $passCount++ } else { $failCount++ }

    # Cache
    if ($cache.CacheEnabled) { $passCount++ } else { $warningCount++ }

    # Certificates
    if ($certs.HasClientCert -and $certs.CertValid) { $passCount++ }
    elseif ($certs.HasClientCert) { $failCount++ }  # Has cert but expired
    else { $warningCount++ }  # No cert (might be OK in HTTP mode)

    # Policies
    if ($policies.MachinePolicy) { $passCount++ } else { $failCount++ }

    # Display the summary counts with colors
    Write-ColorOutput "  Passed:   $passCount" "Green"
    Write-ColorOutput "  Failed:   $failCount" "Red"
    Write-ColorOutput "  Warnings: $warningCount" "Yellow"
    Write-Host ""

    # Provide recommendations based on findings
    if ($failCount -gt 0) {
        Write-ColorOutput "  RECOMMENDATION: Repair is recommended to fix detected issues." "Yellow"
    } elseif ($warningCount -gt 0) {
        Write-ColorOutput "  RECOMMENDATION: Self-check repair may help resolve warnings." "Yellow"
    } else {
        Write-ColorOutput "  SCCM Agent appears to be healthy!" "Green"
    }

    # Return summary for potential use by calling code
    return @{
        Pass = $passCount
        Fail = $failCount
        Warning = $warningCount
    }
}

# ============================================================================
# REPAIR FUNCTIONS
# ============================================================================
# These functions perform repairs on the SCCM client based on the issues
# found during diagnostics.

function Repair-SelfCheckAndFix {
    <#
    .SYNOPSIS
        Performs targeted repairs based on diagnostic results.

    .DESCRIPTION
        This repair option performs specific fixes for detected issues without
        reinstalling the entire client. It's faster and less disruptive than
        a complete reinstall.

        Repairs performed:
        1. Start stopped critical services
        2. Repair WMI repository if issues detected
        3. Trigger machine policy refresh
        4. Trigger hardware and software inventory
        5. Run the built-in CcmEval health evaluation
        6. Reset and rebuild policy store if empty

        This option is best when:
        - The client is installed but not working properly
        - Services are stopped
        - Policies are missing or outdated
        - Inventory hasn't run recently
    #>

    Write-Header "Self-Check and Fix Repair"
    Write-Host "  This will attempt to fix detected issues without reinstalling the client."
    Write-Host ""

    # Track the number of repairs made
    $repairsMade = 0

    # =========================================================================
    # Fix 1: Restart stopped critical services
    # =========================================================================
    Write-SubHeader "Checking and Starting Services"

    # List of critical services that should be running
    $criticalServices = @("CcmExec", "BITS", "wuauserv", "Winmgmt")

    foreach ($svcName in $criticalServices) {
        # Get the current service status
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue

        if ($svc) {
            if ($svc.Status -ne "Running") {
                # Service exists but is not running - try to start it
                Write-Host "  Starting $svcName..." -NoNewline

                try {
                    # Attempt to start the service
                    Start-Service -Name $svcName -ErrorAction Stop

                    # Wait a moment for the service to start
                    Start-Sleep -Seconds 2

                    # Refresh the service object to get current status
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
                # Service is already running
                Write-Host "  $svcName is already running" -ForegroundColor Gray
            }
        }
    }

    # =========================================================================
    # Fix 2: Reset WMI repository if issues detected
    # =========================================================================
    # Only attempt WMI repair if diagnostics showed WMI problems
    if ($Script:DiagnosticResults.WMI -and -not $Script:DiagnosticResults.WMI.WMIHealthy) {
        Write-SubHeader "Repairing WMI Repository"
        Write-Host "  Attempting WMI repository repair..."

        try {
            # Stop the WMI service before attempting repair
            Stop-Service -Name Winmgmt -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2

            # Re-register WMI MOF files
            # MOF (Managed Object Format) files define WMI classes
            $wmiPath = "$env:windir\System32\wbem"
            Push-Location $wmiPath

            # Compile the core WMI definition files
            # mofcomp.exe compiles MOF files into the WMI repository
            & "$wmiPath\mofcomp.exe" "$wmiPath\cimwin32.mof" | Out-Null
            & "$wmiPath\mofcomp.exe" "$wmiPath\cimwin32.mfl" | Out-Null

            Pop-Location

            # Restart WMI service
            Start-Service -Name Winmgmt -ErrorAction Stop
            Write-ColorOutput "  WMI repair attempted" "Green"
            $repairsMade++
        } catch {
            Write-ColorOutput "  WMI repair failed: $($_.Exception.Message)" "Red"
        }
    }

    # =========================================================================
    # Fix 3: Trigger machine policy refresh
    # =========================================================================
    # This causes the client to request fresh policies from the MP
    Write-SubHeader "Refreshing Machine Policies"

    try {
        Write-Host "  Triggering Machine Policy Retrieval..." -NoNewline

        # Use the SMS_Client WMI class to trigger a schedule
        # Schedule ID {00000000-0000-0000-0000-000000000021} = Machine Policy Retrieval
        $null = Invoke-WmiMethod -Namespace "root\ccm" -Class "SMS_Client" -Name "TriggerSchedule" -ArgumentList "{00000000-0000-0000-0000-000000000021}" -ErrorAction Stop

        Write-ColorOutput " Triggered!" "Green"
        $repairsMade++
    } catch {
        Write-ColorOutput " Failed: $($_.Exception.Message)" "Yellow"
    }

    try {
        Write-Host "  Triggering Machine Policy Evaluation..." -NoNewline

        # Schedule ID {00000000-0000-0000-0000-000000000022} = Machine Policy Evaluation
        # This evaluates the policies after they're retrieved
        $null = Invoke-WmiMethod -Namespace "root\ccm" -Class "SMS_Client" -Name "TriggerSchedule" -ArgumentList "{00000000-0000-0000-0000-000000000022}" -ErrorAction Stop

        Write-ColorOutput " Triggered!" "Green"
        $repairsMade++
    } catch {
        Write-ColorOutput " Failed: $($_.Exception.Message)" "Yellow"
    }

    # =========================================================================
    # Fix 4: Trigger inventory cycles
    # =========================================================================
    # This causes the client to collect and send inventory data
    Write-SubHeader "Triggering Inventory Cycles"

    try {
        Write-Host "  Triggering Hardware Inventory..." -NoNewline

        # Schedule ID {00000000-0000-0000-0000-000000000001} = Hardware Inventory
        $null = Invoke-WmiMethod -Namespace "root\ccm" -Class "SMS_Client" -Name "TriggerSchedule" -ArgumentList "{00000000-0000-0000-0000-000000000001}" -ErrorAction Stop

        Write-ColorOutput " Triggered!" "Green"
        $repairsMade++
    } catch {
        Write-ColorOutput " Failed: $($_.Exception.Message)" "Yellow"
    }

    try {
        Write-Host "  Triggering Software Inventory..." -NoNewline

        # Schedule ID {00000000-0000-0000-0000-000000000002} = Software Inventory
        $null = Invoke-WmiMethod -Namespace "root\ccm" -Class "SMS_Client" -Name "TriggerSchedule" -ArgumentList "{00000000-0000-0000-0000-000000000002}" -ErrorAction Stop

        Write-ColorOutput " Triggered!" "Green"
        $repairsMade++
    } catch {
        Write-ColorOutput " Failed: $($_.Exception.Message)" "Yellow"
    }

    # =========================================================================
    # Fix 5: Run CCMEval if available
    # =========================================================================
    # CcmEval.exe is the built-in client health evaluation tool
    Write-SubHeader "Running Client Health Evaluation"

    $ccmEvalPath = "$env:windir\CCM\CcmEval.exe"

    if (Test-Path $ccmEvalPath) {
        Write-Host "  Running CcmEval.exe..." -NoNewline

        try {
            # Run CcmEval with /noreboot to prevent automatic restart
            Start-Process -FilePath $ccmEvalPath -ArgumentList "/noreboot" -Wait -NoNewWindow
            Write-ColorOutput " Completed!" "Green"
            $repairsMade++
        } catch {
            Write-ColorOutput " Failed: $($_.Exception.Message)" "Red"
        }
    } else {
        Write-Host "  CcmEval.exe not found, skipping..." -ForegroundColor Gray
    }

    # =========================================================================
    # Fix 6: Clear and rebuild policy if no policies found
    # =========================================================================
    # Only do this if diagnostics showed no policies
    if ($Script:DiagnosticResults.Policies -and -not $Script:DiagnosticResults.Policies.MachinePolicy) {
        Write-SubHeader "Resetting Policy Store"
        Write-Host "  Attempting policy store reset..."

        try {
            # Policy files are stored in this directory
            $policyPath = "$env:windir\CCM\Policy"

            if (Test-Path $policyPath) {
                # Stop the SCCM service before modifying policy files
                Stop-Service -Name CcmExec -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2

                # Remove all policy files
                # This forces the client to download fresh policies
                Get-ChildItem -Path $policyPath -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue

                # Restart the service
                Start-Service -Name CcmExec -ErrorAction Stop
                Start-Sleep -Seconds 5

                # Trigger policy download
                Invoke-WmiMethod -Namespace "root\ccm" -Class "SMS_Client" -Name "TriggerSchedule" -ArgumentList "{00000000-0000-0000-0000-000000000021}" -ErrorAction SilentlyContinue

                Write-ColorOutput "  Policy store reset completed" "Green"
                $repairsMade++
            }
        } catch {
            Write-ColorOutput "  Policy reset failed: $($_.Exception.Message)" "Red"

            # Make sure the service is started even if reset failed
            Start-Service -Name CcmExec -ErrorAction SilentlyContinue
        }
    }

    # =========================================================================
    # Display Summary
    # =========================================================================
    Write-Header "Self-Check Repair Complete"
    Write-Host "  Repairs attempted: $repairsMade"
    Write-Host ""
    Write-ColorOutput "  Please wait a few minutes for changes to take effect." "Yellow"
    Write-ColorOutput "  Run diagnostics again to verify repairs." "Cyan"
}

function Repair-CompleteReinstall {
    <#
    .SYNOPSIS
        Performs complete SCCM client repair/reinstall.

    .DESCRIPTION
        This repair option completely removes the SCCM client and reinstalls it.
        This is the most thorough repair option and fixes issues that targeted
        repairs cannot.

        Steps performed:
        1. Stop all SCCM services
        2. Uninstall the existing client using ccmsetup /uninstall
        3. Clean up remaining files (CCM folders)
        4. Clean up registry keys
        5. Clean up WMI namespaces
        6. Reinstall the client from a discovered or manual source

        This option is best when:
        - The client is severely broken
        - Self-check repairs didn't work
        - WMI repository is corrupted
        - Client files are missing or damaged

        WARNING: This process takes several minutes and the computer may
        lose management capabilities until reinstallation completes.
    #>

    Write-Header "Complete SCCM Agent Repair"
    Write-Host ""
    Write-ColorOutput "  WARNING: This will completely uninstall and reinstall the SCCM client." "Yellow"
    Write-ColorOutput "  This process may take several minutes." "Yellow"
    Write-Host ""

    # =========================================================================
    # Confirm with user before proceeding
    # =========================================================================
    $confirm = Read-Host "  Are you sure you want to proceed? (Y/N)"

    # Check if user confirmed (accepts Y or y)
    if ($confirm -notmatch "^[Yy]") {
        Write-Host "  Repair cancelled."
        return
    }

    Write-Host ""

    # =========================================================================
    # Step 1: Stop SCCM services
    # =========================================================================
    Write-SubHeader "Stopping SCCM Services"

    # Services to stop before uninstall
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

    # =========================================================================
    # Step 2: Uninstall existing client
    # =========================================================================
    Write-SubHeader "Uninstalling SCCM Client"

    # Path to ccmsetup.exe (the installer/uninstaller)
    $ccmSetupPath = "$env:windir\ccmsetup\ccmsetup.exe"

    if (Test-Path $ccmSetupPath) {
        Write-Host "  Running ccmsetup /uninstall..."

        try {
            # Run the uninstaller
            # /uninstall switch removes the SCCM client
            $proc = Start-Process -FilePath $ccmSetupPath -ArgumentList "/uninstall" -Wait -PassThru -NoNewWindow

            # Wait for uninstall to complete (ccmsetup runs in background)
            $timeout = 300  # 5 minutes maximum wait
            $elapsed = 0

            while ((Get-Process -Name "ccmsetup" -ErrorAction SilentlyContinue) -and $elapsed -lt $timeout) {
                # Show progress dots
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

    # =========================================================================
    # Step 3: Clean up remaining files and directories
    # =========================================================================
    Write-SubHeader "Cleaning Up SCCM Files and Registry"

    # Stop any remaining SCCM processes
    Get-Process -Name "Ccm*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3

    # Directories to remove
    # These are the main SCCM client directories
    $dirsToRemove = @(
        "$env:windir\CCM",           # Main client installation directory
        "$env:windir\ccmsetup",      # Client setup files
        "$env:windir\ccmcache",      # Content cache
        "$env:windir\SMSCFG.ini"     # Client configuration file
    )

    foreach ($dir in $dirsToRemove) {
        if (Test-Path $dir) {
            Write-Host "  Removing $dir..." -NoNewline

            try {
                # Force remove the directory and all contents
                Remove-Item -Path $dir -Recurse -Force -ErrorAction Stop
                Write-ColorOutput " Removed" "Green"
            } catch {
                # Directory might be locked by a process
                Write-ColorOutput " Could not remove (may be locked)" "Yellow"
            }
        }
    }

    # =========================================================================
    # Step 4: Clean up registry
    # =========================================================================
    Write-Host "  Cleaning registry..."

    # Registry keys created by SCCM client
    $regKeysToRemove = @(
        "HKLM:\SOFTWARE\Microsoft\CCM",      # Main client configuration
        "HKLM:\SOFTWARE\Microsoft\CCMSetup", # Setup configuration
        "HKLM:\SOFTWARE\Microsoft\SMS"       # Legacy SMS keys
    )

    foreach ($regKey in $regKeysToRemove) {
        if (Test-Path $regKey) {
            try {
                Remove-Item -Path $regKey -Recurse -Force -ErrorAction SilentlyContinue
            } catch {
                # Ignore registry removal errors
            }
        }
    }

    Write-ColorOutput "  Registry cleaned" "Green"

    # =========================================================================
    # Step 5: Clean up WMI namespaces
    # =========================================================================
    Write-Host "  Cleaning WMI namespaces..."

    try {
        # Remove the CCM namespace from WMI
        # This ensures a clean state for the new installation
        Get-WmiObject -Query "SELECT * FROM __Namespace WHERE Name='ccm'" -Namespace "root" -ErrorAction SilentlyContinue |
            Remove-WmiObject -ErrorAction SilentlyContinue
    } catch {
        # Ignore WMI removal errors
    }

    Write-ColorOutput "  WMI namespaces cleaned" "Green"

    # =========================================================================
    # Step 6: Reinstall the client
    # =========================================================================
    Write-SubHeader "Reinstalling SCCM Client"

    # We need to find ccmsetup.exe to reinstall
    $ccmsetupSource = $null

    # Build a list of possible locations to find ccmsetup.exe
    $possibleSources = @(
        # Local copy (might still exist if uninstall was incomplete)
        "$env:windir\ccmsetup\ccmsetup.exe",
        # Network share on the Management Point server
        "\\$($Script:SCCMServerInfo.ManagementPoint)\SMS_$($Script:SCCMServerInfo.SiteCode)\Client\ccmsetup.exe",
        # Alternative network share format
        "\\$($Script:SCCMServerInfo.ManagementPoint)\ccmsetup$\ccmsetup.exe"
    )

    # Also check common domain network locations
    $domain = $env:USERDNSDOMAIN
    if ($domain) {
        # NETLOGON share (common location for login scripts and tools)
        $possibleSources += "\\$domain\NETLOGON\ccmsetup.exe"
        # SYSVOL share (another common location)
        $possibleSources += "\\$domain\SYSVOL\$domain\scripts\ccmsetup.exe"
    }

    # Try each possible source until we find one that exists
    foreach ($source in $possibleSources) {
        if ($source -and (Test-Path $source -ErrorAction SilentlyContinue)) {
            $ccmsetupSource = $source
            break
        }
    }

    # If we couldn't find ccmsetup automatically, ask the user
    if (-not $ccmsetupSource) {
        Write-ColorOutput "  ERROR: Could not locate ccmsetup.exe" "Red"
        Write-Host ""
        Write-Host "  Please provide the path to ccmsetup.exe or the SCCM server share."
        $manualPath = Read-Host "  Enter path (or press Enter to skip)"

        if ($manualPath -and (Test-Path $manualPath)) {
            $ccmsetupSource = $manualPath
        }
    }

    # If we have a source, proceed with installation
    if ($ccmsetupSource) {
        Write-Host "  Using source: $ccmsetupSource"
        Write-Host "  Installing SCCM client..."

        # Build the installation command line arguments
        # /source: specifies where to get the installation files from
        $installArgs = "/source:$([System.IO.Path]::GetDirectoryName($ccmsetupSource))"

        # /mp: specifies the Management Point to contact
        if ($Script:SCCMServerInfo.ManagementPoint) {
            $installArgs += " /mp:$($Script:SCCMServerInfo.ManagementPoint)"
        }

        # SMSSITECODE= specifies the site code to assign to
        if ($Script:SCCMServerInfo.SiteCode) {
            $installArgs += " SMSSITECODE=$($Script:SCCMServerInfo.SiteCode)"
        }

        # /forceinstall bypasses some checks and forces installation
        $installArgs += " /forceinstall"

        Write-Host "  Arguments: $installArgs" -ForegroundColor Gray

        try {
            # Copy ccmsetup to local temp first (in case network share becomes unavailable)
            $localCcmsetup = "$env:TEMP\ccmsetup.exe"
            Copy-Item -Path $ccmsetupSource -Destination $localCcmsetup -Force

            # Run the installer
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
        # No source found and user didn't provide one
        Write-ColorOutput "  Skipping installation - no source found" "Yellow"
        Write-Host ""
        Write-Host "  To manually install, run:"
        Write-Host "  ccmsetup.exe /mp:<ManagementPointFQDN> SMSSITECODE=<SiteCode>"
    }

    # =========================================================================
    # Display completion message
    # =========================================================================
    Write-Header "Complete Repair Process Finished"
    Write-ColorOutput "  Please wait 10-15 minutes for the client to fully install and register." "Yellow"
}

# ============================================================================
# MENU AND MAIN EXECUTION
# ============================================================================
# This section handles the user interface - displaying menus and processing
# user choices.

function Show-MainMenu {
    <#
    .SYNOPSIS
        Displays the main menu and handles user selection.

    .DESCRIPTION
        This function displays an interactive menu that allows users to:
        1. Run diagnostics only (just view the health status)
        2. Run self-check and fix (targeted repairs)
        3. Run complete repair (full reinstall)
        4. Exit the script

        The menu runs in a loop until the user chooses to exit.
    #>

    # Loop until user chooses to exit
    while ($true) {
        Write-Host ""
        Write-Header "SCCM Agent Repair Options"
        Write-Host ""
        Write-Host "  1. Run Diagnostics Only"
        Write-Host "  2. Self-Check and Fix (Targeted Repairs)"
        Write-Host "  3. Complete SCCM Agent Repair (Uninstall/Reinstall)"
        Write-Host "  4. Exit"
        Write-Host ""

        # Get user's choice
        $choice = Read-Host "  Enter your choice (1-4)"

        # Process the choice using a switch statement
        switch ($choice) {
            "1" {
                # -------------------------------------------------------------------------
                # Option 1: Run Diagnostics Only
                # -------------------------------------------------------------------------
                # Run all diagnostic tests and display results
                Run-AllDiagnostics

                # After diagnostics, offer repair options
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
                    default {
                        # Any other choice returns to main menu
                    }
                }
            }
            "2" {
                # -------------------------------------------------------------------------
                # Option 2: Self-Check and Fix
                # -------------------------------------------------------------------------
                Write-Host ""
                Write-Host "  Running diagnostics to identify issues..."

                # Run diagnostics first to populate the results
                # These results are used by the repair function to determine what to fix
                $null = Run-AllDiagnostics

                # Confirm before proceeding with repairs
                Write-Host ""
                $confirm = Read-Host "  Proceed with Self-Check and Fix? (Y/N)"

                if ($confirm -match "^[Yy]") {
                    Repair-SelfCheckAndFix
                }
            }
            "3" {
                # -------------------------------------------------------------------------
                # Option 3: Complete Repair
                # -------------------------------------------------------------------------
                Write-Host ""
                Write-Host "  Running diagnostics to gather system information..."

                # Run diagnostics to discover SCCM server info needed for reinstall
                $null = Run-AllDiagnostics

                # The complete repair function has its own confirmation prompt
                Repair-CompleteReinstall
            }
            "4" {
                # -------------------------------------------------------------------------
                # Option 4: Exit
                # -------------------------------------------------------------------------
                Write-Host ""
                Write-ColorOutput "  Thank you for using SCCM Agent Diagnostic Tool!" "Cyan"
                Write-Host ""
                return  # Exit the function (and the while loop)
            }
            default {
                # Invalid choice - show error and loop back to menu
                Write-ColorOutput "  Invalid choice. Please enter 1-4." "Red"
            }
        }
    }
}

# ============================================================================
# SCRIPT ENTRY POINT
# ============================================================================
# This is where the script begins execution when run.

# Clear the screen for a clean start
Clear-Host

# -------------------------------------------------------------------------
# Check for Administrator privileges
# -------------------------------------------------------------------------
# Many SCCM operations require elevated privileges (accessing system folders,
# services, registry, WMI, etc.)
if (-not (Test-AdminPrivileges)) {
    Write-ColorOutput "ERROR: This script must be run as Administrator!" "Red"
    Write-Host ""
    Write-Host "Please right-click PowerShell and select 'Run as Administrator'"
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

# -------------------------------------------------------------------------
# Check PowerShell version
# -------------------------------------------------------------------------
# This script requires PowerShell 5.0 or later
# (but NOT PowerShell 7 - we're using PS5-compatible syntax)
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-ColorOutput "ERROR: This script requires PowerShell 5.0 or later." "Red"
    Write-Host "Current version: $($PSVersionTable.PSVersion)"
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

# -------------------------------------------------------------------------
# Display welcome banner
# -------------------------------------------------------------------------
Write-Host ""
Write-ColorOutput "  ============================================================" "Cyan"
Write-ColorOutput "       SCCM Agent Diagnostic and Repair Tool                  " "Cyan"
Write-ColorOutput "  ============================================================" "Cyan"
Write-Host ""
Write-Host "  This tool will diagnose your SCCM client agent and offer"
Write-Host "  repair options if issues are detected."
Write-Host ""

# -------------------------------------------------------------------------
# Run the main menu
# -------------------------------------------------------------------------
# This is the main loop of the script - it continues until user exits
Show-MainMenu

# End of script
