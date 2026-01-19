# Get-InactiveDevices.ps1
# Exports devices that logged on recently but haven't communicated with SCCM

# Define date thresholds
$LogonThreshold = (Get-Date).AddDays(-7)    # Logged on within last 7 days
$CommThreshold = 14                          # Days since last SCCM communication

# Query all devices from SCCM with required properties
# Using Get-CMDevice with -Fast to improve performance (skips lazy properties)
$Devices = Get-CMDevice -Fast | Where-Object {
    # Filter 1: Last logon timestamp exists and is within last 7 days
    $_.LastLogonTimestamp -and $_.LastLogonTimestamp -ge $LogonThreshold -and
    # Filter 2: Client activity is Inactive (0 = Inactive, 1 = Active)
    $_.ClientActiveStatus -eq 0 -and
    # Filter 3: Days since last communication is 14 or more (null treated as very old)
    ($_.CNLastOnlineTime -eq $null -or ((Get-Date) - $_.CNLastOnlineTime).Days -ge $CommThreshold)
}

# Select relevant columns and export to CSV
$Devices | Select-Object `
    Name,                      # Device name
    LastLogonUserName,         # Last logged on user
    LastLogonTimestamp,        # When user last logged on
    CNLastOnlineTime,          # Last SCCM communication time
    @{N='DaysSinceComm';E={if($_.CNLastOnlineTime){((Get-Date)-$_.CNLastOnlineTime).Days}else{'Never'}}},
    ClientActiveStatus,        # 0=Inactive, 1=Active
    ClientVersion,             # SCCM client version
    OperatingSystemNameandVersion |
Export-Csv -Path "C:\Temp\InactiveDevices_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation

# Output count for confirmation
Write-Host "Exported $($Devices.Count) inactive devices to C:\Temp\InactiveDevices_$(Get-Date -Format 'yyyyMMdd').csv"
