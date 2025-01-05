# Require admin privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires admin privileges. Please run as Administrator."
    Exit
}

# Global variables
$script:logFile = "$(Get-Date -Format 'yyyy-MM-dd')-AdminTool.log"
$script:currentPath = Split-Path -Parent $MyInvocation.MyCommand.Path

# Import CVE Handler Module
Import-Module $script:currentPath\Modules\CVEHandler.psm1

# Color definitions
$colors = @{
    Title = [System.ConsoleColor]::Cyan
    Menu = [System.ConsoleColor]::White
    Success = [System.ConsoleColor]::Green
    Error = [System.ConsoleColor]::Red
    Info = [System.ConsoleColor]::Yellow
    SubMenu = [System.ConsoleColor]::Magenta
    Warning = [System.ConsoleColor]::DarkYellow
    Border = [System.ConsoleColor]::Blue
    Header = [System.ConsoleColor]::Cyan
    Footer = [System.ConsoleColor]::DarkCyan
}

# Menu definitions
$mainMenu = @{
    1 = @{ Name = "Network Tools"; Function = "Show-NetworkMenu" }
    2 = @{ Name = "System Tools"; Function = "Show-SystemMenu" }
    3 = @{ Name = "Diagnostics"; Function = "Show-DiagnosticsMenu" }
    4 = @{ Name = "Service Management"; Function = "Show-ServiceMenu" }
    5 = @{ Name = "User Management"; Function = "Show-UserMenu" }
    6 = @{ Name = "Windows Update"; Function = "Show-UpdateMenu" }
    7 = @{ Name = "Advanced Net Tools"; Function = "Show-AdvancedNetMenu" }
    8 = @{ Name = "Processes"; Function = "Show-ProcessesMenu" }
    9 = @{ Name = "Scheduled Tasks"; Function = "Show-ScheduledTasksMenu" }
    10 = @{ Name = "System Maintenance"; Function = "Show-MaintenanceMenu" }
    11 = @{ Name = "Network Diagnostics"; Function = "Show-NetDiagMenu" }
    12 = @{ Name = "Security Tools"; Function = "Show-SecurityMenu" }
    13 = @{ Name = "Performance Tools"; Function = "Show-PerformanceMenu" }
    14 = @{ Name = "Printer Management"; Function = "Show-PrinterMenu" }
    15 = @{ Name = "App Management"; Function = "Show-AppMenu" }
    16 = @{ Name = "Hardware Info"; Function = "Show-HardwareMenu" }
    Q = @{ Name = "Quit"; Function = "Exit-Script" }
}

function Write-Log {
    param($Message)
    $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    Add-Content -Path "$script:currentPath\$script:logFile" -Value $logEntry
}

function Show-Header {
    Clear-Host
    $windowWidth = $host.UI.RawUI.WindowSize.Width
    
    # Top border
    $line = "=" * [math]::Min(80, $windowWidth - 4)
    $padding = [math]::Floor(($windowWidth - $line.Length) / 2)
    Write-Host "`n"
    Write-Host (" " * $padding) -NoNewline
    Write-Host $line -ForegroundColor $colors.Border
    
    # Title
    $title = "Windows Admin Tool"
    $padding = [math]::Floor(($windowWidth - $title.Length) / 2)
    Write-Host (" " * $padding) -NoNewline
    Write-Host $title -ForegroundColor $colors.Title
    
    # Subtitle with version
    $version = "v1.0"
    $subtitle = "System Management Tool $version"
    $padding = [math]::Floor(($windowWidth - $subtitle.Length) / 2)
    Write-Host (" " * $padding) -NoNewline
    Write-Host $subtitle -ForegroundColor $colors.Info
    
    # Author
    $authorText = "by Birger Hohmeier"
    $padding = [math]::Floor(($windowWidth - $authorText.Length) / 2)
    Write-Host (" " * $padding) -NoNewline
    Write-Host $authorText -ForegroundColor $colors.SubMenu
    
    # Date
    $dateText = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $padding = [math]::Floor(($windowWidth - $dateText.Length) / 2)
    Write-Host (" " * $padding) -NoNewline
    Write-Host $dateText -ForegroundColor $colors.Info
    
    # Bottom border
    $padding = [math]::Floor(($windowWidth - $line.Length) / 2)
    Write-Host (" " * $padding) -NoNewline
    Write-Host $line -ForegroundColor $colors.Border
    Write-Host "`n"
}

function Show-Footer {
    $windowWidth = $host.UI.RawUI.WindowSize.Width
    $line = "=" * [math]::Min(80, $windowWidth - 4)
    $padding = [math]::Floor(($windowWidth - $line.Length) / 2)
    
    Write-Host "`n"
    Write-Host (" " * $padding) -NoNewline
    Write-Host $line -ForegroundColor $colors.Border
    
    $footerText = "Navigation: [UP/DOWN] Move  [Enter] Select  [B] Back  [Q] Quit"
    $padding = [math]::Floor(($windowWidth - $footerText.Length) / 2)
    Write-Host (" " * $padding) -NoNewline
    Write-Host $footerText -ForegroundColor $colors.Footer
}

# Neue Funktionen für interaktive Elemente
function Show-LoadingAnimation {
    param([string]$Message)
    $chars = '|', '/', '-', '\'
    $counter = 0
    $job = Start-Job -ScriptBlock { Start-Sleep -Seconds 2 }
    
    while (($job.State -eq 'Running')) {
        Write-Host "`r$Message [ $($chars[$counter % $chars.Length]) ]" -NoNewline -ForegroundColor $colors.Info
        Start-Sleep -Milliseconds 100
        $counter++
    }
    Remove-Job -Job $job
    Write-Host "`r$Message [ Done ]" -ForegroundColor $colors.Success
}

function Show-ProgressBar {
    param (
        [int]$Percent,
        [string]$Activity,
        [ConsoleColor]$BarColor = 'Green'
    )
    $width = $host.UI.RawUI.WindowSize.Width - 20
    $completed = [math]::Floor($width * ($Percent / 100))
    $remaining = $width - $completed
    
    Write-Host "`r[$Activity] " -NoNewline
    Write-Host "$("■" * $completed)" -NoNewline -ForegroundColor $BarColor
    Write-Host "$("-" * $remaining)" -NoNewline -ForegroundColor DarkGray
    Write-Host "] $Percent%" -NoNewline
}

# Neue Hilfsfunktion für einheitliche Benutzerhinweise
function Show-NavigationHint {
    Write-Host "`n===============================================" -ForegroundColor $colors.Border
    Write-Host "Press [Enter] to continue, [B] to go back to menu" -ForegroundColor $colors.Info
    Write-Host "===============================================" -ForegroundColor $colors.Border
    $key = Read-Host
    if ($key -eq 'B' -or $key -eq 'b') {
        return $true  # Signal zum Zurückgehen
    }
    return $false
}

# Modifiziere Show-Menu für interaktives Highlighting
function Show-Menu {
    param (
        [string]$Title = "Windows Admin Tool",
        [hashtable]$MenuItems
    )
    
    Show-Header
    
    $windowWidth = $host.UI.RawUI.WindowSize.Width
    $padding = [math]::Floor(($windowWidth - $Title.Length) / 2)
    Write-Host (" " * $padding) -NoNewline
    Write-Host $Title -ForegroundColor $colors.Title
    Write-Host "`n"
    
    $currentSelection = 0
    $menuArray = @($MenuItems.Keys | Sort-Object)
    
    while ($true) {
        $pos = [System.Console]::CursorTop
        for ($i = 0; $i -lt $menuArray.Count; $i++) {
            $key = $menuArray[$i]
            $menuText = "[$key] $($MenuItems[$key].Name)"
            $padding = [math]::Floor(($windowWidth - $menuText.Length) / 2)
            
            if ($i -eq $currentSelection) {
                Write-Host (" " * $padding) -NoNewline
                Write-Host ">" -NoNewline -ForegroundColor $colors.Success
                Write-Host $menuText -ForegroundColor $colors.Title
            } else {
                Write-Host (" " * ($padding + 1)) -NoNewline
                Write-Host $menuText -ForegroundColor $colors.Menu
            }
        }
        
        $key = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        
        switch ($key.VirtualKeyCode) {
            38 { # Up arrow
                $currentSelection--
                if ($currentSelection -lt 0) { $currentSelection = $menuArray.Count - 1 }
            }
            40 { # Down arrow
                $currentSelection++
                if ($currentSelection -ge $menuArray.Count) { $currentSelection = 0 }
            }
            # Ziffern 1-9 (VirtualKeyCodes 49-57)
            {$_ -ge 49 -and $_ -le 57} {
                $number = $_ - 48  # Konvertiere VirtualKeyCode zu Ziffer
                if ($MenuItems.ContainsKey($number)) {
                    Clear-Host
                    Show-LoadingAnimation "Loading $($MenuItems[$number].Name)"
                    & $MenuItems[$number].Function
                    return
                }
            }
            # Ziffer 0 (VirtualKeyCode 48)
            48 {
                if ($MenuItems.ContainsKey(10)) {  # Für Menüpunkt 10
                    Clear-Host
                    Show-LoadingAnimation "Loading $($MenuItems[10].Name)"
                    & $MenuItems[10].Function
                    return
                }
            }
            # Q Taste
            81 {  # Q key
                if ($MenuItems.ContainsKey("Q")) {
                    Clear-Host
                    & $MenuItems["Q"].Function
                    return
                }
            }
            # B Taste
            66 {  # B key
                if ($MenuItems.ContainsKey("B")) {
                    Clear-Host
                    & $MenuItems["B"].Function
                    return
                }
            }
            13 { # Enter
                $selection = $menuArray[$currentSelection]
                if ($MenuItems.ContainsKey($selection)) {
                    Clear-Host
                    Show-LoadingAnimation "Loading $($MenuItems[$selection].Name)"
                    & $MenuItems[$selection].Function
                    return
                }
            }
        }
        
        [System.Console]::SetCursorPosition(0, $pos)
    }
}

function Show-NetworkMenu {
    $networkMenu = @{
        1 = @{ Name = "IP Configuration"; Function = "Get-IPConfig" }
        2 = @{ Name = "DNS Cache"; Function = "Get-DNSCache" }
        3 = @{ Name = "Test Connection"; Function = "Test-NetworkConnection" }
        4 = @{ Name = "Public IP Info"; Function = "Get-PublicIPInfo" }
        5 = @{ Name = "DNS Lookup"; Function = "Get-DNSInfo" }
        6 = @{ Name = "Check Website Status"; Function = "Test-WebsiteStatus" }
        B = @{ Name = "Back to Main Menu"; Function = { Show-Menu -MenuItems $mainMenu } }
    }
    Show-Menu -Title "Network Tools" -MenuItems $networkMenu
}

# Neue Funktion für Public IP Info
function Get-PublicIPInfo {
    Clear-Host
    Write-Host "=== Public IP Information ===" -ForegroundColor $colors.Title
    Write-Host "Retrieving public IP information from ipinfo.io..." -ForegroundColor $colors.Info
    
    try {
        $ipInfo = Invoke-RestMethod -Uri "https://ipinfo.io/json"
        
        $info = @(
            "IP Address: $($ipInfo.ip)",
            "Hostname: $($ipInfo.hostname)",
            "City: $($ipInfo.city)",
            "Region: $($ipInfo.region)",
            "Country: $($ipInfo.country)",
            "Location: $($ipInfo.loc)",
            "ISP: $($ipInfo.org)",
            "Timezone: $($ipInfo.timezone)"
        )
        
        Write-Host "`nResults:" -ForegroundColor $colors.Success
        foreach ($line in $info) {
            Write-Host $line -ForegroundColor $colors.Info
        }
        
        Write-Log "Executed: Public IP lookup via ipinfo.io"
    }
    catch {
        Write-Host "Error retrieving public IP information: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    
    if (Show-NavigationHint) {
        Show-NetworkMenu
    }
}

function Get-DNSInfo {
    Clear-Host
    Write-Host "=== DNS Information Tool ===" -ForegroundColor $colors.Title
    
    $domain = Read-Host "Enter domain name (e.g. google.com)"
    
    Write-Host "`nQuerying DNS records..." -ForegroundColor $colors.Info
    
    try {
        # A Record
        Write-Host "`nA Records:" -ForegroundColor $colors.SubMenu
        Resolve-DnsName -Name $domain -Type A | Format-Table Name, IP4Address -AutoSize

        # MX Record
        Write-Host "`nMX Records:" -ForegroundColor $colors.SubMenu
        Resolve-DnsName -Name $domain -Type MX | Format-Table NameExchange, Preference -AutoSize

        # TXT Record
        Write-Host "`nTXT Records:" -ForegroundColor $colors.SubMenu
        Resolve-DnsName -Name $domain -Type TXT | Format-Table Strings -AutoSize

        Write-Log "Executed: DNS lookup for $domain"
    }
    catch {
        Write-Host "Error querying DNS: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    
    if (Show-NavigationHint) {
        Show-NetworkMenu
    }
}

function Test-WebsiteStatus {
    Clear-Host
    Write-Host "=== Website Status Check ===" -ForegroundColor $colors.Title
    
    $website = Read-Host "Enter website URL (e.g. https://google.com)"
    
    Write-Host "`nTesting website status..." -ForegroundColor $colors.Info
    
    try {
        $request = [System.Net.WebRequest]::Create($website)
        $request.Timeout = 5000
        $response = $request.GetResponse()
        
        Write-Host "`nResults:" -ForegroundColor $colors.Success
        Write-Host "Status Code: $([int]$response.StatusCode) - $($response.StatusDescription)"
        Write-Host "Server: $($response.Server)"
        Write-Host "Content Type: $($response.ContentType)"
        Write-Host "Last Modified: $($response.LastModified)"
        
        $response.Close()
        Write-Log "Executed: Website status check for $website"
    }
    catch [System.Net.WebException] {
        Write-Host "Website error: $($_.Exception.Message)" -ForegroundColor $colors.Error
        if ($_.Exception.Response) {
            Write-Host "Status Code: $([int]$_.Exception.Response.StatusCode) - $($_.Exception.Response.StatusDescription)"
        }
    }
    catch {
        Write-Host "Error checking website: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    
    if (Show-NavigationHint) {
        Show-NetworkMenu
    }
}

function Show-SystemMenu {
    $systemMenu = @{
        1 = @{ Name = "System Information"; Function = "Get-SystemInfo" }
        2 = @{ Name = "Disk Health"; Function = "Test-DiskHealth" }
        3 = @{ Name = "Memory Usage"; Function = "Get-MemoryStatus" }
        B = @{ Name = "Back to Main Menu"; Function = { Show-Menu -MenuItems $mainMenu } }
    }
    Show-Menu -Title "System Tools" -MenuItems $systemMenu
}

function Show-DiagnosticsMenu {
    $diagMenu = @{
        1 = @{ Name = "View Event Logs"; Function = "View-EventLogs" }
        2 = @{ Name = "Clear Event Logs"; Function = "Clear-EventLogs" }
        3 = @{ Name = "Reboot System"; Function = "Invoke-Reboot" }
        B = @{ Name = "Back to Main Menu"; Function = { Show-Menu -MenuItems $mainMenu } }
    }
    Show-Menu -Title "Diagnostics" -MenuItems $diagMenu
}

function Show-ServiceMenu {
    $serviceMenu = @{
        1 = @{ Name = "List Services"; Function = "List-AllServices" }
        2 = @{ Name = "Restart a Service"; Function = "Restart-ServiceByName" }
        B = @{ Name = "Back to Main Menu"; Function = { Show-Menu -MenuItems $mainMenu } }
    }
    Show-Menu -Title "Service Management" -MenuItems $serviceMenu
}

function Show-UserMenu {
    $umenu = @{
        1 = @{ Name = "List Local Users"; Function = "List-LocalUsers" }
        2 = @{ Name = "Create Local User"; Function = "Create-LocalUser" }
        3 = @{ Name = "Remove Local User"; Function = "Remove-LocalUser" }
        B = @{ Name = "Back"; Function = { Show-Menu -MenuItems $mainMenu } }
    }
    Show-Menu -Title "User Management" -MenuItems $umenu
}

function Show-UpdateMenu {
    $updMenu = @{
        1 = @{ Name = "Check for Updates"; Function = "Check-SystemUpdates" }
        2 = @{ Name = "Install Updates"; Function = "Install-SystemUpdates" }
        B = @{ Name = "Back"; Function = { Show-Menu -MenuItems $mainMenu } }
    }
    Show-Menu -Title "Windows Update" -MenuItems $updMenu
}

function Show-AdvancedNetMenu {
    $advNetMenu = @{
        1 = @{ Name = "NetStat Summary"; Function = "Get-NetStat" }
        2 = @{ Name = "Traceroute"; Function = "Invoke-Traceroute" }
        3 = @{ Name = "Flush DNS Cache"; Function = "Flush-DNS" }
        B = @{ Name = "Back to Main"; Function = { Show-Menu -MenuItems $mainMenu } }
    }
    Show-Menu -Title "Advanced Network Tools" -MenuItems $advNetMenu
}

function Show-ProcessesMenu {
    $procMenu = @{
        1 = @{ Name = "List Processes"; Function = "List-Processes" }
        2 = @{ Name = "Kill Process"; Function = "Kill-ProcessByName" }
        B = @{ Name = "Back to Main"; Function = { Show-Menu -MenuItems $mainMenu } }
    }
    Show-Menu -Title "Process Management" -MenuItems $procMenu
}

function Show-ScheduledTasksMenu {
    $taskMenu = @{
        1 = @{ Name = "List Scheduled Tasks"; Function = "List-ScheduledTasks" }
        2 = @{ Name = "Run Task Now"; Function = "Run-ScheduledTask" }
        B = @{ Name = "Back to Main"; Function = { Show-Menu -MenuItems $mainMenu } }
    }
    Show-Menu -Title "Scheduled Tasks" -MenuItems $taskMenu
}

# Network Functions
function Get-IPConfig {
    Clear-Host
    Write-Host "=== IP Configuration ===" -ForegroundColor $colors.Title
    Write-Host "Retrieving IP Configuration..." -ForegroundColor $colors.Info
    $result = ipconfig /all
    Write-Log "Executed: ipconfig /all"
    $result | Out-Host
    
    if (Show-NavigationHint) {
        Show-NetworkMenu
    }
}

function Get-DNSCache {
    Write-Host "Retrieving DNS Cache..." -ForegroundColor $colors.Info
    $result = ipconfig /displaydns
    Write-Log "Executed: ipconfig /displaydns"
    $result | Out-Host
    Read-Host "Press Enter to continue"
    Show-NetworkMenu
}

function Test-NetworkConnection {
    $target = Read-Host "Enter hostname or IP"
    Write-Host "Testing connection to $target..." -ForegroundColor $colors.Info
    $result = Test-NetConnection -ComputerName $target
    Write-Log "Executed: Test-NetConnection to $target"
    $result | Out-Host
    Read-Host "Press Enter to continue"
    Show-NetworkMenu
}

# System Functions
function Get-SystemInfo {
    Show-Header
    Write-Host "System Information" -ForegroundColor $colors.Title
    Write-Host "================" -ForegroundColor $colors.Border
    
    $steps = @(
        @{ Activity = "Checking OS"; Action = { Get-CimInstance -ClassName Win32_OperatingSystem } },
        @{ Activity = "Checking CPU"; Action = { Get-CimInstance -ClassName Win32_Processor } },
        @{ Activity = "Checking Memory"; Action = { Get-CimInstance -ClassName Win32_ComputerSystem } },
        @{ Activity = "Checking Disk"; Action = { Get-Volume } }
    )
    
    $results = @{}
    $stepCount = $steps.Count
    
    for ($i = 0; $i -lt $stepCount; $i++) {
        $percent = [math]::Floor(($i / $stepCount) * 100)
        Show-ProgressBar -Percent $percent -Activity $steps[$i].Activity
        $results[$steps[$i].Activity] = & $steps[$i].Action
        Start-Sleep -Milliseconds 500
    }
    
    Show-ProgressBar -Percent 100 -Activity "Complete"
    Write-Host "`n"
    
    # Zeige Ergebnisse mit korrigierter String-Formatierung
    foreach ($key in $results.Keys) {
        Write-Host "`n$($key):" -ForegroundColor $colors.SubMenu
        $results[$key] | Format-List
    }
    
    Write-Log "Executed: Enhanced System Information"
    Read-Host "`nPress Enter to continue"
    Show-SystemMenu
}

function Test-DiskHealth {
    Write-Host "Checking Disk Health..." -ForegroundColor $colors.Info
    $result = Get-Volume | Where-Object { $_.DriveLetter } | 
        Select-Object DriveLetter, FileSystemLabel, FileSystem, 
        @{N='Size(GB)';E={[math]::Round($_.Size/1GB,2)}}, 
        @{N='FreeSpace(GB)';E={[math]::Round($_.SizeRemaining/1GB,2)}}
    Write-Log "Executed: Disk Health Check"
    $result | Format-Table | Out-Host
    Read-Host "Press Enter to continue"
    Show-SystemMenu
}

function Get-MemoryStatus {
    Write-Host "Retrieving Memory Status..." -ForegroundColor $colors.Info
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $totalRam = [math]::Round($computerSystem.TotalPhysicalMemory/1GB, 2)
    $freeRam = [math]::Round($os.FreePhysicalMemory/1MB, 2)
    $usedRam = $totalRam - $freeRam
    
    Write-Host "Total RAM: $totalRam GB"
    Write-Host "Used RAM: $usedRam GB"
    Write-Host "Free RAM: $freeRam GB"
    
    Write-Log "Executed: Memory Status Check"
    Read-Host "Press Enter to continue"
    Show-SystemMenu
}

function View-EventLogs {
    Write-Host "Viewing System Event Logs..." -ForegroundColor $colors.Info
    $logs = Get-EventLog -LogName System -Newest 20
    Write-Log "Executed: Get-EventLog (System)"
    $logs | Out-Host
    Read-Host "Press Enter to continue"
    Show-DiagnosticsMenu
}

function Clear-EventLogs {
    Write-Host "Clearing System Event Logs..." -ForegroundColor $colors.Warning
    Clear-EventLog -LogName System
    Write-Log "Executed: Clear-EventLog (System)"
    Write-Host "System Event Log cleared!" -ForegroundColor $colors.Success
    Read-Host "Press Enter to continue"
    Show-DiagnosticsMenu
}

function Invoke-Reboot {
    Write-Host "System will reboot now..." -ForegroundColor $colors.Warning
    Write-Log "Executed: Restart-Computer"
    Restart-Computer -Force
}

function List-AllServices {
    Write-Host "Listing all services..." -ForegroundColor $colors.Info
    $services = Get-Service
    Write-Log "Executed: Get-Service"
    $services | Out-Host
    Read-Host "Press Enter to continue"
    Show-ServiceMenu
}

function Restart-ServiceByName {
    $serviceName = Read-Host "Enter service name to restart"
    Write-Host "Restarting $serviceName..." -ForegroundColor $colors.Info
    Restart-Service -Name $serviceName -Force
    Write-Log "Executed: Restart-Service $serviceName"
    Read-Host "Press Enter to continue"
    Show-ServiceMenu
}

function List-LocalUsers {
    Write-Host "Listing local users..." -ForegroundColor $colors.Info
    $users = Get-LocalUser
    Write-Log "Executed: Get-LocalUser"
    $users | Out-Host
    Read-Host "Press Enter to continue"
    Show-UserMenu
}

function Create-LocalUser {
    $name = Read-Host "Enter username"
    $pass = Read-Host "Enter password" -AsSecureString
    try {
        New-LocalUser -Name $name -Password $pass -FullName $name -UserMayNotChangePassword -PasswordNeverExpires
        Write-Log "Created user: $name"
        Write-Host "User $name created successfully" -ForegroundColor $colors.Success
    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    Read-Host "Press Enter to continue"
    Show-UserMenu
}

function Remove-LocalUser {
    $name = Read-Host "Enter username"
    try {
        Remove-LocalUser -Name $name
        Write-Log "Removed user: $name"
        Write-Host "User $name removed" -ForegroundColor $colors.Success
    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    Read-Host "Press Enter to continue"
    Show-UserMenu
}

function Check-SystemUpdates {
    Write-Host "Checking for Windows updates..." -ForegroundColor $colors.Info
    try {
        # Prüfe ob das Modul installiert ist
        if (!(Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Write-Host "Installing PSWindowsUpdate module..." -ForegroundColor $colors.Warning
            Install-Module PSWindowsUpdate -Force
            Import-Module PSWindowsUpdate
        }
        
        Write-Host "Searching for updates... (this may take a few minutes)" -ForegroundColor $colors.Info
        $updates = Get-WindowsUpdate
        
        if ($updates.Count -eq 0) {
            Write-Host "No updates found." -ForegroundColor $colors.Success
        } else {
            Write-Host "`nFound $($updates.Count) updates:" -ForegroundColor $colors.Warning
            $updates | Select-Object Title, KB, Size | Format-Table -AutoSize
        }
        
        Write-Log "Executed: Get-WindowsUpdate"
    } catch {
        Write-Host "Error checking updates: $($_.Exception.Message)" -ForegroundColor $colors.Error
        Write-Host "Try running 'Install-Module PSWindowsUpdate' manually as administrator" -ForegroundColor $colors.Warning
    }
    Read-Host "Press Enter to continue"
    Show-UpdateMenu
}

function Install-SystemUpdates {
    Write-Host "Installing Windows updates..." -ForegroundColor $colors.Warning
    try {
        if (!(Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Write-Host "PSWindowsUpdate module not found. Please run Check for Updates first." -ForegroundColor $colors.Error
            return
        }
        
        Write-Host "Starting update installation... (this may take a while)" -ForegroundColor $colors.Info
        $installResult = Install-WindowsUpdate -AcceptAll -AutoReboot:$false
        
        Write-Host "`nInstallation Results:" -ForegroundColor $colors.Success
        $installResult | Select-Object Title, Result | Format-Table -AutoSize
        
        Write-Log "Executed: Install-WindowsUpdate"
    } catch {
        Write-Host "Error installing updates: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    Read-Host "Press Enter to continue"
    Show-UpdateMenu
}

function Get-NetStat {
    Write-Host "Displaying NetStat summary..." -ForegroundColor $colors.Info
    $result = netstat -ano
    Write-Log "Executed: netstat -ano"
    $result | Out-Host
    Read-Host "Press Enter to continue"
    Show-AdvancedNetMenu
}

function Invoke-Traceroute {
    $target = Read-Host "Enter hostname or IP"
    Write-Host "Running traceroute to $target..." -ForegroundColor $colors.Info
    $result = tracert $target
    Write-Log "Executed: tracert to $target"
    $result | Out-Host
    Read-Host "Press Enter to continue"
    Show-AdvancedNetMenu
}

function Flush-DNS {
    Write-Host "Flushing DNS cache..." -ForegroundColor $colors.Warning
    ipconfig /flushdns | Out-Null
    Write-Log "Executed: ipconfig /flushdns"
    Write-Host "DNS cache cleared." -ForegroundColor $colors.Success
    Read-Host "Press Enter to continue"
    Show-AdvancedNetMenu
}

function List-Processes {
    Clear-Host
    Write-Host "=== Process List ===" -ForegroundColor $colors.Title
    Write-Host "Listing running processes..." -ForegroundColor $colors.Info
    $procs = Get-Process
    Write-Log "Executed: Get-Process"
    $procs | Out-Host
    
    if (Show-NavigationHint) {
        Show-ProcessesMenu
    }
}

function Kill-ProcessByName {
    $pname = Read-Host "Enter the process name to kill"
    try {
        Stop-Process -Name $pname -Force
        Write-Log "Executed: Stop-Process -Name $pname"
        Write-Host "Process $pname killed." -ForegroundColor $colors.Success
    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    Read-Host "Press Enter to continue"
    Show-ProcessesMenu
}

function List-ScheduledTasks {
    Write-Host "Listing scheduled tasks..." -ForegroundColor $colors.Info
    $tasks = Get-ScheduledTask
    Write-Log "Executed: Get-ScheduledTask"
    $tasks | Out-Host
    Read-Host "Press Enter to continue"
    Show-ScheduledTasksMenu
}

function Run-ScheduledTask {
    $taskName = Read-Host "Enter the scheduled task name"
    try {
        Start-ScheduledTask -TaskName $taskName
        Write-Log "Executed: Start-ScheduledTask -TaskName $taskName"
        Write-Host "Task $taskName started." -ForegroundColor $colors.Success
    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    Read-Host "Press Enter to continue"
    Show-ScheduledTasksMenu
}

function Exit-Script {
    Write-Host "Exiting..." -ForegroundColor $colors.Success
    Exit
}

# Neue Menü-Funktionen
function Show-MaintenanceMenu {
    $maintMenu = @{
        1 = @{ Name = "Disk Cleanup"; Function = "Start-DiskCleanup" }
        2 = @{ Name = "Check Disk (CHKDSK)"; Function = "Start-DiskCheck" }
        3 = @{ Name = "System File Check (SFC)"; Function = "Start-SFC" }
        4 = @{ Name = "DISM Repair"; Function = "Start-DISM" }
        5 = @{ Name = "Clear Temp Files"; Function = "Clear-TempFiles" }
        6 = @{ Name = "Windows Performance Index"; Function = "Get-WinPerformanceIndex" }
        B = @{ Name = "Back to Main Menu"; Function = { Show-Menu -MenuItems $mainMenu } }
    }
    Show-Menu -Title "System Maintenance" -MenuItems $maintMenu
}

function Show-NetDiagMenu {
    $netDiagMenu = @{
        1 = @{ Name = "Network Adapter Status"; Function = "Get-NetworkAdapterStatus" }
        2 = @{ Name = "WiFi Profiles"; Function = "Get-WifiProfiles" }
        3 = @{ Name = "Network Shares"; Function = "Get-NetworkShares" }
        4 = @{ Name = "Reset Network"; Function = "Reset-Network" }
        5 = @{ Name = "SMB Status"; Function = "Get-SMBStatus" }
        6 = @{ Name = "Port Scanner"; Function = "Start-PortScan" }
        B = @{ Name = "Back to Main Menu"; Function = { Show-Menu -MenuItems $mainMenu } }
    }
    Show-Menu -Title "Network Diagnostics" -MenuItems $netDiagMenu
}

function Show-SecurityMenu {
    $securityMenu = @{
        1 = @{ Name = "BitLocker Status"; Function = "Get-BitLockerStatus" }
        2 = @{ Name = "Windows Defender"; Function = "Show-DefenderMenu" }
        3 = @{ Name = "Permissions Tool"; Function = "Show-PermissionsTool" }
        4 = @{ Name = "Security Audit"; Function = "Start-SecurityAudit" }
        5 = @{ Name = "Certificate Manager"; Function = "Show-CertificateManager" }
        6 = @{ Name = "Credential Manager"; Function = "Show-CredentialManager" }
        7 = @{ Name = "Password Generator"; Function = "Show-PasswordGenerator" }
        8 = @{ Name = "Passphrase Generator"; Function = "Show-PassphraseGenerator" }
        9 = @{ Name = "Latest Critical CVEs"; Function = "Show-LatestCVEs" }
        B = @{ Name = "Back to Main Menu"; Function = { Show-Menu -MenuItems $mainMenu } }
    }
    Show-Menu -Title "Security Tools" -MenuItems $securityMenu
}

# Systemwartungs-Funktionen
function Start-DiskCleanup {
    Clear-Host
    Write-Host "=== Disk Cleanup ===" -ForegroundColor $colors.Title
    Write-Host "Starting disk cleanup..." -ForegroundColor $colors.Info
    
    try {
        # Starte cleanmgr.exe mit System-Profil
        Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:1" -Wait
        Write-Log "Executed: Disk Cleanup"
        Write-Host "Disk cleanup completed successfully." -ForegroundColor $colors.Success
    } catch {
        Write-Host "Error during disk cleanup: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    
    if (Show-NavigationHint) {
        Show-MaintenanceMenu
    }
}

function Start-DiskCheck {
    Clear-Host
    Write-Host "=== Check Disk (CHKDSK) ===" -ForegroundColor $colors.Title
    $drive = Read-Host "Enter drive letter (e.g., C)"
    
    try {
        $result = chkdsk "$($drive):" /f /r
        Write-Log "Executed: CHKDSK on drive $drive"
        $result | Out-Host
        Write-Host "Disk check scheduled for next restart." -ForegroundColor $colors.Warning
    } catch {
        Write-Host "Error during disk check: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    
    if (Show-NavigationHint) {
        Show-MaintenanceMenu
    }
}

function Start-SFC {
    Clear-Host
    Write-Host "=== System File Checker ===" -ForegroundColor $colors.Title
    Write-Host "Running SFC scan..." -ForegroundColor $colors.Info
    
    try {
        $result = Start-Process "sfc" -ArgumentList "/scannow" -Wait -PassThru
        Write-Log "Executed: SFC /scannow"
        if ($result.ExitCode -eq 0) {
            Write-Host "SFC scan completed successfully." -ForegroundColor $colors.Success
        } else {
            Write-Host "SFC scan completed with errors." -ForegroundColor $colors.Warning
        }
    } catch {
        Write-Host "Error during SFC scan: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    
    if (Show-NavigationHint) {
        Show-MaintenanceMenu
    }
}

# Netzwerkdiagnose-Funktionen
function Get-NetworkAdapterStatus {
    Clear-Host
    Write-Host "=== Network Adapter Status ===" -ForegroundColor $colors.Title
    
    try {
        $adapters = Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MediaType
        $adapters | Format-Table -AutoSize
        Write-Log "Executed: Get-NetAdapter"
    } catch {
        Write-Host "Error getting adapter status: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    
    if (Show-NavigationHint) {
        Show-NetDiagMenu
    }
}

function Get-WifiProfiles {
    Clear-Host
    Write-Host "=== WiFi Profiles ===" -ForegroundColor $colors.Title
    
    try {
        $profiles = netsh wlan show profiles
        Write-Log "Executed: netsh wlan show profiles"
        $profiles | Out-Host
    } catch {
        Write-Host "Error getting WiFi profiles: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    
    if (Show-NavigationHint) {
        Show-NetDiagMenu
    }
}

# Sicherheits-Funktionen
function Get-BitLockerStatus {
    Clear-Host
    Write-Host "=== BitLocker Status ===" -ForegroundColor $colors.Title
    
    try {
        $volumes = Get-BitLockerVolume
        foreach ($vol in $volumes) {
            Write-Host "`nDrive $($vol.MountPoint):" -ForegroundColor $colors.Info
            Write-Host "Protection Status: $($vol.ProtectionStatus)"
            Write-Host "Encryption Percentage: $($vol.EncryptionPercentage)%"
            Write-Host "Lock Status: $($vol.LockStatus)"
        }
        Write-Log "Executed: Get-BitLockerVolume"
    } catch {
        Write-Host "Error getting BitLocker status: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    
    if (Show-NavigationHint) {
        Show-SecurityMenu
    }
}

# Neue Menü-Funktionen
function Show-PerformanceMenu {
    $perfMenu = @{
        1 = @{ Name = "Autostart Programs"; Function = "Get-AutostartPrograms" }
        2 = @{ Name = "Service Optimization"; Function = "Show-ServiceOptimization" }
        3 = @{ Name = "Power Settings"; Function = "Show-PowerSettings" }
        4 = @{ Name = "Page File Status"; Function = "Get-PageFileStatus" }
        5 = @{ Name = "Performance Monitor"; Function = "Show-PerformanceMonitor" }
        B = @{ Name = "Back to Main Menu"; Function = { Show-Menu -MenuItems $mainMenu } }
    }
    Show-Menu -Title "Performance Tools" -MenuItems $perfMenu
}

function Show-PrinterMenu {
    $printerMenu = @{
        1 = @{ Name = "Printer Queue"; Function = "Show-PrintQueue" }
        2 = @{ Name = "Printer List"; Function = "Get-PrinterList" }
        3 = @{ Name = "Print Jobs"; Function = "Get-PrintJobs" }
        B = @{ Name = "Back to Main Menu"; Function = { Show-Menu -MenuItems $mainMenu } }
    }
    Show-Menu -Title "Printer Management" -MenuItems $printerMenu
}

function Show-AppMenu {
    $appMenu = @{
        1 = @{ Name = "Installed Programs"; Function = "Get-InstalledPrograms" }
        2 = @{ Name = "Windows Features"; Function = "Show-WindowsFeatures" }
        3 = @{ Name = "Store Apps"; Function = "Get-StoreApps" }
        B = @{ Name = "Back to Main Menu"; Function = { Show-Menu -MenuItems $mainMenu } }
    }
    Show-Menu -Title "App Management" -MenuItems $appMenu
}

function Show-HardwareMenu {
    $hwMenu = @{
        1 = @{ Name = "Driver Status"; Function = "Get-DriverStatus" }
        2 = @{ Name = "BIOS Information"; Function = "Get-BiosInfo" }
        3 = @{ Name = "USB Devices"; Function = "Get-USBDevices" }
        B = @{ Name = "Back to Main Menu"; Function = { Show-Menu -MenuItems $mainMenu } }
    }
    Show-Menu -Title "Hardware Information" -MenuItems $hwMenu
}

# Performance Funktionen
function Get-AutostartPrograms {
    Clear-Host
    Write-Host "=== Autostart Programs ===" -ForegroundColor $colors.Title
    
    try {
        Write-Host "`nStartup from Registry:" -ForegroundColor $colors.Info
        Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | 
            Select-Object * -ExcludeProperty PS* | Format-Table -AutoSize
        
        Write-Host "`nStartup from Startup Folder:" -ForegroundColor $colors.Info
        Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" |
            Select-Object Name, LastWriteTime | Format-Table -AutoSize
        
        Write-Log "Executed: Get-AutostartPrograms"
    } catch {
        Write-Host "Error getting autostart programs: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    
    if (Show-NavigationHint) {
        Show-PerformanceMenu
    }
}

function Get-PageFileStatus {
    Clear-Host
    Write-Host "=== Page File Status ===" -ForegroundColor $colors.Title
    
    try {
        $pageFile = Get-WmiObject Win32_PageFileUsage
        $pageFileSetting = Get-WmiObject Win32_PageFileSetting
        
        Write-Host "`nCurrent Page File Usage:" -ForegroundColor $colors.Info
        Write-Host "Location: $($pageFile.Name)"
        Write-Host "Current Usage: $($pageFile.CurrentUsage) MB"
        Write-Host "Peak Usage: $($pageFile.PeakUsage) MB"
        
        Write-Host "`nPage File Settings:" -ForegroundColor $colors.Info
        Write-Host "Initial Size: $($pageFileSetting.InitialSize) MB"
        Write-Host "Maximum Size: $($pageFileSetting.MaximumSize) MB"
        
        Write-Log "Executed: Get-PageFileStatus"
    } catch {
        Write-Host "Error getting page file status: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    
    if (Show-NavigationHint) {
        Show-PerformanceMenu
    }
}

# Printer Funktionen
function Get-PrinterList {
    Clear-Host
    Write-Host "=== Installed Printers ===" -ForegroundColor $colors.Title
    
    try {
        $printers = Get-Printer
        $printers | Select-Object Name, PrinterStatus, Type, PortName |
            Format-Table -AutoSize
        
        Write-Log "Executed: Get-PrinterList"
    } catch {
        Write-Host "Error getting printer list: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    
    if (Show-NavigationHint) {
        Show-PrinterMenu
    }
}

function Get-PrintJobs {
    Clear-Host
    Write-Host "=== Print Jobs ===" -ForegroundColor $colors.Title
    
    try {
        $jobs = Get-PrintJob -All
        if ($jobs) {
            $jobs | Select-Object PrinterName, DocumentName, JobStatus, Pages |
                Format-Table -AutoSize
        } else {
            Write-Host "No active print jobs found." -ForegroundColor $colors.Info
        }
        
        Write-Log "Executed: Get-PrintJobs"
    } catch {
        Write-Host "Error getting print jobs: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    
    if (Show-NavigationHint) {
        Show-PrinterMenu
    }
}

# App Management Funktionen
function Get-InstalledPrograms {
    Clear-Host
    Write-Host "=== Installed Programs ===" -ForegroundColor $colors.Title
    
    try {
        $programs = Get-WmiObject -Class Win32_Product |
            Select-Object Name, Version, Vendor |
            Sort-Object Name
        
        $programs | Format-Table -AutoSize
        Write-Log "Executed: Get-InstalledPrograms"
    } catch {
        Write-Host "Error getting installed programs: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    
    if (Show-NavigationHint) {
        Show-AppMenu
    }
}

function Show-WindowsFeatures {
    Clear-Host
    Write-Host "=== Windows Features ===" -ForegroundColor $colors.Title
    
    try {
        $features = Get-WindowsOptionalFeature -Online |
            Where-Object State -eq "Enabled" |
            Select-Object FeatureName, State
        
        Write-Host "`nEnabled Features:" -ForegroundColor $colors.Info
        $features | Format-Table -AutoSize
        
        Write-Log "Executed: Get-WindowsFeatures"
    } catch {
        Write-Host "Error getting Windows features: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    
    if (Show-NavigationHint) {
        Show-AppMenu
    }
}

# Hardware Funktionen
function Get-DriverStatus {
    Clear-Host
    Write-Host "=== Driver Status ===" -ForegroundColor $colors.Title
    
    try {
        $drivers = Get-WmiObject Win32_PnPSignedDriver |
            Where-Object { $_.DeviceName -ne $null } |
            Select-Object DeviceName, DriverVersion, DriverProviderName, IsSigned |
            Sort-Object DeviceName
        
        $drivers | Format-Table -AutoSize
        Write-Log "Executed: Get-DriverStatus"
    } catch {
        Write-Host "Error getting driver status: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    
    if (Show-NavigationHint) {
        Show-HardwareMenu
    }
}

function Get-USBDevices {
    Clear-Host
    Write-Host "=== USB Devices ===" -ForegroundColor $colors.Title
    
    try {
        $usbDevices = Get-PnpDevice -Class USB |
            Select-Object FriendlyName, Status, Class |
            Sort-Object FriendlyName
        
        $usbDevices | Format-Table -AutoSize
        Write-Log "Executed: Get-USBDevices"
    } catch {
        Write-Host "Error getting USB devices: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    
    if (Show-NavigationHint) {
        Show-HardwareMenu
    }
}

# Neue Funktion für Power Settings
function Show-PowerSettings {
    Clear-Host
    Write-Host "=== Power Settings ===" -ForegroundColor $colors.Title
    
    try {
        # Aktives Power Schema anzeigen
        $activePlan = powercfg /getactivescheme
        Write-Host "`nCurrent Power Plan:" -ForegroundColor $colors.Info
        $activePlan

        # Alle verfügbaren Power Schemes anzeigen
        Write-Host "`nAvailable Power Plans:" -ForegroundColor $colors.Info
        powercfg /list

        # Zeige Details zum aktiven Plan
        Write-Host "`nPower Plan Settings:" -ForegroundColor $colors.Info
        Write-Host "Monitor timeout (AC/Battery):" -ForegroundColor $colors.SubMenu
        powercfg /query SCHEME_CURRENT SUB_VIDEO VIDEOIDLE
        
        Write-Host "`nHard disk timeout (AC/Battery):" -ForegroundColor $colors.SubMenu
        powercfg /query SCHEME_CURRENT SUB_DISK DISKIDLE
        
        Write-Host "`nSleep timeout (AC/Battery):" -ForegroundColor $colors.SubMenu
        powercfg /query SCHEME_CURRENT SUB_SLEEP STANDBYIDLE

        # Hibernate Status
        Write-Host "`nHibernation Status:" -ForegroundColor $colors.SubMenu
        powercfg /hibernate status
        
        Write-Log "Executed: Show-PowerSettings"
    } catch {
        Write-Host "Error getting power settings: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    
    Write-Host "`nOptions:" -ForegroundColor $colors.Warning
    Write-Host "1) Change Power Plan"
    Write-Host "2) Enable/Disable Hibernate"
    Write-Host "B) Back to Menu"
    
    $choice = Read-Host "`nSelect option"
    switch ($choice) {
        "1" {
            $planGuid = Read-Host "Enter Power Plan GUID from list above"
            powercfg /setactive $planGuid
            Write-Host "Power plan changed." -ForegroundColor $colors.Success
        }
        "2" {
            $hibernateChoice = Read-Host "Enable hibernate? (Y/N)"
            if ($hibernateChoice -eq "Y") {
                powercfg /hibernate on
                Write-Host "Hibernate enabled." -ForegroundColor $colors.Success
            } else {
                powercfg /hibernate off
                Write-Host "Hibernate disabled." -ForegroundColor $colors.Success
            }
        }
    }
    
    if (Show-NavigationHint) {
        Show-PerformanceMenu
    }
}

# Neue Funktion für Performance Monitor
function Show-PerformanceMonitor {
    Clear-Host
    Write-Host "=== Performance Monitor ===" -ForegroundColor $colors.Title
    
    try {
        # CPU-Auslastung über WMI
        $cpuUsage = (Get-CimInstance -ClassName Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
        
        # Arbeitsspeicher über WMI
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $totalRam = [math]::Round($computerSystem.TotalPhysicalMemory/1GB, 2)
        $freeRam = [math]::Round($os.FreePhysicalMemory/1MB, 2)
        $usedRam = $totalRam - $freeRam
        
        # Festplattenauslastung
        $disks = Get-CimInstance -ClassName Win32_LogicalDisk | 
            Where-Object { $_.DriveType -eq 3 } |
            Select-Object DeviceID, 
                @{Name="Size(GB)";Expression={[math]::Round($_.Size/1GB, 2)}},
                @{Name="FreeSpace(GB)";Expression={[math]::Round($_.FreeSpace/1GB, 2)}}
        
        # Netzwerkadapter
        $networks = Get-NetAdapter | Where-Object Status -eq 'Up' |
            Select-Object Name, LinkSpeed
        
        # Ausgabe formatieren
        Write-Host "`nSystem Performance Overview:" -ForegroundColor $colors.Info
        Write-Host "------------------------" -ForegroundColor $colors.Border
        
        # CPU-Auslastungsbalken
        Write-Host "`nCPU Usage: " -NoNewline
        $cpuBar = "■" * [math]::Round($cpuUsage / 2)
        Write-Host $cpuBar -NoNewline -ForegroundColor $(if($cpuUsage -gt 80){'Red'}elseif($cpuUsage -gt 60){'Yellow'}else{'Green'})
        Write-Host " $cpuUsage%" -ForegroundColor $colors.Info
        
        # Speichernutzung
        Write-Host "`nMemory Usage:" -ForegroundColor $colors.Info
        Write-Host "Total RAM: $totalRam GB"
        Write-Host "Used RAM: $usedRam GB"
        Write-Host "Free RAM: $freeRam GB"
        
        # Festplattennutzung
        Write-Host "`nDisk Usage:" -ForegroundColor $colors.Info
        $disks | Format-Table -AutoSize
        
        # Netzwerkadapter
        Write-Host "`nNetwork Adapters:" -ForegroundColor $colors.Info
        $networks | Format-Table -AutoSize
        
        # Top Prozesse nach CPU-Auslastung
        Write-Host "`nTop CPU Consuming Processes:" -ForegroundColor $colors.SubMenu
        Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 Name, 
            @{Name="CPU(%)";Expression={[math]::Round($_.CPU, 2)}},
            @{Name="Memory(MB)";Expression={[math]::Round($_.WorkingSet/1MB, 2)}} | 
            Format-Table -AutoSize
        
        # Top Prozesse nach Arbeitsspeicher
        Write-Host "Top Memory Consuming Processes:" -ForegroundColor $colors.SubMenu
        Get-Process | Sort-Object WorkingSet -Descending | 
            Select-Object -First 5 Name,
            @{Name="Memory(MB)";Expression={[math]::Round($_.WorkingSet/1MB, 2)}},
            @{Name="CPU(%)";Expression={[math]::Round($_.CPU, 2)}} | 
            Format-Table -AutoSize
        
        Write-Log "Executed: Show-PerformanceMonitor"
        
        Write-Host "`nOptions:" -ForegroundColor $colors.Warning
        Write-Host "1) Start Real-Time Monitoring"
        Write-Host "2) Export Performance Data"
        Write-Host "B) Back to Menu"
        
        $choice = Read-Host "`nSelect option"
        switch ($choice) {
            "1" {
                Write-Host "`nStarting real-time monitoring (Press Ctrl+C to stop)..." -ForegroundColor $colors.Warning
                while ($true) {
                    $cpuUsage = (Get-CimInstance -ClassName Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
                    $memoryUsage = (Get-CimInstance -ClassName Win32_OperatingSystem | 
                        Select-Object @{Name="MemoryUsage";Expression={[math]::Round((1-($_.FreePhysicalMemory/$_.TotalVisibleMemorySize))*100, 2)}}).MemoryUsage
                    
                    Write-Host "`rCPU: $cpuUsage% | RAM: $memoryUsage%" -NoNewline -ForegroundColor $(
                        if($cpuUsage -gt 80 -or $memoryUsage -gt 80){'Red'}
                        elseif($cpuUsage -gt 60 -or $memoryUsage -gt 60){'Yellow'}
                        else{'Green'}
                    )
                    Start-Sleep -Seconds 1
                }
            }
            "2" {
                $exportPath = "$env:USERPROFILE\Desktop\PerformanceLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
                $perfData = @{
                    Timestamp = Get-Date
                    CPU_Usage = $cpuUsage
                    Total_RAM_GB = $totalRam
                    Free_RAM_GB = $freeRam
                    Top_Process = (Get-Process | Sort-Object CPU -Descending | Select-Object -First 1 Name).Name
                }
                $perfData | Export-Csv -Path $exportPath -NoTypeInformation
                Write-Host "Performance data exported to: $exportPath" -ForegroundColor $colors.Success
            }
        }
        
    } catch {
        Write-Host "Error monitoring performance: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    
    if (Show-NavigationHint) {
        Show-PerformanceMenu
    }
}

# Neue Funktion für BIOS Information
function Get-BiosInfo {
    Clear-Host
    Write-Host "=== BIOS Information ===" -ForegroundColor $colors.Title
    
    try {
        # BIOS-Informationen abrufen
        $bios = Get-CimInstance -ClassName Win32_BIOS
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
        $baseboard = Get-CimInstance -ClassName Win32_BaseBoard
        
        # BIOS Details
        Write-Host "`nBIOS Details:" -ForegroundColor $colors.Info
        Write-Host "Manufacturer: $($bios.Manufacturer)"
        Write-Host "Version: $($bios.Version)"
        Write-Host "Release Date: $($bios.ReleaseDate)"
        Write-Host "Serial Number: $($bios.SerialNumber)"
        Write-Host "SMBIOS Version: $($bios.SMBIOSBIOSVersion)"
        
        # Systemhersteller Details
        Write-Host "`nSystem Manufacturer Details:" -ForegroundColor $colors.Info
        Write-Host "System Manufacturer: $($computerSystem.Manufacturer)"
        Write-Host "System Model: $($computerSystem.Model)"
        Write-Host "System Type: $($computerSystem.SystemType)"
        
        # Motherboard Details
        Write-Host "`nMotherboard Details:" -ForegroundColor $colors.Info
        Write-Host "Board Manufacturer: $($baseboard.Manufacturer)"
        Write-Host "Board Product: $($baseboard.Product)"
        Write-Host "Board Version: $($baseboard.Version)"
        Write-Host "Board Serial Number: $($baseboard.SerialNumber)"
        
        # Secure Boot Status
        try {
            $secureBootStatus = Confirm-SecureBootUEFI
            Write-Host "`nSecure Boot Status: $($secureBootStatus)" -ForegroundColor $(
                if($secureBootStatus){'Green'}else{'Red'}
            )
        } catch {
            Write-Host "`nSecure Boot Status: Not Available" -ForegroundColor $colors.Warning
        }
        
        # TPM Status
        try {
            $tpm = Get-Tpm
            Write-Host "`nTPM Status:" -ForegroundColor $colors.Info
            Write-Host "TPM Present: $($tpm.TpmPresent)"
            Write-Host "TPM Ready: $($tpm.TpmReady)"
            Write-Host "TPM Enabled: $($tpm.TpmEnabled)"
            Write-Host "TPM Activated: $($tpm.TpmActivated)"
        } catch {
            Write-Host "`nTPM Status: Not Available" -ForegroundColor $colors.Warning
        }
        
        Write-Log "Executed: Get-BiosInfo"
    } catch {
        Write-Host "Error retrieving BIOS information: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    
    if (Show-NavigationHint) {
        Show-HardwareMenu
    }
}

# Neue Funktion für Windows Defender Menü
function Show-DefenderMenu {
    $defenderMenu = @{
        1 = @{ Name = "Scan Status"; Function = "Get-DefenderStatus" }
        2 = @{ Name = "Quick Scan"; Function = "Start-DefenderQuickScan" }
        3 = @{ Name = "Full Scan"; Function = "Start-DefenderFullScan" }
        4 = @{ Name = "Update Definitions"; Function = "Update-DefenderDefinitions" }
        B = @{ Name = "Back"; Function = { Show-SecurityMenu } }
    }
    Show-Menu -Title "Windows Defender" -MenuItems $defenderMenu
}

# Neue Funktion für Permissions Tool
function Show-PermissionsTool {
    Clear-Host
    Write-Host "=== Permissions Tool ===" -ForegroundColor $colors.Title
    
    $path = Read-Host "Enter path to check permissions"
    if (Test-Path $path) {
        try {
            $acl = Get-Acl $path
            Write-Host "`nOwner: $($acl.Owner)" -ForegroundColor $colors.Info
            Write-Host "`nAccess Rules:" -ForegroundColor $colors.SubMenu
            $acl.Access | Format-Table IdentityReference, FileSystemRights, AccessControlType -AutoSize
            Write-Log "Executed: Permissions check for $path"
        } catch {
            Write-Host "Error getting permissions: $($_.Exception.Message)" -ForegroundColor $colors.Error
        }
    } else {
        Write-Host "Path not found!" -ForegroundColor $colors.Error
    }
    
    if (Show-NavigationHint) {
        Show-SecurityMenu
    }
}

# Neue Funktion für Security Audit
function Start-SecurityAudit {
    Clear-Host
    Write-Host "=== Security Audit ===" -ForegroundColor $colors.Title
    
    try {
        # Check Windows Defender Status
        Write-Host "`nChecking Windows Defender..." -ForegroundColor $colors.Info
        $defender = Get-MpComputerStatus
        Write-Host "Antivirus Enabled: $($defender.AntivirusEnabled)"
        Write-Host "Real-time Protection: $($defender.RealTimeProtectionEnabled)"
        
        # Check Firewall Status
        Write-Host "`nChecking Firewall..." -ForegroundColor $colors.Info
        $firewall = Get-NetFirewallProfile
        foreach ($profile in $firewall) {
            Write-Host "$($profile.Name) Profile: $($profile.Enabled)"
        }
        
        # Check Windows Update Status
        Write-Host "`nChecking Windows Update..." -ForegroundColor $colors.Info
        $updateStatus = Get-WindowsUpdateLog -ErrorAction SilentlyContinue
        
        # Check BitLocker Status
        Write-Host "`nChecking BitLocker..." -ForegroundColor $colors.Info
        $bitlocker = Get-BitLockerVolume -ErrorAction SilentlyContinue
        if ($bitlocker) {
            $bitlocker | ForEach-Object {
                Write-Host "Drive $($_.MountPoint): $($_.ProtectionStatus)"
            }
        }
        
        Write-Log "Executed: Security Audit"
    } catch {
        Write-Host "Error during security audit: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    
    if (Show-NavigationHint) {
        Show-SecurityMenu
    }
}

# Neue Funktion für Certificate Manager
function Show-CertificateManager {
    Clear-Host
    Write-Host "=== Certificate Manager ===" -ForegroundColor $colors.Title
    
    try {
        Write-Host "`nLocal Machine Certificates:" -ForegroundColor $colors.Info
        Get-ChildItem Cert:\LocalMachine\My | 
            Select-Object Subject, NotAfter, Thumbprint |
            Format-Table -AutoSize
            
        Write-Host "`nCurrent User Certificates:" -ForegroundColor $colors.Info
        Get-ChildItem Cert:\CurrentUser\My |
            Select-Object Subject, NotAfter, Thumbprint |
            Format-Table -AutoSize
            
        Write-Log "Executed: Certificate Manager"
    } catch {
        Write-Host "Error accessing certificates: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    
    if (Show-NavigationHint) {
        Show-SecurityMenu
    }
}

# Neue Funktion für Credential Manager
function Show-CredentialManager {
    Clear-Host
    Write-Host "=== Credential Manager ===" -ForegroundColor $colors.Title
    
    try {
        Write-Host "`nStored Credentials:" -ForegroundColor $colors.Info
        cmdkey /list | Out-Host
        
        Write-Log "Executed: Credential Manager"
    } catch {
        Write-Host "Error accessing credentials: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    
    if (Show-NavigationHint) {
        Show-SecurityMenu
    }
}

# Windows Defender Functions
function Get-DefenderStatus {
    Clear-Host
    Write-Host "=== Windows Defender Status ===" -ForegroundColor $colors.Title
    
    try {
        $status = Get-MpComputerStatus
        
        Write-Host "`nProtection Status:" -ForegroundColor $colors.Info
        Write-Host "Antivirus Enabled: $($status.AntivirusEnabled)"
        Write-Host "Real-time Protection: $($status.RealTimeProtectionEnabled)"
        Write-Host "Behavior Monitor: $($status.BehaviorMonitorEnabled)"
        Write-Host "IoAV Protection: $($status.IoavProtectionEnabled)"
        Write-Host "Network Protection: $($status.IsTamperProtected)"
        
        Write-Host "`nDefinitions:" -ForegroundColor $colors.Info
        Write-Host "Signature Version: $($status.AntivirusSignatureVersion)"
        Write-Host "Last Update: $($status.AntivirusSignatureLastUpdated)"
        
        Write-Log "Executed: Get Defender Status"
    } catch {
        Write-Host "Error getting Defender status: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    
    if (Show-NavigationHint) {
        Show-DefenderMenu
    }
}

function Start-DefenderQuickScan {
    Clear-Host
    Write-Host "=== Starting Quick Scan ===" -ForegroundColor $colors.Title
    
    try {
        Start-MpScan -ScanType QuickScan
        Write-Host "Quick scan started successfully." -ForegroundColor $colors.Success
        Write-Log "Executed: Defender Quick Scan"
    } catch {
        Write-Host "Error starting scan: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    
    if (Show-NavigationHint) {
        Show-DefenderMenu
    }
}

function Start-DefenderFullScan {
    Clear-Host
    Write-Host "=== Starting Full Scan ===" -ForegroundColor $colors.Title
    Write-Host "Warning: This may take several hours" -ForegroundColor $colors.Warning
    
    try {
        Start-MpScan -ScanType FullScan
        Write-Host "Full scan started successfully." -ForegroundColor $colors.Success
        Write-Log "Executed: Defender Full Scan"
    } catch {
        Write-Host "Error starting scan: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    
    if (Show-NavigationHint) {
        Show-DefenderMenu
    }
}

function Update-DefenderDefinitions {
    Clear-Host
    Write-Host "=== Updating Defender Definitions ===" -ForegroundColor $colors.Title
    
    try {
        Update-MpSignature
        Write-Host "Definition update started successfully." -ForegroundColor $colors.Success
        Write-Log "Executed: Update Defender Definitions"
    } catch {
        Write-Host "Error updating definitions: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }
    
    if (Show-NavigationHint) {
        Show-DefenderMenu
    }
}

# Add new functions for password generation
function Show-PasswordGenerator {
    Clear-Host
    Write-Host "=== Modern Password Generator ===" -ForegroundColor $colors.Title
    Write-Host "`nModern Password Requirements:" -ForegroundColor $colors.Info
    Write-Host "- Minimum length: 12 characters" -ForegroundColor $colors.Info
    Write-Host "- Must include: uppercase, lowercase, numbers, special characters" -ForegroundColor $colors.Info
    Write-Host "- Avoiding common patterns and dictionary words" -ForegroundColor $colors.Info
    
    $length = 0
    do {
        $lengthInput = Read-Host "Enter password length (12-128)"
        if ([int]::TryParse($lengthInput, [ref]$length) -and $length -ge 12 -and $length -le 128) {
            break
        }
        Write-Host "Please enter a valid length between 12 and 128" -ForegroundColor $colors.Warning
    } while ($true)

    try {
        # Modern character sets
        $lowerChars = 'abcdefghijklmnopqrstuvwxyz'
        $upperChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        $numbers = '0123456789'
        $specialChars = '!@#$%^&*()_+-=[]{}|;:,.<>?~'
        
        # Ensure at least one of each type
        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        $password = @()
        
        # Add one of each required character type
        $password += Get-RandomChar $lowerChars $rng
        $password += Get-RandomChar $upperChars $rng
        $password += Get-RandomChar $numbers $rng
        $password += Get-RandomChar $specialChars $rng
        
        # Fill the rest randomly
        $fullCharset = $lowerChars + $upperChars + $numbers + $specialChars
        while ($password.Count -lt $length) {
            $password += Get-RandomChar $fullCharset $rng
        }
        
        # Shuffle the password
        $password = $password | Sort-Object {Get-Random}
        $finalPassword = -join $password

        # Password strength check
        $strength = Test-PasswordStrength $finalPassword
        
        Write-Host "`nGenerated Password:" -ForegroundColor $colors.Success
        Write-Host $finalPassword -ForegroundColor $colors.Info
        Write-Host "`nPassword Strength: $strength" -ForegroundColor $(
            switch ($strength) {
                "Very Strong" { "Green" }
                "Strong" { "Yellow" }
                default { "Red" }
            }
        )
        
        Write-Log "Executed: Modern Password Generator"
    }
    catch {
        Write-Host "Error generating password: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }

    if (Show-NavigationHint) {
        Show-SecurityMenu
    }
}

function Get-RandomChar {
    param (
        [string]$charset,
        $rng
    )
    $bytes = New-Object byte[](1)
    $rng.GetBytes($bytes)
    return $charset[$bytes[0] % $charset.Length]
}

function Test-PasswordStrength {
    param ([string]$password)
    
    $score = 0
    
    # Length
    if ($password.Length -ge 12) { $score += 2 }
    if ($password.Length -ge 16) { $score += 2 }
    
    # Character types
    if ($password -match "[a-z]") { $score++ }
    if ($password -match "[A-Z]") { $score++ }
    if ($password -match "[0-9]") { $score++ }
    if ($password -match "[^a-zA-Z0-9]") { $score++ }
    
    # Complexity
    if ($password -match ".*[a-z].*[a-z].*") { $score++ }
    if ($password -match ".*[A-Z].*[A-Z].*") { $score++ }
    if ($password -match ".*[0-9].*[0-9].*") { $score++ }
    if ($password -match ".*[^a-zA-Z0-9].*[^a-zA-Z0-9].*") { $score++ }
    
    # Return strength based on score
    if ($score -ge 10) { return "Very Strong" }
    elseif ($score -ge 7) { return "Strong" }
    elseif ($score -ge 5) { return "Moderate" }
    else { return "Weak" }
}

function Show-PassphraseGenerator {
    Clear-Host
    Write-Host "=== Modern Passphrase Generator ===" -ForegroundColor $colors.Title
    Write-Host "`nModern Passphrase Guidelines:" -ForegroundColor $colors.Info
    Write-Host "- Minimum 4 words" -ForegroundColor $colors.Info
    Write-Host "- Random word selection" -ForegroundColor $colors.Info
    Write-Host "- Optional numbers and special characters" -ForegroundColor $colors.Info
    
    $wordCount = 0
    do {
        $countInput = Read-Host "Enter number of words (4-10)"
        if ([int]::TryParse($countInput, [ref]$wordCount) -and $wordCount -ge 4 -and $wordCount -le 10) {
            break
        }
        Write-Host "Please enter a valid number between 4 and 10" -ForegroundColor $colors.Warning
    } while ($true)

    $addNumbers = (Read-Host "Add random numbers? (Y/N)").ToUpper() -eq 'Y'
    $addSpecial = (Read-Host "Add special characters? (Y/N)").ToUpper() -eq 'Y'
    $separator = Read-Host "Enter word separator (default: -)"
    if ([string]::IsNullOrWhiteSpace($separator)) { $separator = "-" }

    try {
        # Enhanced word list with more common but memorable words
        $words = Get-Content "$script:currentPath\wordlist.txt" -ErrorAction SilentlyContinue
        
        if (-not $words) {
            $words = @(
                'correct', 'horse', 'battery', 'staple', 'rainbow', 'mountain',
                'river', 'forest', 'ocean', 'desert', 'winter', 'summer',
                'spring', 'autumn', 'north', 'south', 'east', 'west',
                'fire', 'water', 'earth', 'wind', 'heart', 'mind',
                'peace', 'love', 'joy', 'hope', 'dream', 'wish',
                'star', 'moon', 'sun', 'sky', 'cloud', 'storm',
                'thunder', 'lightning', 'rain', 'snow', 'ice', 'steam',
                'metal', 'wood', 'stone', 'glass', 'paper', 'cloth',
                'digital', 'crypto', 'quantum', 'cyber', 'data', 'cloud',
                'network', 'system', 'secure', 'binary', 'matrix', 'vector'
            )
        }

        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        $bytes = New-Object byte[]($wordCount)
        $passphrase = @()

        # Generate base passphrase
        for ($i = 0; $i -lt $wordCount; $i++) {
            $rng.GetBytes($bytes)
            $word = $words[$bytes[0] % $words.Count]
            # Randomly capitalize some words
            if ((Get-Random -Maximum 2) -eq 1) {
                $word = (Get-Culture).TextInfo.ToTitleCase($word)
            }
            $passphrase += $word
        }

        # Add numbers if requested
        if ($addNumbers) {
            $rng.GetBytes($bytes)
            $passphrase += [string]($bytes[0] % 900 + 100)
        }

        # Add special character if requested
        if ($addSpecial) {
            $specialChars = '!@#$%^&*'
            $rng.GetBytes($bytes)
            $passphrase += $specialChars[$bytes[0] % $specialChars.Length]
        }

        # Shuffle array if numbers or special chars were added
        if ($addNumbers -or $addSpecial) {
            $passphrase = $passphrase | Sort-Object {Get-Random}
        }

        $result = $passphrase -join $separator
        
        Write-Host "`nGenerated Passphrase:" -ForegroundColor $colors.Success
        Write-Host $result -ForegroundColor $colors.Info
        Write-Host "`nEstimated Entropy: $([math]::Round([Math]::Log($words.Count) * $wordCount / [Math]::Log(2), 2)) bits" -ForegroundColor $colors.Info
        
        Write-Log "Executed: Modern Passphrase Generator"
    }
    catch {
        Write-Host "Error generating passphrase: $($_.Exception.Message)" -ForegroundColor $colors.Error
    }

    if (Show-NavigationHint) {
        Show-SecurityMenu
    }
}

function Show-LatestCVEs {
    Clear-Host
    Write-Host "=== Latest Critical & High Microsoft CVEs ===" -ForegroundColor $colors.Title
    Write-Host "Fetching critical and high severity Microsoft vulnerabilities..." -ForegroundColor $colors.Info
    
    try {
        $endDate = Get-Date -Format "yyyy-MM-dd"
        $startDate = (Get-Date).AddDays(-30).ToString("yyyy-MM-dd")
        $reportPath = Join-Path $script:currentPath "CVE_Report_$($endDate -replace '-','').md"
        
        # Separate requests for Critical and High vulnerabilities
        $urls = @{
            Critical = "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${startDate}T00:00:00.000&pubEndDate=${endDate}T23:59:59.999&cvssV3Severity=CRITICAL"
            High = "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${startDate}T00:00:00.000&pubEndDate=${endDate}T23:59:59.999&cvssV3Severity=HIGH"
        }
        
        $vulnerabilities = @{
            Critical = @()
            High = @()
        }

        # Fetch data with rate limiting
        foreach ($key in $urls.Keys) {
            Write-Host "Requesting $key data..." -ForegroundColor $colors.Info
            $response = Invoke-RestMethod -Uri $urls[$key] -Method Get
            
            # Filter for Microsoft vulnerabilities
            $msVulns = $response.vulnerabilities | Where-Object {
                $vuln = $_.cve
                $vuln.descriptions[0].value -match "Microsoft" -or
                $vuln.descriptions[0].value -match "Windows" -or
                $vuln.references.url -match "microsoft.com"
            }
            
            if ($key -like "*Critical") {
                $vulnerabilities.Critical += $msVulns
            } else {
                $vulnerabilities.High += $msVulns
            }
            
            Start-Sleep -Seconds 6  # Rate limiting pause
        }

        $currentTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        
        # Create new report content
        $mdContent = @"
# Microsoft CVE Report
Generated on $currentTime

## Overview
Timeframe: $startDate to $endDate
Total Microsoft CVEs found: $($vulnerabilities.Critical.Count + $vulnerabilities.High.Count)
- Critical: $($vulnerabilities.Critical.Count)
- High: $($vulnerabilities.High.Count)

## Critical Vulnerabilities
"@
        # Add Critical vulnerabilities
        foreach ($vuln in $vulnerabilities.Critical) {
            $mdContent += "`n### $($vuln.cve.id) (Score: $($vuln.cve.metrics.cvssMetricV31[0].cvssData.baseScore))`n"
            $mdContent += "- **Published:** $($vuln.cve.published)`n"
            $mdContent += "- **Description:** $($vuln.cve.descriptions[0].value)`n"
            if ($vuln.cve.references) {
                $mdContent += "- **References:**`n"
                foreach ($ref in $vuln.cve.references | Select-Object -First 3) {
                    $mdContent += "  - [$($ref.url)]($($ref.url))`n"
                }
            }
            $mdContent += "`n---`n"
        }

        $mdContent += "`n## High Vulnerabilities`n"
        # Add High vulnerabilities
        foreach ($vuln in $vulnerabilities.High) {
            $mdContent += "`n### $($vuln.cve.id) (Score: $($vuln.cve.metrics.cvssMetricV31[0].cvssData.baseScore))`n"
            $mdContent += "- **Published:** $($vuln.cve.published)`n"
            $mdContent += "- **Description:** $($vuln.cve.descriptions[0].value)`n"
            if ($vuln.cve.references) {
                $mdContent += "- **References:**`n"
                foreach ($ref in $vuln.cve.references | Select-Object -First 3) {
                    $mdContent += "  - [$($ref.url)]($($ref.url))`n"
                }
            }
            $mdContent += "`n---`n"
        }

        # Save to file
        $mdContent | Out-File -FilePath $reportPath -Force -Encoding UTF8
        
        Write-Host "`nReport saved to:" -ForegroundColor $colors.Success
        Write-Host "MD: $reportPath" -ForegroundColor $colors.Info
        
        Write-Log "Generated Microsoft CVE report: $reportPath"
    }
    catch {
        Write-Host "Error fetching CVE data: $($_.Exception.Message)" -ForegroundColor $colors.Error
        Write-Host "Note: The NIST NVD API has rate limits. Please wait a few minutes before trying again." -ForegroundColor $colors.Warning
    }
    
    if (Show-NavigationHint) {
        Show-SecurityMenu
    }
}

# Start the script
Show-Menu -MenuItems $mainMenu
