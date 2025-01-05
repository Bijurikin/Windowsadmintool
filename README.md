# 🛠️ Windows Admin Tool

A comprehensive PowerShell-based system administration tool with an interactive menu interface for Windows systems.

## ✨ Features

- **Network Tools**
  - IP Configuration
  - DNS Cache Management
  - Network Connection Testing
  - Public IP Information
  - DNS Lookup
  - Website Status Check

- **System Tools**
  - System Information
  - Disk Health
  - Memory Status

- **Diagnostics**
  - Event Log Viewer
  - Event Log Cleanup
  - System Reboot

- **Service Management**
  - Service Listing
  - Service Restart

- **User Management**
  - List Local Users
  - Create Local User
  - Remove Local User

- **Windows Update**
  - Check for Updates
  - Install Updates

- **Advanced Network Tools**
  - NetStat Summary
  - Traceroute
  - DNS Cache Flush

- **Process Management**
  - List Processes
  - Kill Process

- **Security Tools**
  - BitLocker Status
  - Windows Defender Management
  - Permissions Tool
  - Security Audit
  - Certificate Manager
  - Credential Manager
  - Password Generator
  - Passphrase Generator
  - Microsoft CVE Reporter
    - Tracks latest Critical & High CVEs
    - Filters for Microsoft-specific vulnerabilities
    - Generates Markdown reports

- **Performance Tools**
  - Autostart Programs
  - Service Optimization
  - Power Settings
  - Page File Status
  - Performance Monitor

## 📋 Requirements

- Windows 10/11
- PowerShell 5.1 or higher
- Administrator privileges

## 💻 Installation and Setup

### PowerShell
1. Open PowerShell as Administrator:
   - Press Windows + X
   - Select "Windows PowerShell (Admin)"

2. Adjust Execution Policy (one-time):
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

3. Navigate to script directory:
```powershell
cd C:\Path\To\Script
```

4. Execute script:
```powershell
.\AdminTool.ps1
```

### 🔧 Troubleshooting

If you encounter errors:

1. Check PowerShell version:
```powershell
$PSVersionTable.PSVersion
```

2. Verify Administrator rights:
```powershell
# Should return "True"
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
```

3. For Execution Policy errors:
```powershell
# Show current policy
Get-ExecutionPolicy -List

# Set policy temporarily for current session
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

## 🎮 Navigation

- Use arrow keys to navigate menus
- Press Enter to select an option
- Press 'B' to go back to previous menu
- Press 'Q' to quit the application

## 📚 Features in Detail

### 🌐 Network Tools
- View detailed IP configuration
- Manage DNS cache
- Test network connections
- View public IP information
- Perform DNS lookups
- Check website status

### 💻 System Tools
- View comprehensive system information
- Check disk health
- Monitor memory status

### 🔒 Security Features
- BitLocker drive encryption status
- Windows Defender management
- File and folder permissions
- Security auditing
- Certificate management
- Credential management

### 📊 Performance Monitoring
- Real-time system monitoring
- Process management
- Service optimization
- Power settings management
- Performance data export

## 📝 Logging

The script maintains a log file with the naming format:
`YYYY-MM-DD-AdminTool.log`

## 👨‍💻 Author

Birger Hohmeier

## 📌 Version

1.0

## 📜 License

MIT License

## ⚠️ Disclaimer

This tool requires administrator privileges and should be used with caution. Always ensure you understand the implications of system changes before executing them.

## 🤝 Contributing

Feel free to submit issues and enhancement requests!

