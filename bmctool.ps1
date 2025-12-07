if ($PSVersionTable.PSVersion.Major -lt 7) {
    #Set colors for Windows 10
    $Host.UI.RawUI.BackgroundColor = "Black"
    $Host.UI.RawUI.ForegroundColor = "White"

    #Create $PSStyle
    $ESC = [char]27
    $PSStyle = New-Object PSObject
    $PSStyle | Add-Member -MemberType NoteProperty -Name Blink -Value "$ESC[5m"
    $PSStyle | Add-Member -MemberType NoteProperty -Name BlinkOff -Value "$ESC[22m"
    $PSStyle | Add-Member -MemberType NoteProperty -Name Foreground -Value @{}
    $PSStyle.Foreground | Add-Member -MemberType NoteProperty -Name Red -Value "$ESC[91m"
    $PSStyle | Add-Member -MemberType NoteProperty -Name Reset -Value "$ESC[0m"
}

#Variables
$BenchmarkComputersPath = "C:\Benchmark Computers"
$currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
$banner = @("
██████╗ ███████╗███╗   ██╗ ██████╗██╗  ██╗███╗   ███╗ █████╗ ██████╗ ██╗  ██╗
██╔══██╗██╔════╝████╗  ██║██╔════╝██║  ██║████╗ ████║██╔══██╗██╔══██╗██║ ██╔╝
██████╔╝█████╗  ██╔██╗ ██║██║     ███████║██╔████╔██║███████║██████╔╝█████╔╝
██╔══██╗██╔══╝  ██║╚██╗██║██║     ██╔══██║██║╚██╔╝██║██╔══██║██╔══██╗██╔═██╗
██████╔╝███████╗██║ ╚████║╚██████╗██║  ██║██║ ╚═╝ ██║██║  ██║██║  ██║██║  ██╗
╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝

████████╗ ██████╗  ██████╗ ██╗     ███████╗
╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔════╝
   ██║   ██║   ██║██║   ██║██║     ███████╗       █ █   ▀█   █▀█   █▀█
   ██║   ██║   ██║██║   ██║██║     ╚════██║       ▀▄▀   █▄ ▄ █▄█ ▄ █▄█
   ██║   ╚██████╔╝╚██████╔╝███████╗███████║
   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚══════╝
═════════════════════════════════════════════════════════════════════════════
")

#Create "Benchmark Computers" folder
New-item -ItemType Directory -Force -Path $BenchmarkComputersPath | Out-Null

function Show-Menu {
    <#
    .SYNOPSIS
        Generates a dynamic console menu featuring a list of options, allowing users to 
        navigate and select choices using their keyboard arrows.
    .DESCRIPTION
        The Show-Menu function is used to display a dynamic menu in the console. It takes 
        a title and a list of options as parameters. The title is optional and defaults to
        "Please make a selection...". The list of options is mandatory. The function will 
        display the title in green, followed by the list of options. The user can then make 
        a selection from the options provided.
    .EXAMPLE
        $MenuData += [PSCustomObject]@{Id = 1; DisplayName = "Menu Option 1"; RequireAdmin = $false}, `
                     [PSCustomObject]@{Id = 2; DisplayName = "Menu Option 2"; RequireAdmin = $true}, `
                     [PSCustomObject]@{Id = 3; DisplayName = "Menu Option 3"; RequireAdmin = $true}
        Show-Menu -DynamicMenuTitle "Main Menu" -DynamicMenuList $MenuData
        This example shows how to use the Show-Menu function to display a menu with a custom title and three options.
    .NOTES
        Version: 1.0.0
        Original Author:  Ryan Dunton https://github.com/ryandunton
        Author: Don Gordon
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]
        $DynamicMenuTitle = "What do you want to do today?",
        [Parameter(Mandatory=$true)]
        [array]
        $DynamicMenuList
    )
    
    begin {
        # Get longest item for background padding
        $paddingLength = 42

        if(-not $isAdmin){
            Write-Host "$($PSStyle.Blink)You are not running as Administrator! Some scripts my not be available.$($PSStyle.BlinkOff)" -ForegroundColor Red
            Write-Host ""
        }
        Write-Host "$DynamicMenuTitle" -ForegroundColor Green
        Write-Host ""
        
        # Create space for the menu
        $i=0
        while ($i -lt $DynamicMenuList.Count) {
            $i++
            Write-Host ""
        } 
    }
    
    process {
        # Set initial selection index
        $SelectedValueIndex = 0
        # Display the menu and handle user input
        do {
            # Move cursor to top of menu area
            [Console]::SetCursorPosition(0, [Console]::CursorTop - $DynamicMenuList.Count)
            for ($i = 0; $i -lt $DynamicMenuList.Count; $i++) {

                #Format name if not running as admin
                $MenuText = $DynamicMenuList[$i].DisplayName
                if(-not $isAdmin -and $DynamicMenuList[$i].RequireAdmin){
                    $menuText += " $($PSStyle.Foreground.Red)(Admin Required)$($PSStyle.Reset)"
                }

                if ($i -eq $SelectedValueIndex) {
                    Write-Host " → $($MenuText)".PadRight($paddingLength) -NoNewline -BackgroundColor Blue
                } else {
                    Write-Host "   $($MenuText)".PadRight($paddingLength) -NoNewline
                }
                #Clear any extra characters from previous lines
                $SpacesToClear = [Math]::Max(0, ($DynamicMenuList[0].Length - $DynamicMenuList[$i].Length))
                Write-Host (" " * $SpacesToClear) -NoNewline
                Write-Host ""
            }
            # Get user input
            $KeyInfo = $Host.UI.RawUI.ReadKey('NoEcho, IncludeKeyDown')
            # Process arrow key input
            switch ($KeyInfo.VirtualKeyCode) {
                38 {  # Up arrow
                    $SelectedValueIndex = [Math]::Max(0, $SelectedValueIndex - 1)
                }
                40 {  # Down arrow
                    $SelectedValueIndex = [Math]::Min($DynamicMenuList.Count - 1, $SelectedValueIndex + 1)
                }
            }
        } while ($KeyInfo.VirtualKeyCode -ne 13)  # Enter key
        $SelectedValue = $DynamicMenuList[$SelectedValueIndex]
    }
    
    end {
        return [PSCustomObject]@{
            Id = $SelectedValue.Id;
            RequireAdmin = $SelectedValue.RequireAdmin
        }
    }
}

function Write-Header {
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Title
    )

    $header = @("

==================================================
   $Title
==================================================")
    Write-Host $header -ForegroundColor Blue
}

function Get-SystemInfo {
    Clear-Host
    # number of tasks for the progress bar
    $tasks = 8
    [Ref]$currentTask = 0
    $sleep = 250

    Write-Header "System Information"
    if(-not $isAdmin) {
    Write-Host "Not running as admin, supported TPM versions and Secure Boot will not be checked" -ForegroundColor Red
    $tasks = $tasks - 1
    }

    # Computer system info
    Write-Progress -Activity 'Taking System Inventory' -PercentComplete ($currentTask.Value++/$tasks*100) -Status 'Collecting System Information'
    $system  = Get-CimInstance -ClassName Win32_ComputerSystem
    Start-Sleep -Milliseconds $sleep

    Write-Progress -Activity 'Taking System Inventory' -PercentComplete ($currentTask.Value++/$tasks*100) -Status 'Collecting Operaating System Information'
    $os        = Get-CimInstance -ClassName Win32_OperatingSystem
    $osVersion = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion
    $isWin10   = $os.Caption -Match "Windows 10"
    Start-Sleep -Milliseconds $sleep

    Write-Progress -Activity 'Taking System Inventory' -PercentComplete ($currentTask.Value++/$tasks*100) -Status 'Collecting CPU Information'
    $cpu     = Get-CimInstance -ClassName Win32_Processor
    Start-Sleep -Milliseconds $sleep

    Write-Progress -Activity 'Taking System Inventory' -PercentComplete ($currentTask.Value++/$tasks*100) -Status 'Collecting Video Card Information'
    $gpu     = Get-CimInstance -ClassName Win32_VideoController
    Start-Sleep -Milliseconds $sleep

    Write-Progress -Activity 'Taking System Inventory' -PercentComplete ($currentTask.Value++/$tasks*100) -Status 'Collecting Drive Information'
    $drives  = Get-CimInstance -ClassName Win32_DiskDrive
    Start-Sleep -Milliseconds $sleep

    Write-Progress -Activity 'Taking System Inventory' -PercentComplete ($currentTask.Value++/$tasks*100) -Status 'Collecting Free Space Information'
    $volumes = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3"
    Start-Sleep -Milliseconds $sleep

    # TPM info (may require admin rights)
    Write-Progress -Activity 'Taking System Inventory' -PercentComplete ($currentTask.Value++/$tasks*100) -Status 'Collecting Supported TPM Versions'
    if($isAdmin) {
        try {
            $tpm = Get-CimInstance -Namespace "Root\CIMV2\Security\MicrosoftTpm" -ClassName Win32_Tpm -ErrorAction Stop
            $tpmVersion = $tpm.SpecVersion
        } catch {
            $tpmVersion = "Not Present / Inaccessible"
        }
    } else {
        $tpmVersion = "SKIPPED"
    }

    # Antivirus info (Windows Security Center)
    Write-Progress -Activity 'Taking System Inventory' -PercentComplete ($currentTask.Value++/$tasks*100) -Status 'Collecting Antivirus Information'
    try {
        $avProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop
        $avList = ($avProducts | Select-Object -ExpandProperty displayName) -join "`n"
    } catch {
        $avList = "Unable to retrieve"
    }
    Start-Sleep -Milliseconds $sleep

    Write-Progress -Activity 'Taking System Inventory' -Status "Complete" -Completed

    # Build custom object
    $computerInfo = [PSCustomObject]@{
        Hostname    = $env:COMPUTERNAME
        Make        = $system.Manufacturer
        Model       = $system.Model
        OS          = "$($os.Caption) $($osVersion)"
        CPU         = ($cpu | ForEach-Object { $_.Name }) -join "`n"
        Memory      = "$([Math]::Round($system.TotalPhysicalMemory / 1GB, 2)) GB"
        VideoCards  = ($gpu | ForEach-Object { $_.Name }) -join "`n"
        Storage     = ($drives | ForEach-Object {
                            $sizeGB = [Math]::Round($_.Size / 1GB, 0)
                            "$($_.Model) - ${sizeGB} GB"
                        }) -join "`n"
        StorageFree = ($volumes | ForEach-Object {
                            $freeGB  = [Math]::Round($_.FreeSpace / 1GB, 0)
                            $totalGB = [Math]::Round($_.Size / 1GB, 0)
                            "$($_.DeviceID) ${freeGB}GB free of ${totalGB} GB"
                        }) -join "`n"
        TPMVersion  = $tpmVersion
        Antivirus   = $avList
    }

    # Show results
    $computerInfo | Format-List

    if($isWin10) {
        $diskNumber = (Get-Partition -DriveLetter C).DiskNumber
        $partitionStyle = (Get-Disk -Number $diskNumber).PartitionStyle
        if($isAdmin){
            $SecureBoot = Confirm-SecureBootUEFI
        } else {
            $SecureBoot = "SKIPPED"
        }

        $supports11 = [PSCustomObject]@{
            PartitionStyle = $partitionStyle
            FirmwareMode = $env:firmware_type
            SecureBoot = $SecureBoot
        }
        
        Write-Header "Windows 11 Support info"
        $supports11 | Format-List
    }
    
    #Ask to save info
    $SaveInfo = $Host.UI.PromptForChoice("Save system inventory", "Do you want to save to file?", @('&Yes', '&No'), 0)
    if($SaveInfo -eq 0){
        $computerInfo | Format-List | Out-File -FilePath "$BenchmarkComputersPath\SystemInfo-$env:COMPUTERNAME.txt"
        if($isWin10){
            $supports11 | Format-List | Out-File -Append -FilePath "$BenchmarkComputersPath\Systeminfo-$env:COMPUTERNAME.txt"
        }
        Write-Host "Saved to $BenchmarkComputersPath\SystemInfo.txt"
        Pause
    }
}

function Install-RMM {
    Clear-Host
    $AgentUrl = "https://rmm.syncromsp.com/dl/rs/djEtMzQ3NTUwMDgtMTc5NjAwODEyMS03MTA3MC00NzAzOTI4"
    $SavePath = "$BenchmarkComputersPath\SyncroRmmSetup.exe"

    #Download installer
    try {
        Write-Header "Downloading RMM Agent"
        Invoke-WebRequest -Uri $AgentUrl -OutFile $SavePath -PassThru | Out-Null
        Write-Host "Saved file to $SavePath" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to download RMM Agent"
        Write-Host "Error Message: $($_.Exception.Message)"
        Write-Host "Error Category: $($_.CategoryInfo.Category)"
        Write-Host "Full Error Details:"
        $_ | Format-List # Display all properties of the error object
        return
    }    

    #Install
    try {
        Write-Header "Installing RMM Agent"
        Start-Process $SavePath -Wait
        Write-Host "Successfully installed RMM agent"
        Write-Host "It will be under the account `"Benchmark RMM`"."
        Write-Host "Asset Name: $env:COMPUTERNAME"
    }
    catch {
        Write-Error "Failed to install RMM Agent"
        Write-Host "Error Message: $($_.Exception.Message)"
        Write-Host "Error Category: $($_.CategoryInfo.Category)"
        Write-Host "Full Error Details:"
        $_ | Format-List # Display all properties of the error object
    }
    Pause
}

function Repair-WindowsImage {
    $RunTimestamp = [datetime]::Now.ToString("yyyyMMdd-HHmmss")
    Clear-Host
    
    Write-Header "Running Component Clanup"
    DISM /Online /Cleanup-Image /StartComponentCleanup

    Write-Header "Running Restore Health"
    DISM /Online /Cleanup-Image /RestoreHealth

    Write-Header "Backing up current CBS.log"
    Copy-Item -Path "$env:windir\Logs\CBS\CBS.log" -Destination "$BenchmarkComputersPath\CBS.log.$RunTimestamp.before.log" -Force
    Write-Host "Wrote $BenchmarkComputersPath\CBS.log.$RunTimestamp.before.log" -ForegroundColor Green
    Stop-Service TrustedInstaller
    Remove-Item -Path "$env:windir\Logs\CBS\CBS.log" -Force -ErrorAction SilentlyContinue
    Start-Service TrustedInstaller

    Write-Header "Running System File Checker"
    SFC /scannow

    Write-Header "Backing up CBS.log after repairs"
    Copy-Item -Path "$env:windir\Logs\CBS\CBS.log" -Destination "$BenchmarkComputersPath\CBS.log.$RunTimestamp.after.log" -Force
    Write-Host "Wrote $BenchmarkComputersPath\CBS.log.$RunTimestamp.after.log" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "Windows Image repair completed." -ForegroundColor Green
    Pause
}

function Repair-WindowsUpdate {
    Clear-Host
    Write-Host "1. Stopping Windows Update Services..."
    Stop-Service -Name BITS -Force
    Stop-Service -Name wuauserv -Force
    Stop-Service -Name cryptsvc -Force
    
    Write-Host "2. Remove QMGR Data file..." 
    Remove-Item -Path "$env:allusersprofile\Application Data\Microsoft\Network\Downloader\qmgr*.dat" -ErrorAction SilentlyContinue 
    
    Write-Host "3. Removing the Software Distribution and CatRoot Folder..." 
    Remove-Item -Path "$env:systemroot\SoftwareDistribution" -ErrorAction SilentlyContinue -Recurse
    Remove-Item -Path "$env:systemroot\System32\Catroot2" -ErrorAction SilentlyContinue -Recurse
    
    Write-Host "4. Resetting the Windows Update Services to defualt settings..." 
    Start-Process "sc.exe" -ArgumentList "sdset bits D:(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
    Start-Process "sc.exe" -ArgumentList "sdset wuauserv D:(A;;CCLCSWRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"
    
    Set-Location $env:systemroot\system32 
    
    Write-Host "5. Registering some DLLs..." 
    regsvr32.exe atl.dll /s
    regsvr32.exe urlmon.dll /s
    regsvr32.exe mshtml.dll /s
    regsvr32.exe shdocvw.dll /s
    regsvr32.exe browseui.dll /s
    regsvr32.exe jscript.dll /s
    regsvr32.exe vbscript.dll /s
    regsvr32.exe scrrun.dll /s
    regsvr32.exe msxml.dll /s
    regsvr32.exe msxml3.dll /s
    regsvr32.exe msxml6.dll /s
    regsvr32.exe actxprxy.dll /s
    regsvr32.exe softpub.dll /s
    regsvr32.exe wintrust.dll /s
    regsvr32.exe dssenh.dll /s
    regsvr32.exe rsaenh.dll /s
    regsvr32.exe gpkcsp.dll /s
    regsvr32.exe sccbase.dll /s
    regsvr32.exe slbcsp.dll /s
    regsvr32.exe cryptdlg.dll /s
    regsvr32.exe oleaut32.dll /s
    regsvr32.exe ole32.dll /s
    regsvr32.exe shell32.dll /s
    regsvr32.exe initpki.dll /s
    regsvr32.exe wuapi.dll /s
    regsvr32.exe wuaueng.dll /s
    regsvr32.exe wuaueng1.dll /s
    regsvr32.exe wucltui.dll /s
    regsvr32.exe wups.dll /s
    regsvr32.exe wups2.dll /s
    regsvr32.exe wuweb.dll /s
    regsvr32.exe qmgr.dll /s
    regsvr32.exe qmgrprxy.dll /s
    regsvr32.exe wucltux.dll /s
    regsvr32.exe muweb.dll /s
    regsvr32.exe wuwebv.dll /s
    
    Write-Host "6) Resetting the WinSock..." 
    netsh winsock reset 

    Write-Host "7) Starting Windows Update Services..." 
    Start-Service -Name BITS 
    Start-Service -Name wuauserv 
    Start-Service -Name cryptsvc 
    
    Write-Host "8) Forcing discovery..." 
    #wuauclt /resetauthorization /detectnow 
    USOClient.exe RefreshSettings
    USOClient.exe StartScan
    
    Write-Host "Process complete. Please reboot your computer."
    Pause
}

function Install-ActiveBackup {
    $ABCommand = "winget install --id=Synology.ActiveBackupForBusinessAgent -e --accept-source-agreements --accept-package-agreements"

    #Ask if this is for safetynet or not
    $options = @(
        [System.Management.Automation.Host.ChoiceDescription]::new("&Yes", "Configure Active Backup to connect to Scruffy with the safetynet user.")
        [System.Management.Automation.Host.ChoiceDescription]::new("&No", "Manually configure Active Backup after intall.")
        [System.Management.Automation.Host.ChoiceDescription]::new("&Cancel", "Cancel installing Active Backup.")
    )
    $safetynet = $Host.UI.PromptForChoice("Install Active Backup Agent", "Do you want to setup for safetynet?", $options, 1)

    switch ($safetynet) {
        0 { 
            #Yes
            $server = "10.0.1.1"
            $username = $password = "safetynet"
            $ABCommand += " --override `"ADDRESS=```"$server```" USERNAME=$username PASSWORD=$password ALLOW_UNTRUST=1 /qn`""
        }
        1 {
            #No
        }
        2 {
            #Cancel
            return
        }
        Default {
            Write-Host "Invalid Choice" -ForegroundColor Red
        }
    }
    Invoke-Command $ABCommand
    
}

#Menu options
$MenuData = [PSCustomObject]@{Id = 1; DisplayName = "Get System Information"; RequireAdmin = $false}, `
            [PSCustomObject]@{Id = 2; DisplayName = "Run DISM and SFC"; RequireAdmin = $true}, `
            [PSCustomObject]@{Id = 3; DisplayName = "Fix Windows Updates"; RequireAdmin = $true}, `
            [PSCustomObject]@{Id = 4; DisplayName = "Install RMM Agent"; RequireAdmin = $false}, `
            [PSCustomObject]@{Id = 5; DisplayName = "Install Active Backup Agent"; RequireAdmin = $true}, `
            [PSCustomObject]@{Id = 99; DisplayName = "Quit"; RequireAdmin = $false}
$exit = $false

do {
    Clear-Host
    Write-Host $banner -ForegroundColor Blue

    $SelectedItem = Show-Menu -DynamicMenuList $MenuData

    #Block admin sctips
    if(-not $isAdmin -and $SelectedItem.RequireAdmin){
        Clear-Host
        Write-Host ""
        Write-Host ""
        Write-Host "$($PSStyle.Bold)Script can not be run as a Standard user. Please run as Administrator$($PSStyle.BoldOff)" -ForegroundColor Red
        Write-Host ""
        Write-Host ""
        Pause
        Continue
    }

    switch ($SelectedItem.Id) {
        1 { Get-SystemInfo }
        2 { Repair-WindowsImage }
        3 { Repair-WindowsUpdate }
        4 { Install-RMM }
        5 { Install-ActiveBackup }
        99 { $exit = $true }
    }
} until ($exit -eq $true)