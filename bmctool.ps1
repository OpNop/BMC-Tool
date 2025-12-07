#Set colors for Windows 10
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ForegroundColor = "White"
clear-host

#Variables
$BenchmarkComputersPath = "C:\Benchmark Computers"
$currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

#Create Benchmark Computers folder
New-item -ItemType Directory -Force -Path $BenchmarkComputersPath | Out-Null

function Show-Menu {
    Clear-Host
    Write-Host "==== Benchmark Computers Tools ====" -ForegroundColor DarkCyan
    Write-Host "1. System Information" -ForegroundColor DarkCyan
    Write-Host "2. Repair Windows Image" -ForegroundColor DarkCyan
    Write-Host "3. Repair Windows Update" -ForegroundColor DarkCyan
    Write-Host "4. Exit" -ForegroundColor DarkCyan
}

function Get-SystemInfo {
    Clear-Host
    # number of tasks for the progress bar
    $tasks = 8
    [Ref]$currentTask = 0
    $sleep = 250

    Clear-Host
    Write-Host " ____  __  __  ____   ___        __       "
    Write-Host "| __ )|  \/  |/ ___| |_ _|_ __  / _| ___  "
    Write-Host "|  _ \| |\/| | |      | || '_ \| |_ / _ \ "
    Write-Host "| |_) | |  | | |___   | || | | |  _| (_) |"
    Write-Host "|____/|_|  |_|\____| |___|_| |_|_|  \___/ "
    Write-Host " v1.0 by Don Gordon"
    Write-Host ""
    Write-Host ""
    if(-not $isAdmin) {
    Write-Host "Not running as admin, supported TPM versions will not be checked" -ForegroundColor Red
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
        $supports11 = [PSCustomObject]@{
            PartitionStyle = $partitionStyle
            FirmwareMode = $env:firmware_type
        }
        
        Write-Host "------------------------------------------------------"
        Write-Host "               Windows 11 Support info                "
        Write-Host "------------------------------------------------------"
        $supports11 | Format-List
    }
    Pause
}

function Repair-WindowsImage {
    Clear-Host
    
    Write-Host "Running Component Clanup" -ForegroundColor Yellow
    DISM /Online /Cleanup-Image /StartComponentCleanup

    Write-Host "Running Restore Health" -ForegroundColor Yellow
    DISM /Online /Cleanup-Image /RestoreHealth

    Write-Host "Backing up current CBS.log" -ForegroundColor Yellow
    Copy-Item -Path "$env:windir\Logs\CBS\CBS.log" -Destination "$BenchmarkComputersPath\CBS.log.copy.$([datetime]::Now.ToString("yyyyMMdd-HHmmss")).log" -Force
    Remove-Item -Path "$env:windir\Logs\CBS\CBS.log" -Force -ErrorAction SilentlyContinue

    Write-Host "Running System File Checker" -ForegroundColor Yellow
    SFC /scannow

    Write-Host "Backing up CBS.log after repairs" -ForegroundColor Yellow
    Copy-Item -Path "$env:windir\Logs\CBS\CBS.log" -Destination "$BenchmarkComputersPath\CBS.log.after.$([datetime]::Now.ToString("yyyyMMdd-HHmmss")).log" -Force
    
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

if(-not $isAdmin) {
    Write-Host "Warning: This script must be running with administrative privileges" -ForegroundColor Red
    pause
    exit
}

do {
    #Display Menu
    Show-Menu
    Write-Host "Please select an option (1-4)" -ForegroundColor DarkGreen
    $choice = Read-Host 
    
    switch ($choice) {
        "1" { Get-SystemInfo }
        "2" { Repair-WindowsImage }
        "3" { Repair-WindowsUpdate }
        "4" { break}
        default { Write-Host "Invalid selection. Please try again." ; Pause }
    }
} until ($choice -eq "4")