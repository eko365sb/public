<#
.SYNOPSIS
    .Removes manufacturer bloat from a fresh Windows build
.DESCRIPTION
    .Removes HP Bloat
    .Removes Dell Bloat
    .Removes Lenovo Bloat
    
.INPUTS
.OUTPUTS
    C:\ProgramData\ManuDebloat\ManuDebloat.log
.NOTES
    Version:        1.0.1
    Author:         Andrew Taylor - Fabio Secchia
    WWW:            eko365.it
    Creation Date:  16/09/2023
    Purpose/Change: Initial script development carved out from RemoveBloat.ps1 Andrew Taylor Script
    Change 15/09/2023 - Fixed an error (calling a function before setting var value)
.EXAMPLE
    N/A
#>

############################################################################################################
#                                         Initial Setup                                                    #
#                                                                                                          #
############################################################################################################

##Elevate if needed

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Write-Host "You didn't run this script as an Administrator. This script will self elevate to run as an Administrator and continue."
    Start-Sleep 1
    Write-Host "                                               3"
    Start-Sleep 1
    Write-Host "                                               2"
    Start-Sleep 1
    Write-Host "                                               1"
    Start-Sleep 1
    Start-Process powershell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit
}

#no errors throughout
$ErrorActionPreference = 'silentlycontinue'

Function Get-ScriptVersion(){
    
    <#
    .SYNOPSIS
        This function is used to check if the running script is the latest version
    .DESCRIPTION
        This function checks GitHub and compares the 'live' version with the one running
    .EXAMPLE
        Get-ScriptVersion
        Returns a warning and URL if outdated
    .NOTES
        NAME: Get-ScriptVersion
    #>
    
    [cmdletbinding()]
    
    param
    (
        $liveuri
    )
    $contentheaderraw = (Invoke-WebRequest -Uri $liveuri -Method Get)
    $contentheader = $contentheaderraw.Content.Split([Environment]::NewLine)
    $liveversion = (($contentheader | Select-String 'Version:') -replace '[^0-9.]','') | Select-Object -First 1
    $currentversion = ((Get-Content -Path $PSCommandPath | Select-String -Pattern "Version: *") -replace '[^0-9.]','') | Select-Object -First 1
    if ($liveversion -ne $currentversion) {
        write-host "Script has been updated, please download the latest version from $liveuri" -ForegroundColor Red
    }
}
Get-ScriptVersion -liveuri "https://raw.githubusercontent.com/eko365sb/public/main/de-bloat/RemoveManuBloat.ps1"


#Create Folder
$DebloatFolder = "C:\ProgramData\ManuDebloat"
If (Test-Path $DebloatFolder) {
    Write-Output "$DebloatFolder exists. Skipping."
}
Else {
    Write-Output "The folder '$DebloatFolder' doesn't exist. This folder will be used for storing logs created after the script runs. Creating now."
    Start-Sleep 1
    New-Item -Path "$DebloatFolder" -ItemType Directory
    Write-Output "The folder $DebloatFolder was successfully created."
}

Start-Transcript -Path "C:\ProgramData\ManuDebloat\ManuDebloat.log"

$locale = Get-WinSystemLocale | Select-Object -expandproperty Name

##Switch on locale to set variables
## Switch on locale to set variables
switch ($locale) {
    "en-US" {
        $everyone = "Everyone"
        $builtin = "Builtin"
    }    
    "en-GB" {
        $everyone = "Everyone"
        $builtin = "Builtin"
    }
    "it-IT" {
        $everyone = "Tutti"
        $builtin = "Incorporato"
    }
    default {
        $everyone = "Everyone"
        $builtin = "Builtin"
    }
}

############################################################################################################
#                                        Remove Manufacturer Bloat                                         #
#                                                                                                          #
############################################################################################################
##Check Manufacturer
write-host "Detecting Manufacturer"
$details = Get-CimInstance -ClassName Win32_ComputerSystem
$manufacturer = $details.Manufacturer

#region HP
if ($manufacturer -like "*HP*") {
    Write-Host "HP detected"
    #Remove HP bloat

    ##HP Specific
    $UninstallPrograms = @(
        "HP Client Security Manager"
        "HP Notifications"
        "HP Security Update Service"
        "HP System Default Settings"
        "HP Wolf Security"
        "HP Wolf Security Application Support for Sure Sense"
        "HP Wolf Security Application Support for Windows"
        "AD2F1837.HPPCHardwareDiagnosticsWindows"
        "AD2F1837.HPPowerManager"
        "AD2F1837.HPPrivacySettings"
        "AD2F1837.HPQuickDrop"
        "AD2F1837.HPSupportAssistant"
        "AD2F1837.HPSystemInformation"
        "AD2F1837.myHP"
        "RealtekSemiconductorCorp.HPAudioControl",
        "HP Sure Recover",
        "HP Sure Run Module"
        "HP Google Drive Plugin"
        "HP Dropbox Plugin"
        "HP Assess and Respond"
    )

    $HPidentifier = "AD2F1837"
    $InstalledPackages = Get-AppxPackage -AllUsers | Where-Object {($UninstallPackages -contains $_.Name) -or ($_.Name -match "^$HPidentifier")}
    $ProvisionedPackages = Get-AppxProvisionedPackage -Online | Where-Object {($UninstallPackages -contains $_.DisplayName) -or ($_.DisplayName -match "^$HPidentifier")}
    $InstalledPrograms = Get-Package | Where-Object {$UninstallPrograms -contains $_.Name}

    # Remove provisioned packages first
    ForEach ($ProvPackage in $ProvisionedPackages) {

        Write-Host -Object "Attempting to remove provisioned package: [$($ProvPackage.DisplayName)]..."

        Try {
            $Null = Remove-AppxProvisionedPackage -PackageName $ProvPackage.PackageName -Online -ErrorAction Stop
            Write-Host -Object "Successfully removed provisioned package: [$($ProvPackage.DisplayName)]"
        }
        Catch {Write-Warning -Message "Failed to remove provisioned package: [$($ProvPackage.DisplayName)]"}
    }

    # Remove appx packages
    ForEach ($AppxPackage in $InstalledPackages) {
                                                
        Write-Host -Object "Attempting to remove Appx package: [$($AppxPackage.Name)]..."

        Try {
            $Null = Remove-AppxPackage -Package $AppxPackage.PackageFullName -AllUsers -ErrorAction Stop
            Write-Host -Object "Successfully removed Appx package: [$($AppxPackage.Name)]"
        }
        Catch {Write-Warning -Message "Failed to remove Appx package: [$($AppxPackage.Name)]"}
    }

    # Remove installed programs
    $InstalledPrograms | ForEach-Object {

        Write-Host -Object "Attempting to uninstall: [$($_.Name)]..."

        Try {
            $Null = $_ | Uninstall-Package -AllVersions -Force -ErrorAction Stop
            Write-Host -Object "Successfully uninstalled: [$($_.Name)]"
        }
        Catch {Write-Warning -Message "Failed to uninstall: [$($_.Name)]"}
    }


    #Remove HP Documentation
    $A = Start-Process -FilePath "C:\Program Files\HP\Documentation\Doc_uninstall.cmd" -Wait -passthru -NoNewWindow;$a.ExitCode

    ##Remove Standard HP apps via msiexec
    $InstalledPrograms | ForEach-Object {
    $appname = $_.Name
        Write-Host -Object "Attempting to uninstall: [$($_.Name)]..."

        Try {
            $Prod = Get-WMIObject -Classname Win32_Product | Where-Object Name -Match $appname
            $Prod.UnInstall()
            Write-Host -Object "Successfully uninstalled: [$($_.Name)]"
        }
        Catch {Write-Warning -Message "Failed to uninstall: [$($_.Name)]"}
    }

    ##Remove HP Connect Optimizer
    invoke-webrequest -uri "https://raw.githubusercontent.com/eko365sb/public/main/de-bloat/HPConnOpt.iss" -outfile "C:\Windows\Temp\HPConnOpt.iss"

    &'C:\Program Files (x86)\InstallShield Installation Information\{6468C4A5-E47E-405F-B675-A70A70983EA6}\setup.exe' @('-s', '-f1C:\Windows\Temp\HPConnOpt.iss')

    Write-Host "Removed HP bloat"
}
#endregion

#region Dell
if ($manufacturer -like "*Dell*") {
    Write-Host "Dell detected"
    #Remove Dell bloat

    ##Dell

    $UninstallPrograms = @(
        "Dell Optimizer"
        "Dell Power Manager"
        "DellOptimizerUI"
        "Dell SupportAssist OS Recovery"
        "Dell SupportAssist"
        "Dell Optimizer Service"
        "DellInc.PartnerPromo"
        "DellInc.DellOptimizer"
        "DellInc.DellCommandUpdate"
    )

    $WhitelistedApps = @(
        "WavesAudio.MaxxAudioProforDell2019"
        "Dell - Extension*"
        "Dell, Inc. - Firmware*"
    )

    $InstalledPackages = Get-AppxPackage -AllUsers | Where-Object {(($_.Name -in $UninstallPrograms) -or ($_.Name -like "*Dell*")) -and ($_.Name -NotMatch $WhitelistedApps)}
    $ProvisionedPackages = Get-AppxProvisionedPackage -Online | Where-Object { ($_.Name -in $UninstallPrograms) -and ($_.Name -NotMatch $WhitelistedApps)}
    $InstalledPrograms = Get-Package | Where-Object {($_.Name -in $UninstallPrograms) -and ($_.Name -NotMatch $WhitelistedApps)}

    # Remove provisioned packages first
    ForEach ($ProvPackage in $ProvisionedPackages) {

        Write-Host -Object "Attempting to remove provisioned package: [$($ProvPackage.DisplayName)]..."

        Try {
            $Null = Remove-AppxProvisionedPackage -PackageName $ProvPackage.PackageName -Online -ErrorAction Stop
            Write-Host -Object "Successfully removed provisioned package: [$($ProvPackage.DisplayName)]"
        }
        Catch {Write-Warning -Message "Failed to remove provisioned package: [$($ProvPackage.DisplayName)]"}
    }

    # Remove appx packages
    ForEach ($AppxPackage in $InstalledPackages) {
                                                
        Write-Host -Object "Attempting to remove Appx package: [$($AppxPackage.Name)]..."

        Try {
            $Null = Remove-AppxPackage -Package $AppxPackage.PackageFullName -AllUsers -ErrorAction Stop
            Write-Host -Object "Successfully removed Appx package: [$($AppxPackage.Name)]"
        }
        Catch {Write-Warning -Message "Failed to remove Appx package: [$($AppxPackage.Name)]"}
    }

    # Remove any bundled packages
    ForEach ($AppxPackage in $InstalledPackages) {
                                                
        Write-Host -Object "Attempting to remove Appx package: [$($AppxPackage.Name)]..."

        Try {
            $null = Get-AppxPackage -AllUsers -PackageTypeFilter Main, Bundle, Resource -Name $AppxPackage.Name | Remove-AppxPackage -AllUsers
            Write-Host -Object "Successfully removed Appx package: [$($AppxPackage.Name)]"
        }
        Catch {Write-Warning -Message "Failed to remove Appx package: [$($AppxPackage.Name)]"}
    }

    # Remove installed programs
    $InstalledPrograms | ForEach-Object {

        Write-Host -Object "Attempting to uninstall: [$($_.Name)]..."

        Try {
            $Null = $_ | Uninstall-Package -AllVersions -Force -ErrorAction Stop
            Write-Host -Object "Successfully uninstalled: [$($_.Name)]"
        }
        Catch {Write-Warning -Message "Failed to uninstall: [$($_.Name)]"}
    }

}
#endregion

#region Lenovo
if ($manufacturer -like "Lenovo") {
    Write-Host "Lenovo detected"

   
    ##Lenovo Specific
    # Function to uninstall applications with .exe uninstall strings

    function UninstallApp {

        param (
            [string]$appName
        )

        # Get a list of installed applications from Programs and Features
        $installedApps = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
        HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
        Where-Object { $_.DisplayName -like "*$appName*" }

        # Loop through the list of installed applications and uninstall them

        foreach ($app in $installedApps) {
            $uninstallString = $app.UninstallString
            $displayName = $app.DisplayName
            Write-Host "Uninstalling: $displayName"
            Start-Process $uninstallString -ArgumentList "/VERYSILENT" -Wait
            Write-Host "Uninstalled: $displayName" -ForegroundColor Green
        }
    }

    ##Stop Running Processes

    $processnames = @(
    "SmartAppearanceSVC.exe"
    "UDClientService.exe"
    "ModuleCoreService.exe"
    "ProtectedModuleHost.exe"
    "*lenovo*"
    "FaceBeautify.exe"
    "McCSPServiceHost.exe"
    "mcapexe.exe"
    "MfeAVSvc.exe"
    "mcshield.exe"
    "Ammbkproc.exe"
    "AIMeetingManager.exe"
    "DADUpdater.exe"
    )

    foreach ($process in $processnames) {
        write-host "Stopping Process $process"
        Get-Process -Name $process | Stop-Process -Force
        write-host "Process $process Stopped"
    }

    $UninstallPrograms = @(
        "E046963F.AIMeetingManager"
        "E0469640.SmartAppearance"
        "MirametrixInc.GlancebyMirametrix"
        "E046963F.LenovoCompanion"
        "E0469640.LenovoUtility"
    )


    $InstalledPackages = Get-AppxPackage -AllUsers | Where-Object {(($_.Name -in $UninstallPrograms))}

    $ProvisionedPackages = Get-AppxProvisionedPackage -Online | Where-Object {(($_.Name -in $UninstallPrograms))}

    $InstalledPrograms = Get-Package | Where-Object {(($_.Name -in $UninstallPrograms))}

    # Remove provisioned packages first
    ForEach ($ProvPackage in $ProvisionedPackages) {

        Write-Host -Object "Attempting to remove provisioned package: [$($ProvPackage.DisplayName)]..."

        Try {
            $Null = Remove-AppxProvisionedPackage -PackageName $ProvPackage.PackageName -Online -ErrorAction Stop
            Write-Host -Object "Successfully removed provisioned package: [$($ProvPackage.DisplayName)]"
        }
        Catch {Write-Warning -Message "Failed to remove provisioned package: [$($ProvPackage.DisplayName)]"}
    }

    # Remove appx packages
    ForEach ($AppxPackage in $InstalledPackages) {
                                                
        Write-Host -Object "Attempting to remove Appx package: [$($AppxPackage.Name)]..."

        Try {
            $Null = Remove-AppxPackage -Package $AppxPackage.PackageFullName -AllUsers -ErrorAction Stop
            Write-Host -Object "Successfully removed Appx package: [$($AppxPackage.Name)]"
        }
        Catch {Write-Warning -Message "Failed to remove Appx package: [$($AppxPackage.Name)]"}
    }

    # Remove any bundled packages
    ForEach ($AppxPackage in $InstalledPackages) {
                                                
        Write-Host -Object "Attempting to remove Appx package: [$($AppxPackage.Name)]..."

        Try {
            $null = Get-AppxPackage -AllUsers -PackageTypeFilter Main, Bundle, Resource -Name $AppxPackage.Name | Remove-AppxPackage -AllUsers
            Write-Host -Object "Successfully removed Appx package: [$($AppxPackage.Name)]"
        }
        Catch {Write-Warning -Message "Failed to remove Appx package: [$($AppxPackage.Name)]"}
    }


    # Remove installed programs
    $InstalledPrograms | ForEach-Object {

        Write-Host -Object "Attempting to uninstall: [$($_.Name)]..."

        Try {
            $Null = $_ | Uninstall-Package -AllVersions -Force -ErrorAction Stop
            Write-Host -Object "Successfully uninstalled: [$($_.Name)]"
        }
        Catch {Write-Warning -Message "Failed to uninstall: [$($_.Name)]"}
    }

    # Get Lenovo Vantage service uninstall string to uninstall service
    $lvs = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object DisplayName -eq "Lenovo Vantage Service"
    if (!([string]::IsNullOrEmpty($lvs.QuietUninstallString))) {
        $uninstall = "cmd /c " + $lvs.QuietUninstallString
        Write-Host $uninstall
        Invoke-Expression $uninstall
    }

    # Uninstall Lenovo Smart
    UninstallApp -appName "Lenovo Smart"

    # Uninstall Ai Meeting Manager Service
    UninstallApp -appName "Ai Meeting Manager"

    # Uninstall ImController service
    Invoke-Expression -Command 'cmd.exe /c "c:\windows\system32\ImController.InfInstaller.exe" -uninstall'

    # Remove vantage associated registry keys
    Remove-Item 'HKLM:\SOFTWARE\Policies\Lenovo\E046963F.LenovoCompanion_k1h2ywk1493x8' -Recurse -ErrorAction SilentlyContinue
    Remove-Item 'HKLM:\SOFTWARE\Policies\Lenovo\ImController' -Recurse -ErrorAction SilentlyContinue
    Remove-Item 'HKLM:\SOFTWARE\Policies\Lenovo\Lenovo Vantage' -Recurse -ErrorAction SilentlyContinue
    Remove-Item 'HKLM:\SOFTWARE\Policies\Lenovo\Commercial Vantage' -Recurse -ErrorAction SilentlyContinue

    # Uninstall AI Meeting Manager Service
    Invoke-Expression -Command 'cmd.exe /c "C:\Program Files\Lenovo\Ai Meeting Manager Service\unins000.exe" /SILENT'

    # Uninstall Lenovo Vantage
    Invoke-Expression -Command 'cmd.exe /c "C:\Program Files (x86)\Lenovo\VantageService\3.13.43.0\Uninstall.exe" /SILENT'

    ##Uninstall Smart Appearance
    Invoke-Expression -Command 'cmd.exe /c "C:\Program Files\Lenovo\Lenovo Smart Appearance Components\unins000.exe" /SILENT'

    # Remove Lenovo Now
    Set-Location "c:\program files (x86)\lenovo\lenovowelcome\x86"

    # Update $PSScriptRoot with the new working directory
    $PSScriptRoot = (Get-Item -Path ".\").FullName
    invoke-expression -command .\uninstall.ps1

    Write-Host "All applications and associated Lenovo components have been uninstalled." -ForegroundColor Green
}
#endregion 

write-host "Completed"
Stop-Transcript
