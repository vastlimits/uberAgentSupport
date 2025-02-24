#Requires -Version 5.1
#Requires -RunAsAdministrator
Function New-uASupportBundle {
    [CmdletBinding(SupportsShouldProcess = $False)]
    PARAM
    (

    )

    Begin {
        $ErrorActionPreference = 'Stop'
        Try {
            $stopWatch = [system.diagnostics.stopwatch]::startNew()
            $stopWatch.Start()

            # Evaluate log file path
            $null = $LogPath
            if (Test-Path "HKLM:\SOFTWARE\Policies\vast limits\uberAgent\LogConfig") {
                $LogPath = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\vast limits\uberAgent\LogConfig" -Name LogPath -ErrorAction SilentlyContinue
            }
            if (-not $LogPath) {
                if (Test-Path "HKLM:\SOFTWARE\vast limits\uberAgent\LogConfig") {
                    $LogPath = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\vast limits\uberAgent\LogConfig" -Name LogPath -ErrorAction SilentlyContinue
                }
                else {
                    Write-Verbose "LogPath not found in 'HKLM:\SOFTWARE\Policies\vast limits\uberAgent\LogConfig'. Trying 'HKLM:\SOFTWARE\vast limits\uberAgent\LogConfig'." -Verbose
                }
            }
            else {
                Write-Verbose "LogPath found in 'HKLM:\SOFTWARE\Policies\vast limits\uberAgent\LogConfig'." -Verbose
            }
            if (-not $LogPath)
            {
                Write-Verbose "LogPath not found in 'HKLM:\SOFTWARE\vast limits\uberAgent\LogConfig'. Using default path." -Verbose
                $LogPath = "$env:windir\temp"
            }
            else
            {
                Write-Verbose "LogPath found in 'HKLM:\SOFTWARE\Policies\vast limits\uberAgent\LogConfig'." -Verbose
            }
            
            $ResolvedLogPath = [System.Environment]::ExpandEnvironmentVariables($LogPath)
            Write-Verbose "Resolved log path: $ResolvedLogPath" -Verbose

            # Test access to log path
            if (-not $(Test-Path -Path $ResolvedLogPath))
            {
                Throw "Log path '$ResolvedLogPath' not found. Please check the log path configuration or verify that you have the permissions to access the log path."
            }

            $uAServiceLogs = [System.IO.Path]::Combine($ResolvedLogPath, "uberAgent*.log")
            $uAServiceConfigurationLogs = [System.IO.Path]::Combine($ResolvedLogPath, "uberAgentServiceConfig*.log")
            if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList') {
                $ProfilesDirectory = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Name ProfilesDirectory
            } else {
                Throw "Registry key 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' not found."
            }
            $uAInSessionHelperLog = [System.IO.Path]::Combine($ResolvedLogPath, "uAInSessionHelper.log")
            $ProfilesDirectory = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Name ProfilesDirectory
            $UserProfiles = (Get-ChildItem -Path $ProfilesDirectory -Directory -Exclude 'Public').Name
            $WorkingDirectory = [System.IO.Path]::Combine($env:temp, "uASupport")
            $PowerShellLog = [System.IO.Path]::Combine($WorkingDirectory, "PowerShellTranskript.log")
            $OperatingSystem = (Get-CimInstance -Class Win32_OperatingSystem).caption
            $DesktopPath = [Environment]::GetFolderPath('Desktop')
            $OSBitness = $env:PROCESSOR_ARCHITECTURE
            $Processes = @('uberAgent','uAInSessionHelper')
            $UninstallPaths = @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
            $uberAgentInstallDir = ($UninstallPaths | ForEach-Object {Get-ItemProperty $_} | Where-Object Displayname -match "uberAgent").InstallLocation
            $SplunkUFservice = "SplunkForwarder"
            $ExcludeExecutablesAndLibraries = @('*.exe','*.dll','*.sys','*.msi')

            $RegKeysx86 = @(
                [PSCustomObject]@{Component = 'Service'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\vast limits' }
                [PSCustomObject]@{Component = 'Service'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\vast limits' }
                [PSCustomObject]@{Component = 'Chrome'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Google\Chrome\NativeMessagingHosts\com.vastlimits.uainsessionhelper' }
                [PSCustomObject]@{Component = 'Firefox'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Mozilla\NativeMessagingHosts\com.vastlimits.uainsessionhelper' }
                [PSCustomObject]@{Component = 'Internet Explorer'; Path = 'Registry::HKEY_CLASSES_ROOT\CLSID\{82004312-5B53-46F1-B179-4FCE28048E6F}\InProcServer32' }
                [PSCustomObject]@{Component = 'Internet Explorer'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\IEXPLORE.EXE' }
                [PSCustomObject]@{Component = 'Internet Explorer'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main' }
                [PSCustomObject]@{Component = 'Driver'; Path = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\UberAgentDrv' }
                [PSCustomObject]@{Component = 'Driver'; Path = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\uberAgentNetMon' }
            )

            $RegKeysx64 = @(
                [PSCustomObject]@{Component = 'Service'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\vast limits' }
                [PSCustomObject]@{Component = 'Service'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\vast limits' }
                [PSCustomObject]@{Component = 'Chrome'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Google\Chrome\NativeMessagingHosts\com.vastlimits.uainsessionhelper' }
                [PSCustomObject]@{Component = 'Firefox'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Mozilla\NativeMessagingHosts\com.vastlimits.uainsessionhelper' }
                [PSCustomObject]@{Component = 'Firefox'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Mozilla\NativeMessagingHosts\com.vastlimits.uainsessionhelper' }
                [PSCustomObject]@{Component = 'Internet Explorer'; Path = 'Registry::HKEY_CLASSES_ROOT\CLSID\{82004312-5B53-46F1-B179-4FCE28048E6F}\InProcServer32' }
                [PSCustomObject]@{Component = 'Internet Explorer'; Path = 'Registry::HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{82004312-5B53-46F1-B179-4FCE28048E6F}\InProcServer32' }
                [PSCustomObject]@{Component = 'Internet Explorer'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\IEXPLORE.EXE' }
                [PSCustomObject]@{Component = 'Internet Explorer'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main' }
                [PSCustomObject]@{Component = 'Driver'; Path = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\UberAgentDrv' }
                [PSCustomObject]@{Component = 'Driver'; Path = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\uberAgentNetMon' }
            )

            If ($OSBitness -eq 'AMD64') { $RegKeys = $RegKeysx64 } Else { $RegKeys = $RegKeysx86 }

            If ((Get-Service).Name -contains $SplunkUFservice) {
               $SplunkUFinstalled = $True
               $SplunkUFInstallDir = (($UninstallPaths | ForEach-Object {Get-ItemProperty $_} | Where-Object Displayname -match "UniversalForwarder").InstallLocation).TrimEnd("\")
               $Processes += 'splunkd'
            }
            Else {
               $SplunkUFinstalled = $False
            }

            # Check for latest module version
            $LatestModuleVersion = $null
            $LatestModuleVersion = (Find-uAModule -Name uberAgentSupport).properties.version

            If ($LatestModuleVersion) {
                $InstalledModuleVersion = (Get-Module uberAgentSupport).Version

                If ($LatestModuleVersion -gt $InstalledModuleVersion) {
                    Write-Warning "Module version in PowerShell Gallery is '$LatestModuleVersion' while you are using '$InstalledModuleVersion'. Please update to the latest version with 'Update-Module uberAgentSupport'."
                }
                If ($LatestModuleVersion -eq $InstalledModuleVersion) {
                    Write-Verbose "Latest uberAgentSupport module version '$LatestModuleVersion' is installed." -Verbose
                }
            }
            Else {
                Write-Warning "Not able to get latest module version from PowerShell Gallery. Please check manually if you are using the latest module version."
            }
        }
        Catch {
            $ErrorMessage = $_.Exception.Message
            Throw $ErrorMessage
        }
    }

    Process {
        $ErrorActionPreference = 'Continue'
        Try {
            Start-Transcript -Path $PowerShellLog | Out-Null
            Write-Verbose 'Start' -Verbose

            Write-Verbose "Create working directory $WorkingDirectory" -Verbose
            New-Item -Path $WorkingDirectory -ItemType Directory -Force | Out-Null

            #region log files
            Write-Verbose 'Collect uberAgent service logs' -Verbose
            Copy-uAItem -Source $uAServiceLogs -Destination "$WorkingDirectory\Service"

            Write-Verbose 'Collect uberAgent service configuration logs' -Verbose
            Copy-uAItem -Source $uAServiceConfigurationLogs -Destination "$WorkingDirectory\Service"

            Write-Verbose 'Collect In-Session helper log' -Verbose
            Copy-uAItem -Source $uAInSessionHelperLog -Destination "$WorkingDirectory\uAInSessionHelper"

            Write-Verbose 'Collect Chrome/Firefox browser extension in-session helper logs for all sessions' -Verbose
            

            foreach ($UserProfile in $UserProfiles) {
                $src = [System.IO.Path]::Combine($ProfilesDirectory, $UserProfile, "AppData\Local\Temp\uAInSessionHelper.log")
                $dst = [System.IO.Path]::Combine($WorkingDirectory, "Browser", "uAInSessionHelper-$UserProfile.log")

                Copy-uAItem -Source $src -Destination $dst
            }

            Write-Verbose 'Collect Internet Explorer add-on log' -Verbose
            foreach ($UserProfile in $UserProfiles) {
                $src = [System.IO.Path]::Combine($ProfilesDirectory, $UserProfile, "AppData\Local\Temp\Low\uberAgentIEExtension.log")
                $dst = [System.IO.Path]::Combine($WorkingDirectory, "Browser", "uberAgentIEExtension-$UserProfile.log")
                Copy-uAItem -Source $src -Destination $dst
            }

            Write-Verbose 'Collect Internet Explorer add-on log - Enhanced Protection Mode' -Verbose
            If ($OperatingSystem -match 'Microsoft Windows 7') {
                foreach ($UserProfile in $UserProfiles) {
                    $src = [System.IO.Path]::Combine($ProfilesDirectory, $UserProfile, "AppData\Local\Temp\Low\uberAgentIEExtension.log")
                    $dst = [System.IO.Path]::Combine($WorkingDirectory, "Browser", "uberAgentIEExtension-EPM-$UserProfile.log")
                    Copy-uAItem -Source $src -Destination $dst
                }
            }
            Else {
                foreach ($UserProfile in $UserProfiles) {
                    $src = [System.IO.Path]::Combine($ProfilesDirectory, $UserProfile, "AppData\Local\Packages\windows_ie_ac_001\AC\Temp\uberAgentIEExtension.log")
                    $dst = [System.IO.Path]::Combine($WorkingDirectory, "Browser", "uberAgentIEExtension-EPM-$UserProfile.log")
                    Copy-uAItem -Source $src -Destination $dst
                }
            }

            If($SplunkUFinstalled) {
                Write-Verbose 'Collect Splunk Universal Forwarder logs' -Verbose

                $src = [System.IO.Path]::Combine($SplunkUFInstallDir, "var\log\splunk\splunkd.log")
                $dst = [System.IO.Path]::Combine($WorkingDirectory, "SplunkUniversalForwarder", "splunkd.log")
                Copy-uAItem -Source $src -Destination $dst

                $src = [System.IO.Path]::Combine($SplunkUFInstallDir, "var\log\splunk\metrics.log")
                $dst = [System.IO.Path]::Combine($WorkingDirectory, "SplunkUniversalForwarder", "metrics.log")
                Copy-uAItem -Source $src -Destination $dst

                Write-Verbose 'Performing uberAgent to Splunk Universal Forwarder connection check' -Verbose
                $dst = [System.IO.Path]::Combine($WorkingDirectory, "SplunkUniversalForwarder", "Get-NetTCPConnection.log")
                Get-NetTCPConnection | Format-Table LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | Out-File -FilePath $dst
            }
            #endregion log files

            #region config files
            Write-Verbose 'Collect uberAgent configuration files' -Verbose
            New-Item -Path "$WorkingDirectory" -Name Config -ItemType Directory | Out-Null

            $src = [System.IO.Path]::Combine($env:programdata, "vast limits\uberAgent\Configuration\*")
            $dst = [System.IO.Path]::Combine($WorkingDirectory, "Config\ProgramData")
            Copy-uAItem -Source $src -Destination $dst -Recurse -Exclude $ExcludeExecutablesAndLibraries
            
            $src = [System.IO.Path]::Combine($uberAgentInstallDir, "*")
            $dst = [System.IO.Path]::Combine($WorkingDirectory, "Config\ProgramFiles")
            Copy-uAItem -Source $src -Destination $dst -Recurse -Exclude $ExcludeExecutablesAndLibraries

            if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\vast limits\uberAgent\Config" -Name ConfigFilePath -ErrorAction SilentlyContinue) -OR (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\vast limits\uberAgent\Config" -Name ConfigFilePath -ErrorAction SilentlyContinue)) {
                # CCFM is active
                $ConfigCachePath = (Get-ItemProperty -Path "HKLM:\SOFTWARE\vast limits\uberAgent\CCFM" -Name ConfigCachePath).ConfigCachePath
                if ($ConfigCachePath)
                {
                    $src = [System.IO.Path]::Combine($ConfigCachePath, "*")
                    $dst = [System.IO.Path]::Combine($WorkingDirectory, "Config\CCFM")
                    Copy-uAItem -Source $src -Destination $dst -Recurse -Exclude $ExcludeExecutablesAndLibraries
                }
                else {
                    Write-Warning "ConfigFilePath is set but ConfigCachePath is not. CCFM config is broken."
                }

            }

            If($SplunkUFinstalled) {
                Write-Verbose 'Collect Splunk Universal Forwarder configuration files' -Verbose

                $src = [System.IO.Path]::Combine($SplunkUFInstallDir, "etc\system\local\inputs.conf")
                $dst = [System.IO.Path]::Combine($WorkingDirectory, "SplunkUniversalForwarder", "inputs.conf")
                Copy-uAItem -Source $src -Destination $dst

                $src = [System.IO.Path]::Combine($SplunkUFInstallDir, "etc\system\local\outputs.conf")
                $dst = [System.IO.Path]::Combine($WorkingDirectory, "SplunkUniversalForwarder", "outputs.conf")
                Copy-uAItem -Source $src -Destination $dst
            }
            #endregion config files

            #region registry
            Write-Verbose 'Collect registry items' -Verbose
            New-Item -Path "$WorkingDirectory\Registry" -ItemType Directory | Out-Null
            New-Item -Path "$WorkingDirectory\Registry" -Name "Service registry keys.txt" -ItemType File | Out-Null
            New-Item -Path "$WorkingDirectory\Registry" -Name "Chrome registry keys.txt" -ItemType File | Out-Null
            New-Item -Path "$WorkingDirectory\Registry" -Name "Firefox registry keys.txt" -ItemType File | Out-Null
            New-Item -Path "$WorkingDirectory\Registry" -Name "Internet Explorer registry keys.txt" -ItemType File | Out-Null
            New-Item -Path "$WorkingDirectory\Registry" -Name "Driver registry keys.txt" -ItemType File | Out-Null

            Foreach ($RegKey in $RegKeys) {
                $RegKeyContent = Get-uARegistryItem -Key "$($RegKey.Path)"
                $RegKeyComponent = "$($RegKey.Component)"

                $dst = [System.IO.Path]::Combine($WorkingDirectory, "Registry", "$RegKeyComponent registry keys.txt")
                Out-File -FilePath $dst -InputObject $RegKeyContent -Append -NoClobber
            }
            #endregion registry

            #region processes
            Write-Verbose 'Collect uberAgent process details' -Verbose
            New-Item -Path "$WorkingDirectory\Processes" -ItemType Directory | Out-Null
            Foreach ($Process in $Processes) {
                $ProcessDetail = Get-uAProcessDetails -ProcessName $Process

                Write-Verbose "Collect details for process $Process"

                $dst = [System.IO.Path]::Combine($WorkingDirectory, "Processes", "Process details.txt")

                Out-File -FilePath $dst -InputObject $ProcessDetail -Append -NoClobber
            }
            #endregion processes

            #region zip file
            Write-Verbose 'Create support zip file' -Verbose
            $CurrentDate = Get-Date -Format "yyyy-MM-dd HH-mm-ss"
            $ZipFilename = 'uASupportBundle-' + "$env:COMPUTERNAME" + '-' + "$CurrentDate" + '.zip'

            Compress-uAArchive -SourceDir $WorkingDirectory -ZipFilename $ZipFilename -ZipFilepath $DesktopPath
            Write-Verbose "Successfully created uberAgent support bundle at $(Join-Path $DesktopPath $ZipFilename)" -Verbose
            #endregion zip file

            Write-Verbose 'Finish' -Verbose
        }
        Catch {
            $ErrorMessage = $_.Exception.Message
            Write-Error $ErrorMessage
        }

        Finally {
            $stopWatch.Stop()
            Write-Verbose "Elapsed Runtime: $($stopWatch.Elapsed.Minutes) minutes and $($stopWatch.Elapsed.Seconds) seconds." -Verbose
            Stop-Transcript | Out-Null

            # Delete old working folder if any
            If (Test-Path $WorkingDirectory) {

                if ((Test-IsAbsolutePath -Path $WorkingDirectory) -eq $true) {
                    Remove-Item $WorkingDirectory -Force -Recurse -ErrorAction Stop
                    Write-Verbose "Successfully deleted working directory '$WorkingDirectory'"
                }
                else {
                    Write-Error "Failed to delete working directory '$WorkingDirectory'"
                }
                
            }
        }
    }
}
# SIG # Begin signature block
# MIIRVgYJKoZIhvcNAQcCoIIRRzCCEUMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBzCMJu/A491jL+
# Wf9iWiG4CMDeQEQzjzX+RgDvvXOIxqCCDW0wggZyMIIEWqADAgECAghkM1HTxzif
# CDANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMx
# EDAOBgNVBAcMB0hvdXN0b24xGDAWBgNVBAoMD1NTTCBDb3Jwb3JhdGlvbjExMC8G
# A1UEAwwoU1NMLmNvbSBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IFJTQTAe
# Fw0xNjA2MjQyMDQ0MzBaFw0zMTA2MjQyMDQ0MzBaMHgxCzAJBgNVBAYTAlVTMQ4w
# DAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjERMA8GA1UECgwIU1NMIENv
# cnAxNDAyBgNVBAMMK1NTTC5jb20gQ29kZSBTaWduaW5nIEludGVybWVkaWF0ZSBD
# QSBSU0EgUjEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCfgxNzqrDG
# bSHL24t6h3TQcdyOl3Ka5LuINLTdgAPGL0WkdJq/Hg9Q6p5tePOf+lEmqT2d0bKU
# Vz77OYkbkStW72fL5gvjDjmMxjX0jD3dJekBrBdCfVgWQNz51ShEHZVkMGE6ZPKX
# 13NMfXsjAm3zdetVPW+qLcSvvnSsXf5qtvzqXHnpD0OctVIFD+8+sbGP0EmtpuNC
# GVQ/8y8Ooct8/hP5IznaJRy4PgBKOm8yMDdkHseudQfYVdIYyQ6KvKNc8HwKp4WB
# wg6vj5lc02AlvINaaRwlE81y9eucgJvcLGfE3ckJmNVz68Qho+Uyjj4vUpjGYDdk
# jLJvSlRyGMwnh/rNdaJjIUy1PWT9K6abVa8mTGC0uVz+q0O9rdATZlAfC9KJpv/X
# gAbxwxECMzNhF/dWH44vO2jnFfF3VkopngPawismYTJboFblSSmNNqf1x1KiVgMg
# Lzh4gL32Bq5BNMuURb2bx4kYHwu6/6muakCZE93vUN8BuvIE1tAx3zQ4XldbyDge
# VtSsSKbt//m4wTvtwiS+RGCnd83VPZhZtEPqqmB9zcLlL/Hr9dQg1Zc0bl0EawUR
# 0tOSjAknRO1PNTFGfnQZBWLsiePqI3CY5NEv1IoTGEaTZeVYc9NMPSd6Ij/D+KNV
# t/nmh4LsRR7Fbjp8sU65q2j3m2PVkUG8qQIDAQABo4H7MIH4MA8GA1UdEwEB/wQF
# MAMBAf8wHwYDVR0jBBgwFoAU3QQJB6L1en1SUxKSle44gCUNplkwMAYIKwYBBQUH
# AQEEJDAiMCAGCCsGAQUFBzABhhRodHRwOi8vb2NzcHMuc3NsLmNvbTARBgNVHSAE
# CjAIMAYGBFUdIAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwOwYDVR0fBDQwMjAwoC6g
# LIYqaHR0cDovL2NybHMuc3NsLmNvbS9zc2wuY29tLXJzYS1Sb290Q0EuY3JsMB0G
# A1UdDgQWBBRUwv4QlQCTzWr158DX2bJLuI8M4zAOBgNVHQ8BAf8EBAMCAYYwDQYJ
# KoZIhvcNAQELBQADggIBAPUPJodwr5miyvXWyfCNZj05gtOII9iCv49UhCe204MH
# 154niU2EjlTRIO5gQ9tXQjzHsJX2vszqoz2OTwbGK1mGf+tzG8rlQCbgPW/M9r1x
# xs19DiBAOdYF0q+UCL9/wlG3K7V7gyHwY9rlnOFpLnUdTsthHvWlM98CnRXZ7WmT
# V7pGRS6AvGW+5xI+3kf/kJwQrfZWsqTU+tb8LryXIbN2g9KR+gZQ0bGAKID+260P
# Z+34fdzZcFt6umi1s0pmF4/n8OdX3Wn+vF7h1YyfE7uVmhX7eSuF1W0+Z0duGwdc
# +1RFDxYRLhHDsLy1bhwzV5Qe/kI0Ro4xUE7bM1eV+jjk5hLbq1guRbfZIsr0WkdJ
# LCjoT4xCPGRo6eZDrBmRqccTgl/8cQo3t51Qezxd96JSgjXktefTCm9r/o35pNfV
# HUvnfWII+NnXrJlJ27WEQRQu9i5gl1NLmv7xiHp0up516eDap8nMLDt7TAp4z5T3
# NmC2gzyKVMtODWgqlBF1JhTqIDfM63kXdlV4cW3iSTgzN9vkbFnHI2LmvM4uVEv9
# XgMqyN0eS3FE0HU+MWJliymm7STheh2ENH+kF3y0rH0/NVjLw78a3Z9UVm1F5VPz
# iIorMaPKPlDRADTsJwjDZ8Zc6Gi/zy4WZbg8Zv87spWrmo2dzJTw7XhQf+xkR6Od
# MIIG8zCCBNugAwIBAgIQfYHMItEnwWprKIwmkVmsVDANBgkqhkiG9w0BAQsFADB4
# MQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0b24x
# ETAPBgNVBAoMCFNTTCBDb3JwMTQwMgYDVQQDDCtTU0wuY29tIENvZGUgU2lnbmlu
# ZyBJbnRlcm1lZGlhdGUgQ0EgUlNBIFIxMB4XDTIzMDMwNzIyNTIyNloXDTI2MDMw
# NjIyNTIyNlowfDELMAkGA1UEBhMCREUxHDAaBgNVBAgME05vcmRyaGVpbi1XZXN0
# ZmFsZW4xGTAXBgNVBAcMEE1vbmhlaW0gYW0gUmhlaW4xGTAXBgNVBAoMEHZhc3Qg
# bGltaXRzIEdtYkgxGTAXBgNVBAMMEHZhc3QgbGltaXRzIEdtYkgwggIiMA0GCSqG
# SIb3DQEBAQUAA4ICDwAwggIKAoICAQDmsmxRhHnZ47SQfWJmJje0vVjTVhDfA15d
# Q99NkNBuxZV4F+zSdMuCH+CT77aJIa6fbQQzQCs5Z2bfia82RXAKgC9SPALFAdLq
# 3OyQ8IICyivsVn4IkLzGuEJPETDHWfRAJmICajFqyxX6DXcuOmxIm3c/s3F413DO
# uBn+oTebJu1lk/Mp0L+pd1MYnY3rKEsv+FuXE6valQqJRrIlkQA7sC2ji6A4tsA8
# 9NxK7IQlGIh4P2sEBq9YVrXOpCoxuzGC9zDwE1et1BrcviHr2z9AEfOD5te7CAbZ
# CukDEri7zskt8pL5vT+Djdn+u5yo689L3QcFG4JVs0AIPmxt91l8UJDX/I2oKBz8
# 4KuZGLExHDYETtIiCjB0gKBOWl4kojgqewBe8cL0HNcuCxmfMTubepSTF3R3UOrv
# bcSP2W34eJ353EEuCZMmkgQnj+Cu+g7fY379ddWO24rS9gonoSrsoCK7iVlGPLjz
# whKRe6S2vpFpsoEPo9bhdP5w1aCf/TQZixffdQSB2gFgGivgXjZ60ld5XUOG5eyZ
# ow6vEzKq7Bqnipd7t8xgBq6jIQ0y2fFS8o656pZvf7fvZ7bMM47uBXN9812/R4mX
# Zw6kvsH2k5YKZh97i9oBa+XCSeFVecFT5JY9uRj3SutCj5JvxsX5z5FH4qVedwse
# PYM6LtsztwIDAQABo4IBczCCAW8wDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBRU
# wv4QlQCTzWr158DX2bJLuI8M4zBYBggrBgEFBQcBAQRMMEowSAYIKwYBBQUHMAKG
# PGh0dHA6Ly9jZXJ0LnNzbC5jb20vU1NMY29tLVN1YkNBLUNvZGVTaWduaW5nLVJT
# QS00MDk2LVIxLmNlcjBRBgNVHSAESjBIMAgGBmeBDAEEATA8BgwrBgEEAYKpMAED
# AwEwLDAqBggrBgEFBQcCARYeaHR0cHM6Ly93d3cuc3NsLmNvbS9yZXBvc2l0b3J5
# MBMGA1UdJQQMMAoGCCsGAQUFBwMDME0GA1UdHwRGMEQwQqBAoD6GPGh0dHA6Ly9j
# cmxzLnNzbC5jb20vU1NMY29tLVN1YkNBLUNvZGVTaWduaW5nLVJTQS00MDk2LVIx
# LmNybDAdBgNVHQ4EFgQUH4wxTfruqchOioKCaULdd2n1d6AwDgYDVR0PAQH/BAQD
# AgeAMA0GCSqGSIb3DQEBCwUAA4ICAQA+C1FID5jlerfUMR3DnJAe3ngwe/3YaItK
# 40Ccvd2ZG7lwmpho0ITP5EcXvQnkfsL5pGrXT1iRXMYrDgTz6eqtfpyC99F+fUGj
# aLrlOJvtzl1KypxHDRCvZKs2Qc7pceyvDZb+Wb4VrthpOYYTVfI+HWIYLiMH4fKB
# pkxCGLDipaPXHEQ+DNPUs1J7GpVyrh6jyMtfYZSEHz9YACvlT0FHooj7QDIlAX/u
# 6988XxGO8N4LZaaWUcLBb+LlQwiskVg+FXUMTarv7MS/e8ZirVfiHGXtiV9texcf
# 0LepL2nKtbcUTXYLucaW/8G+v0lO1H++K0/ziwqCCdxADzNR3/NGDth9vnLl+UPN
# 4QXCJEaw37RnipOxudFJOMqFSvNvARWNlxHvwgk+dRI5RDLKKSWdCKrC1/svMuG4
# sj+PgtITa3nWNVb56FpB6TXPc04Jqj7aeGcS7IfDKcZKXknVW/ngvZxLuKhdyJrk
# aovWHDjJNX2YuS6mAaw5CJ/5QDnxVD78qn9Zq4uqEg6aEnS1+FPuo42P+78sMuys
# +sjER4hLMrLhXfvwEOOHeweV75IF7rm5zDmZFJv54tJP3vuvNF1opr9ccWzhO3BG
# ufTWS/qKYurtB8uEmbJCH8ltE56bquVL0YRfVwVSV7gyp355x3Ptgu+v8YPDuzn3
# ZJjydk0JATGCAz8wggM7AgEBMIGMMHgxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVU
# ZXhhczEQMA4GA1UEBwwHSG91c3RvbjERMA8GA1UECgwIU1NMIENvcnAxNDAyBgNV
# BAMMK1NTTC5jb20gQ29kZSBTaWduaW5nIEludGVybWVkaWF0ZSBDQSBSU0EgUjEC
# EH2BzCLRJ8FqayiMJpFZrFQwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIB
# DDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEE
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgdtXSFwOoYASn
# bNGkY/AvArQ4bxpWMjJFkTnvQ0q+O/owDQYJKoZIhvcNAQEBBQAEggIAuSHZkiwp
# owQ+SXV0WCYPwDj29GDqO+SulCp8KcsOswRmfl7FZJmOXldav/OAUYkdnvo/HGWl
# dcTjhyxtROIRVguDCqDZysMd2deobAL6C299kaPiIuv/+Ui+7decyPRSD9AWvUZu
# gnphN5gRx6ZYfeP8YHtmIfNvAx1XDF7ZVNwWiKAlGKXUYa8yCemBoE0ZLk1QCM9x
# tDrzLTSlHC/Gu0SmsQzwa/rWWgjJEcN+bb6ISFp2WL7VhqIuodeP7DOoSSr+7SKm
# bM1FY0Z+b4FO8EpE8kCb8zhYMAtdW6hwGdw67ihC+cj0+AYEwPR3WA9ZOiFqmSYh
# E3fzLGDS3/7jNC/fstHigzeSeMM98InW+fBwChJisJOCwR/68+VE9O+O3q0bTRAU
# iWJnAwB6clx2S5JBRYg7MHIJX8cL/g/l8GauN/vuKni7HPROMS1sOmr43OIFvr7W
# Z//Ziwz+0emJ2WRDl4JRGZcB6rO8JYYMEDmWaeNMo2jNmE/1+IBLV8nLxhXd3uEt
# y3GpTDsnCkJUXvjDFn/3VwCRNr26RYhkiC9zvki/JF15I/bOwggQ41FMOk0kn+c1
# 8BRtdDBhab1Kyl0qAlkG1W3g1eIK3isp5ywYvKy2sQu/RjBgwX63X5tR4kEyVr9w
# AN1hZ/JyIVr67GbusuMAR2YlIVQzF4/4A2k=
# SIG # End signature block
