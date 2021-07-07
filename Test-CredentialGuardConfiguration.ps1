# Test-CredentialGuardConfiguration.ps1

<#
.SYNOPSIS
   Checks if Credential Guard is active and collects system data for further analysis.
.DESCRIPTION
   This script performs the following activities:
   * Checks for the Credential Guard configuration in the following locations:
     * Registry key HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard 
     * Registry key HKLM\SYSTEM\CurrentControlSet\Control\LSA
     * WMI class root\Microsoft\Windows\DeviceGuard\Win32_DeviceGuard
     * Various events in the event log
   * Checks if the process 'lsaIso' is running
   * Collects various events from the event logs for further diagnostics
#>

#Requires -Version 5.0

[CmdletBinding()]
Param()

$Datum = Get-Date -Format yyyy-MM-dd_hh-mm 
$User = $env:USERNAME
$NoteBook = $env:COMPUTERNAME

## Check Desktop Locaton Local or OneDrive
if(Test-Path ($env:OneDrive + "\Desktop")){
    $destinationPath = $env:OneDrive
} 
else{
    $destinationPath = $env:USERPROFILE
}

## Log Folder
$LogFolder = "$destinationPath\Desktop\CredentialGuard_Logs"
if(!(Test-Path $LogFolder)){
    New-Item -Name CredentialGuard_Logs -ItemType Directory -Path "$destinationPath\Desktop\"
}
else{}

## Log Files
$TranscriptFile = "$LogFolder\$NoteBook" + "_" + $Datum + ".txt" 
$ExportEvent1x = $LogFolder + "\" + "Event15-17_" + $NoteBook + "_" + $Datum + ".txt" 
$ExportEvent7x = $LogFolder + "\" + "Event700x_"  + $NoteBook + "_" + $Datum + ".txt" 

Start-Transcript -Path $TranscriptFile 

## Start Check CG
""
"--------------------------------------------------------------------------------------------------"
Write-Host "Anwender:" $User  " Notebook:" $NoteBook -ForegroundColor Yellow
"--------------------------------------------------------------------------------------------------"
""
"--------------------------------------------------------------------------------------------------"
Write-Host "Credential Guard Konfiguration::" -ForegroundColor Gray
"--------------------------------------------------------------------------------------------------"

## Check ob Credential Guard konfiguriert wurde
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
$reg = Get-ItemProperty $RegPath | select EnableVirtualizationBasedSecurity, RequirePlatformSecurityFeatures

### virtualisierungsbasierte Sicherheit
if($reg.EnableVirtualizationBasedSecurity -eq $NULL){
    Write-Host "Virtualisierungsbasierte Sicherheit ist nicht konfiguriert" -ForegroundColor Yellow
}
if($reg.EnableVirtualizationBasedSecurity -eq "1"){
    Write-Host "Virtualisierungsbasierte Sicherheit ist aktiviert" -ForegroundColor Cyan
}
if($reg.EnableVirtualizationBasedSecurity -eq "0"){
        Write-Host "Virtualisierungsbasierte Sicherheit ist deaktiviert" -ForegroundColor Yellow    
}

if($reg.RequirePlatformSecurityFeatures -eq $NULL){
    Write-Host "Sicherer Start ist ist nicht konfiguriert" -ForegroundColor Yellow    
}
if($reg.RequirePlatformSecurityFeatures -eq "1"){
    Write-Host "Sicherer Start ist aktiviert" -ForegroundColor Cyan
}
if($reg.RequirePlatformSecurityFeatures -eq "2"){
    Write-Host "Sicherer Start ist und DMA-Schutz" -ForegroundColor Cyan    
}

## Check ob Credential Guard aktiviert wurde
$RegPath2 = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA"
$reg2 = Get-ItemProperty $RegPath2

#$reg2.LsaCfgFlags
if($reg2.LsaCfgFlags -eq "0"){
    Write-Host "Windows Defender Credential Guard ist deaktieviert" -ForegroundColor Yellow
}
if($reg2.LsaCfgFlags -eq "1"){
    Write-Host "Windows Defender Credential Guard mit UEFI-Sperre aktiviert" -ForegroundColor Cyan
}
if($reg2.LsaCfgFlags -eq "2"){
    Write-Host "Windows Defender Credential Guard ohne UEFI-Sperre aktiviert" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "Credential Guard Status::" -ForegroundColor Gray

## Check ob Credential Guard auf einem Clientcomputer ausgeführt wird
$CGchek1 = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning
if($CGchek1 -eq "1"){
    Write-Host "Windows Defender Credential Guard ist aktiviert (ausgeführt)" -ForegroundColor Cyan
}
else{
    Write-Host "Windows Defender Credential Guard ist deaktiviert (wird nicht ausgeführt)" -ForegroundColor Yellow
}

## Check Prozess
Write-Host ""
Write-Host "Credential Guard Prozess" -ForegroundColor Gray
$CGprozess = Get-Process | ?{$_.ProcessName -eq "lsaIso"}
if($CGprozess -eq $NULL){
    Write-Host "Prozess: lsaIso -- nicht ausgeführt oder nicht Vorhanden" -ForegroundColor Yellow
}
else{
    Write-Host "Credential Guard Prozess: " -ForegroundColor Cyan 
    $CGprozess | ft 
}

## Check Events
"--------------------------------------------------------------------------------------------------"
Write-Host "Credential Guard Events::  Bitte warten ... !!!" -ForegroundColor Gray
"--------------------------------------------------------------------------------------------------"
Write-Host ""
Write-Host "Credential Guard Events::" -ForegroundColor Gray

$Event14 = Get-WinEvent -FilterHashtable @{LogName='System';Id=14} -MaxEvents 1
$EventTemp14 = $Event14.Message.Split(":").Replace(" ","")

if($EventTemp14 -eq "0x2,0"){
    Write-Host "Credential Guard ist für die Ausführung und im Schutzmodus konfiguriert" -ForegroundColor Cyan
}
if($EventTemp14 -eq "0x1,0"){
    Write-Host "Credential Guard ist für die Ausführung und im Schutzmodus konfiguriert" -ForegroundColor Cyan
}
if($EventTemp14 -eq "0x0,0"){
    Write-Host "Credential Guard ist für die Ausführung nicht konfiguriert" -ForegroundColor Yellow
}

$Event15 = Get-WinEvent -FilterHashtable @{ProviderName='Microsoft-Windows-Wininit';Id=15} -MaxEvents 1 -ErrorAction SilentlyContinue
Write-Host $Event15.Message -ForegroundColor Yellow

$Event700xInfo = Get-WinEvent -logname "Microsoft-Windows-DeviceGuard/Operational" | ?{($_.Id -eq 7001) -or ($_.Id -eq 7000)} | select -First 1 
if($Event700xInfo -eq $NULL){
    Write-Host "Microsoft-Windows-DeviceGuard nicht aktiv oder nicht konfiguriert" -ForegroundColor Yellow
}
elseif($Event700xInfo.id -eq "7000" ){
    Write-Host $Event700xInfo.TimeCreated -ForegroundColor DarkGray
    Write-Host $Event700xInfo.Message  -ForegroundColor Cyan       
}
elseif($Event700xInfo.id -eq "7001" ){
    Write-Host $Event700xInfo.TimeCreated -ForegroundColor DarkGray
    Write-Host $Event700xInfo.Message  -ForegroundColor Yellow
}

""
### Export CG Logs
"--------------------------------------------------------------------------------------------------"
Write-Host "Credential Guard Events Export, Bitte warten ... !!!" -ForegroundColor Yellow
"--------------------------------------------------------------------------------------------------"
$TimeCreated = (get-Date).AddDays(-7)
$Event14_17_ExportLog = Get-WinEvent System | ?{(($_.Id -eq 14)  -or ($_.Id -eq 15) -or ($_.Id -eq 16) -or ($_.Id -eq 17)) -and $_.TimeCreated -gt $TimeCreated} | ft  -AutoSize 
$Event14_17_ExportLog | Out-File $ExportEvent1x -Append
$Event700x_ExportLog = Get-WinEvent -logname "Microsoft-Windows-DeviceGuard/Operational" | ?{(($_.Id -eq 7001) -or ($_.Id -eq 7000)) -and $_.TimeCreated -gt $TimeCreated} | ft  -AutoSize 
$Event700x_ExportLog | Out-File $ExportEvent7x -Append

""
Stop-Transcript
""
### Log Compression 
$logZip = "CG_Logs_" + $User.Split(".")[1] + "_" + $NoteBook + ".zip"

Compress-Archive -Path $LogFolder\* -CompressionLevel Fastest -DestinationPath "$destinationPath\Desktop\$logZip" -Force

"--------------------------------------------------------------------------------------------------"
""
Write-Host "!!!   Please send the logs: $logZip   to: example@domain.de   !!!" -ForegroundColor Red
""
"--------------------------------------------------------------------------------------------------"

explorer.exe "$destinationPath\Desktop"

