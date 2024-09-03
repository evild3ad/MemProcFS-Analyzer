# ProcessesAndModules-Extended_Info v0.1
#
# @author:    Martin Willing
# @copyright: Copyright (c) 2024 Martin Willing. All rights reserved.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:       https://lethal-forensics.com/
# @date:      2024-08-31
#
#
# ██╗     ███████╗████████╗██╗  ██╗ █████╗ ██╗      ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
# ██║     ██╔════╝╚══██╔══╝██║  ██║██╔══██╗██║      ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
# ██║     █████╗     ██║   ███████║███████║██║█████╗█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
# ██║     ██╔══╝     ██║   ██╔══██║██╔══██║██║╚════╝██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
# ███████╗███████╗   ██║   ██║  ██║██║  ██║███████╗ ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
# ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
#
#
# Dependencies:
#
# ImportExcel v7.8.9 (2024-06-21)
# https://github.com/dfinke/ImportExcel
#
#
# Changelog:
# Version 0.1
# Release Date: 2024-08-31
# Initial Release
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  ProcessesAndModules-Extended_Info v0.1 - Automated Processing of 'ProcessesAndModules-Extended_Info.tsv' (MAGNET Response)

.DESCRIPTION
  ProcessesAndModules-Extended_Info.ps1 is a simple PowerShell script utilized to beautify the extended information about running processes and loaded modules collected by MAGNET Response.

  Enable 'Capture Running Processes - Extended Info'
  This option collects more data about running processes (and loaded modules in memory), saving hash values and metadata from identified files which can be used to enable post-collection lookups/enrichment in another tool.

  Collect-MemoryDump.ps1 --> \Pagefile\Pagefile\Processes\ProcessesAndModules-Extended_Info.tsv

  https://github.com/evild3ad/Collect-MemoryDump

.EXAMPLE
  PS> .\ProcessesAndModules-Extended_Info.ps1

.NOTES
  Author - Martin Willing

.LINK
  https://lethal-forensics.com/
#>

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Declarations

# Declarations

# Script Root
if ($PSVersionTable.PSVersion.Major -gt 2)
{
    # PowerShell 3+
    $SCRIPT_DIR = $PSScriptRoot
}
else
{
    # PowerShell 2
    $SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Definition
}

# Colors
Add-Type -AssemblyName System.Drawing

# Output Directory
$OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\ProcessesAndModules"

#endregion Declarations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Header

# Windows Title
$DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "ProcessesAndModules-Extended_Info v0.1 - Automated Processing of Extended Info about Running Processes and Loaded Modules collected by MAGNET Response"

# Check if the PowerShell script is being run with admin rights
if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Host "[Error] This PowerShell script must be run with admin rights." -ForegroundColor Red
    Exit
}

# Flush Output Directory
if (Test-Path "$OUTPUT_FOLDER")
{
    Get-ChildItem -Path "$OUTPUT_FOLDER" -Force -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse
    New-Item "$OUTPUT_FOLDER" -ItemType Directory -Force | Out-Null
}
else 
{
    New-Item "$OUTPUT_FOLDER" -ItemType Directory -Force | Out-Null
}

# Function Get-FileSize
Function Get-FileSize()
{
    Param ([long]$Length)
    If ($Length -gt 1TB) {[string]::Format("{0:0.00} TB", $Length / 1TB)}
    ElseIf ($Length -gt 1GB) {[string]::Format("{0:0.00} GB", $Length / 1GB)}
    ElseIf ($Length -gt 1MB) {[string]::Format("{0:0.00} MB", $Length / 1MB)}
    ElseIf ($Length -gt 1KB) {[string]::Format("{0:0.00} KB", $Length / 1KB)}
    ElseIf ($Length -gt 0) {[string]::Format("{0:0.00} Bytes", $Length)}
    Else {""}
}

# Select Log File
Function Get-LogFile($InitialDirectory)
{ 
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.InitialDirectory = $InitialDirectory
    $OpenFileDialog.Filter = "ProcessesAndModules-Extended_Info.tsv|ProcessesAndModules-Extended_Info.tsv|All Files (*.*)|*.*"
    $OpenFileDialog.ShowDialog()
    $OpenFileDialog.Filename
    $OpenFileDialog.ShowHelp = $true
    $OpenFileDialog.Multiselect = $false
}

$Result = Get-LogFile

if($Result -eq "OK")
{
    $script:LogFile = $Result[1]
}
else
{
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Get Start Time
$startTime = (Get-Date)

# Logo
$Logo = @"
██╗     ███████╗████████╗██╗  ██╗ █████╗ ██╗      ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
██║     ██╔════╝╚══██╔══╝██║  ██║██╔══██╗██║      ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
██║     █████╗     ██║   ███████║███████║██║█████╗█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
██║     ██╔══╝     ██║   ██╔══██║██╔══██║██║╚════╝██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
███████╗███████╗   ██║   ██║  ██║██║  ██║███████╗ ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
"@

Write-Output ""
Write-Output "$Logo"
Write-Output ""

# Header
Write-Output "ProcessesAndModules-Extended_Info v0.1 - Automated Processing of Extended Info about Running Processes and Loaded Modules collected by MAGNET Response"
Write-Output "(c) 2024 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
Write-Output ""

# Analysis date (ISO 8601)
$AnalysisDate = [datetime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "Analysis date: $AnalysisDate UTC"
Write-Output ""

#endregion Header

#############################################################################################################################################################################################

#region Analysis

# Input-Check
if (!(Test-Path "$LogFile"))
{
    Write-Host "[Error] $LogFile does not exist." -ForegroundColor Red
    Write-Host ""
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Check File Extension
$Extension = [IO.Path]::GetExtension($LogFile)
if (!($Extension -eq ".tsv" ))
{
    Write-Host "[Error] No TSV File provided." -ForegroundColor Red
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Input Size
$InputSize = Get-FileSize((Get-Item "$LogFile").Length)
Write-Output "[Info]  Total Input Size: $InputSize"

# Count rows of TSV (w/ thousands separators)
$Count = 0
switch -File "$LogFile" { default { ++$Count } }
$Rows = '{0:N0}' -f $Count
Write-Output "[Info]  Total Lines: $Rows"

# Processing ProcessesAndModules-Extended_Info.tsv
Write-Output "[Info]  Processing ProcessesAndModules-Extended_Info.tsv ..."

# XLSX
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$LogFile")
    {
        if(!([String]::IsNullOrWhiteSpace((Get-Content "$LogFile"))))
        {
            $IMPORT = Import-Csv -Path "$LogFile" -Delimiter "`t" -Encoding UTF8 | Select-Object "File Path","Digital Signature",Entropy,"Company Name","Product Name",Description,Comments,Version,"Found On Disk",MD5,SHA1,"Location of Saved File in ZIP"
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\ProcessesAndModules-Extended_Info.xlsx" -NoNumberConversion * -FreezePane 2,4 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Running Processes" -CellStyleSB {
            param($WorkSheet)

            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:L1"] -BackgroundColor $BackgroundColor -FontColor White

            # HorizontalAlignment "Center" of columns B-E and H-K
            $WorkSheet.Cells["B:E"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["H:K"].Style.HorizontalAlignment="Center"

            # Digital Signature: No Valid Signature Found --> Font: Red
            $MaliciousColor = [System.Drawing.Color]::FromArgb(255,0,0)
            Add-ConditionalFormatting -Address $WorkSheet.Cells["B:B"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("No Valid Signature Found",$B1)))' -FontColor $MaliciousColor

            # Entropy >= 7.7
            # Note: Entropy is a measure of randomness. For binary data 0,0 is not-random and 8,0 is perfectly random.
            $MaliciousColor = [System.Drawing.Color]::FromArgb(255,0,0) # Red
            $SuspiciousColor = [System.Drawing.Color]::FromArgb(255,192,0) # Orange
            $Cells = "C:C"
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("8,0",$C1)))' -BackgroundColor $MaliciousColor
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("7,9",$C1)))' -BackgroundColor $MaliciousColor
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("7,8",$C1)))' -BackgroundColor $MaliciousColor
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("7,7",$C1)))' -BackgroundColor $MaliciousColor
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("7,6",$C1)))' -BackgroundColor $SuspiciousColor
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("7,5",$C1)))' -BackgroundColor $SuspiciousColor
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("7,4",$C1)))' -BackgroundColor $SuspiciousColor
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("7,3",$C1)))' -BackgroundColor $SuspiciousColor

            # Digital Signature: No Valid Signature Found --> Pink
            $UnsignedColor = [System.Drawing.Color]::FromArgb(255,204,206)
            Add-ConditionalFormatting -Address $WorkSheet.Dimension.Address -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("No Valid Signature Found",$B1)))' -BackgroundColor $UnsignedColor

            # Image Path: File not found --> Yellow
            $FileNotFoundColor = [System.Drawing.Color]::FromArgb(255,255,0)
            Add-ConditionalFormatting -Address $WorkSheet.Dimension.Address -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("No",$I1)))' -BackgroundColor $FileNotFoundColor

            }
        }
    }
}
else
{
    Write-Host "[Error] PowerShell module 'ImportExcel' NOT found." -ForegroundColor Red
}

# File Size (XLSX)
if (Test-Path "$OUTPUT_FOLDER\ProcessesAndModules-Extended_Info.xlsx")
{
    $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\ProcessesAndModules-Extended_Info.xlsx").Length)
    Write-Output "[Info]  File Size (XLSX): $Size"
}

# Stats
New-Item "$OUTPUT_FOLDER\Stats" -ItemType Directory -Force | Out-Null

# Company Name (Stats)
$Total = (Import-Csv -Path "$LogFile" -Delimiter "`t" | Where-Object { $_."Found On Disk" -eq "Yes" } | Measure-Object).Count
$Import = Import-Csv -Path "$LogFile" -Delimiter "`t" -Encoding UTF8 | Where-Object { $_."Found On Disk" -eq "Yes" }  | Group-Object "Company Name" | Select-Object @{Name='Company Name'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
$Import | Export-Excel -Path "$OUTPUT_FOLDER\Stats\CompanyName.xlsx" -NoHyperLinkConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Company Name" -CellStyleSB {
param($WorkSheet)
# BackgroundColor and FontColor for specific cells of TopRow
$BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
# HorizontalAlignment "Center" of column B-C
$WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
}

# Digital Signature (Stats)
$Total = (Import-Csv -Path "$LogFile" -Delimiter "`t" | Where-Object { $_."Found On Disk" -eq "Yes" } | Measure-Object).Count
$Import = Import-Csv -Path "$LogFile" -Delimiter "`t" -Encoding UTF8 | Where-Object { $_."Found On Disk" -eq "Yes" }  | Group-Object "Digital Signature" | Select-Object @{Name='Digital Signature'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
$Import | Export-Excel -Path "$OUTPUT_FOLDER\Stats\DigitalSignature.xlsx" -NoHyperLinkConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Digital Signature" -CellStyleSB {
param($WorkSheet)
# BackgroundColor and FontColor for specific cells of TopRow
$BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
# HorizontalAlignment "Center" of column B-C
$WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
}

# File Path (Stats)
$Total = (Import-Csv -Path "$LogFile" -Delimiter "`t" | Measure-Object).Count
$FilePath = Import-Csv -Path "$LogFile" -Delimiter "`t" -Encoding UTF8 | Select-Object -ExpandProperty "File Path" | Split-Path -Parent
$FilePath | Out-File "$OUTPUT_FOLDER\Stats\FilePath.txt" -Encoding UTF8
$Import = Get-Content "$OUTPUT_FOLDER\Stats\FilePath.txt" | Group-Object | Select-Object @{Name='FilePath'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
$Import | Export-Excel -Path "$OUTPUT_FOLDER\Stats\FilePath.xlsx" -NoHyperLinkConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "File Path" -CellStyleSB {
param($WorkSheet)
# BackgroundColor and FontColor for specific cells of TopRow
$BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
# HorizontalAlignment "Center" of column B-C
$WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
# ConditionalFormatting - File Path (No Regex supported)
Add-ConditionalFormatting -Address $WorkSheet.Cells["A:A"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("C:\Temp",$A1)))' -BackgroundColor Red # %SystemDrive%\Temp
Add-ConditionalFormatting -Address $WorkSheet.Cells["A:A"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("C:\Users\Public",$A1)))' -BackgroundColor Red # %SystemDrive%\Users\Public
Add-ConditionalFormatting -Address $WorkSheet.Cells["A:A"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("C:\Windows\Temp",$A1)))' -BackgroundColor Red # %SystemDrive%\Windows\Temp
}

# Cleaning Up
if (Test-Path "$OUTPUT_FOLDER\Stats\FilePath.txt")
{
    Remove-Item "$OUTPUT_FOLDER\Stats\FilePath.txt" -Force
}

# Found On Disk (Stats)
$Total = (Import-Csv -Path "$LogFile" -Delimiter "`t" | Measure-Object).Count
$Import = Import-Csv -Path "$LogFile" -Delimiter "`t" -Encoding UTF8 | Group-Object "Found On Disk" | Select-Object @{Name='Found On Disk'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
$Import | Export-Excel -Path "$OUTPUT_FOLDER\Stats\FoundOnDisk.xlsx" -NoHyperLinkConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Found On Disk" -CellStyleSB {
param($WorkSheet)
# BackgroundColor and FontColor for specific cells of TopRow
$BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
# HorizontalAlignment "Center" of column A-C
$WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
}

# Total Number of Files
$Count = (Import-Csv -Path "$LogFile" -Delimiter "`t" | Select-Object "File Path" | Measure-Object).Count
$Total = '{0:N0}' -f $Count
Write-Output "[Info]  $Total File(s) found"

# Digital Signature --> No Valid Signature Found
$Count = (Import-Csv -Path "$LogFile" -Delimiter "`t" | Select-Object "Digital Signature" | Select-String -Pattern "No Valid Signature Found" | Measure-Object).Count
$Unsigned = '{0:N0}' -f $Count
Write-Output "[Info]  $Unsigned Unsigned File(s) found"

# Image Path --> Found On Disk
$FileNotFound = (Import-Csv -Path "$LogFile" -Delimiter "`t" | Where-Object { $_."Found On Disk" -eq "No" } | Measure-Object).Count
Write-Output "[Info]  $FileNotFound File(s) NOT found on disk"

# No Description
$MissingDescription = (Import-Csv -Path "$LogFile" -Delimiter "`t" | Where-Object { $_.Description -eq "" } | Measure-Object).Count
Write-Output "[Info]  $MissingDescription suspicious images with no 'Description' found"

# No Publisher
$MissingPublisher = (Import-Csv -Path "$LogFile" -Delimiter "`t" | Where-Object { $_."Company Name" -eq "" } | Measure-Object).Count
Write-Output "[Info]  $MissingPublisher suspicious images with no 'Company Name' found"

# No Description and no Publisher
$MissingDescriptionAndPublisher = (Import-Csv -Path "$LogFile" -Delimiter "`t" | Where-Object { $_.Description -eq "" -and $_."Company Name" -eq "" } | Measure-Object).Count
Write-Output "[Info]  $MissingDescriptionAndPublisher suspicious images with no 'Description' and no 'Company Name' found"

# Entropy >= 7.7
$MaliciousEntropy = (Import-Csv -Path "$LogFile" -Delimiter "`t" | Where-Object { $_.Entropy -ge "7,7" } | Measure-Object).Count
Write-Host "[Info]  $MaliciousEntropy suspicious images with an 'Entropy >= 7.7' found" -ForegroundColor Red

# Entropy >= 7.3
$SuspiciousEntropy = (Import-Csv -Path "$LogFile" -Delimiter "`t" | Where-Object { $_.Entropy -ge "7,3" -and $_.Entropy -lt "7,7" } | Measure-Object).Count
Write-Host "[Info]  $SuspiciousEntropy suspicious images with an 'Entropy >= 7.3' found" -ForegroundColor Yellow

#endregion Analysis

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Footer

# Get End Time
$endTime = (Get-Date)

# Echo Time elapsed
Write-Output ""
Write-Output "FINISHED!"

$Time = ($endTime-$startTime)
$ElapsedTime = ('Overall analysis duration: {0} h {1} min {2} sec' -f $Time.Hours, $Time.Minutes, $Time.Seconds)
Write-Output "$ElapsedTime"

# Reset Windows Title
$Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"

#endregion Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# Colors
# Pink   - this means that no publisher information was found, or if code verification is on, means that the digital signature either doesn't exist or doesn't match, or there is no publisher information.
# Yellow - the entry is there, but the file it points to doesn't exist anymore.
