# Checking Script
# For safe and local quick-dumping of System logs and files
#
# Author:
# Created by dot-sys under GPL-3.0 license
# This script is not related to any external Project.
#
# Usage:
# Use with Powershell 5.1 and NET 4.0 or higher.
# Running PC Checking Programs, including this script, outside of PC Checks may have impact on the outcome.
# It is advised not to use this on your own.
#
# Version 2.0BETA
# 21 - October - 2024

$ErrorActionPreference = "SilentlyContinue"
$MFTPath = "C:\temp\dump\MFT"
Set-Location "$MFTPath"

$mftDrives = Get-WmiObject Win32_LogicalDisk | Select-Object -ExpandProperty DeviceID | ForEach-Object { $_.Substring(0, 1) }
foreach ($mftDriveLetter in $mftDrives) {
    & "C:\temp\dump\mftecmd.exe" -f "${mftDriveLetter}:\`$Extend\`$UsnJrnl:`$J" -m "${mftDriveLetter}:\`$MFT" --fl --csv "C:\Temp\Dump\MFT"

    $mftFiles = Get-ChildItem "$MFTPath\*.csv"
    foreach ($mftFile in $mftFiles) {
        $mftNewName = "${mftDriveLetter}_$($mftFile.Name)"
        $mftNewPath = "$MFTPath\$mftNewName"
        Rename-Item -Path $mftFile.FullName -NewName $mftNewName
        Move-Item -Path $mftNewPath -Destination "$MFTPath\Raw"
    }
}

$mftFolderPath = "$MFTPath\Raw"
$mftCsvFiles = Get-ChildItem -Path $mftFolderPath -Filter *.csv

foreach ($mftFile in $mftCsvFiles) {
    $mftCsvPath = $mftFile.FullName
    $mftTempPath = [System.IO.Path]::GetTempFileName()
    $mftDriveLetter = $mftFile.BaseName[0]

    try {
        $mftReader = [System.IO.StreamReader]::new($mftCsvPath)
        $mftWriter = [System.IO.StreamWriter]::new($mftTempPath, $false)

        $mftHeader = $mftReader.ReadLine()
        if ($mftHeader) {
            if ($mftHeader -match 'Drive') {
                $mftWriter.WriteLine($mftHeader)
            }
            else {
                $mftWriter.WriteLine("Drive,$mftHeader")
            }

            while ($mftLine = $mftReader.ReadLine()) {
                if ($mftHeader -match 'Drive') {
                    $mftWriter.WriteLine($mftLine)
                }
                else {
                    $mftWriter.WriteLine("$mftDriveLetter,$mftLine")
                }
            }
        }

        $mftReader.Close()
        $mftWriter.Close()

        Remove-Item -Path $mftCsvPath -Force
        Move-Item -Path $mftTempPath -Destination $mftCsvPath

    }
    catch {
        Write-Error "Failed to process file ${mftCsvPath}: $_"
        if (Test-Path $mftTempPath) { Remove-Item -Path $mftTempPath -Force }
    }
}

$mftSourcePath = "$MFTPath\Raw"

Get-ChildItem -Path $mftSourcePath -File | Where-Object {
    $_.Name -like '*$J_output.csv' -or $_.Name -like '*Filelisting.csv'
} | ForEach-Object {
    $mftInputFile = $_.FullName
    $mftOutputFile = Join-Path -Path $mftSourcePath -ChildPath "$($_.BaseName)_filtered.csv"

    Import-Csv -Path $mftInputFile | Where-Object { $_.Extension -match '\.(exe|rar|zip|7z|bat|ps1|identifier|rpf|dll)$' } | Export-Csv -Path $mftOutputFile -NoTypeInformation
}

$mftSourcePath = "$MFTPath\Raw"
$mftDestinationPath = "$MFTPath\Filtered"

Get-ChildItem -Path $mftSourcePath -Filter '*_filtered.csv' | ForEach-Object {
    Move-Item -Path $_.FullName -Destination $mftDestinationPath -Force
}

$mftSourceDir = "$MFTPath\Filtered"
$mftFileListingFiles = Get-ChildItem -Path $mftSourceDir -Filter '*FileListing_filtered.csv' | Select-Object -ExpandProperty FullName
$mftOutputFiles = Get-ChildItem -Path $mftSourceDir -Filter '*Output_filtered.csv' | Select-Object -ExpandProperty FullName

function mftJoinSortAndSelectCsv {
    param (
        [string[]]$mftFiles,
        [string]$mftSortColumn,
        [string[]]$mftSelectColumns
    )

    if ($mftFiles.Length -eq 0) {
        return
    }

