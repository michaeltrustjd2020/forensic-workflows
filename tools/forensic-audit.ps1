param(
    [Parameter(Position=0)]
    [string]$Target = ".",
    [switch]$IncludeBinaries
)

$ErrorActionPreference = "Stop"

function Get-HashSha256 {
    param([string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs  = [System.IO.File]::OpenRead($Path)
    try {
        $hashBytes = $sha.ComputeHash($fs)
        # Convert to hex without dashes
        -join ($hashBytes | ForEach-Object { $_.ToString("x2") })
    } finally {
        $fs.Dispose()
        $sha.Dispose()
    }
}

function Has-BOM {
    param([byte[]]$Bytes)
    return ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF)
}

function Contains-SmartQuotes {
    param([string]$Text)
    # U+2018/U+2019/U+201C/U+201D
    return ($Text -match "[\u2018\u2019\u201C\u201D]")
}

# Start transcript
$ts = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$transcriptPath = Join-Path (Get-Location) "forensic_audit_transcript_$ts.txt"
Start-Transcript -Path $transcriptPath | Out-Null

# Prepare CSV rows
$csvPath = Join-Path (Get-Location) "forensic_audit_$ts.csv"
$rows = @()

Write-Host "Scanning: $((Resolve-Path $Target).Path)"

# Binary extensions to skip unless -IncludeBinaries
$binaryExt = @(
    ".png",".jpg",".jpeg",".gif",".pdf",".zip",".exe",".dll",".bin",".dat",
    ".mp3",".mp4",".mov",".avi",".ttf",".otf",".woff",".woff2",".ico",".svg"
)

Get-ChildItem -Path $Target -Recurse -File | ForEach-Object {
    $f = $_.FullName
    $hash  = Get-HashSha256 -Path $f
    $bytes = $null
    $bom   = $false
    $smart = $false

    try {
        $bytes = [System.IO.File]::ReadAllBytes($f)
        $bom = Has-BOM -Bytes $bytes

        $ext = [System.IO.Path]::GetExtension($f).ToLower()
        $shouldCheckText = $IncludeBinaries -or -not ($binaryExt -contains $ext)

        if ($shouldCheckText) {
            try {
                $text = Get-Content -LiteralPath $f -Raw -ErrorAction Stop
                $smart = Contains-SmartQuotes -Text $text
            } catch {
                $smart = $false
            }
        }
    } catch {
        $bom = $false
        $smart = $false
    }

    $rows += [PSCustomObject]@{
        Path        = $f
        SizeBytes   = $_.Length
        LastWrite   = $_.LastWriteTime.ToString("o")
        SHA256      = $hash
        HasBOM      = $bom
        SmartQuotes = $smart
    }
}

$rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvPath
Write-Host "CSV written: $csvPath"
Write-Host "Transcript:  $transcriptPath"

Stop-Transcript | Out-Null
