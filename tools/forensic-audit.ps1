param(
    [Parameter(Position=0)]
    [string]$Target = ".",
    [switch]$IncludeBinaries
)

$ErrorActionPreference = "Stop"

# Directories to skip (internal repo folders and output folder)
$SkipDirs = @(".git", ".github", "audit")

# Extensions typically binary (skip unless -IncludeBinaries)
$BinaryExt = @(
    ".png",".jpg",".jpeg",".gif",".pdf",".zip",".exe",".dll",".bin",".dat",
    ".mp3",".mp4",".mov",".avi",".ttf",".otf",".woff",".woff2",".ico",".svg"
)

function Get-HashSha256 {
    param([string]$Path)
    # Use FileShare.ReadWrite to avoid contention with tools that briefly hold open handles
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha.ComputeHash($fs)
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
    # U+2018/U+2019/U+201C/U+201D (smart quotes)
    return ($Text -match "[\u2018\u2019\u201C\u201D]")
}

# Prepare output directory (separate from scan target to avoid reading open transcript)
$AuditDir = Join-Path (Get-Location) "audit"
if (-not (Test-Path $AuditDir)) { New-Item -ItemType Directory -Path $AuditDir -Force | Out-Null }

# Start transcript
$ts = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$TranscriptPath = Join-Path $AuditDir "forensic_audit_transcript_$ts.txt"
Start-Transcript -Path $TranscriptPath | Out-Null

# CSV path (also inside audit/, excluded from scan)
$CsvPath = Join-Path $AuditDir "forensic_audit_$ts.csv"
$rows = @()

$ResolvedTarget = (Resolve-Path $Target).Path
Write-Host "Scanning: $ResolvedTarget"
Write-Host "Outputs:  $CsvPath"
Write-Host "Transcript: $TranscriptPath"

Get-ChildItem -Path $ResolvedTarget -Recurse -File | Where-Object {
    # Exclude files inside skipped directories
    $relative = $_.FullName.Substring($ResolvedTarget.Length).TrimStart('\','/')
    $parts = $relative -split '[\\/]+'
    # skip if first part matches any of $SkipDirs (case-insensitive)
    if ($parts.Length -gt 0) {
        $first = $parts[0].ToLower()
        if ($SkipDirs -contains $first) { return $false }
    }
    # Exclude our current outputs
    if ($_.FullName -eq $CsvPath -or $_.FullName -eq $TranscriptPath) { return $false }
    return $true
} | ForEach-Object {
    $f = $_.FullName
    $hash  = $null
    $bytes = $null
    $bom   = $false
    $smart = $false

    # Compute hash (skip if locked)
    try {
        $hash = Get-HashSha256 -Path $f
    } catch {
        # Locked or inaccessible; record null and continue
        $hash = $null
    }

    # Read bytes to detect BOM (skip if locked)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($f)
        $bom   = Has-BOM -Bytes $bytes
    } catch {
        $bom   = $false
    }

    # Determine whether to attempt text read
    $ext = [System.IO.Path]::GetExtension($f).ToLower()
    $shouldCheckText = $IncludeBinaries -or -not ($BinaryExt -contains $ext)

    if ($shouldCheckText) {
        try {
            $text = Get-Content -LiteralPath $f -Raw -ErrorAction Stop
            $smart = Contains-SmartQuotes -Text $text
        } catch {
            $smart = $false
        }
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

$rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $CsvPath
Write-Host "CSV written: $CsvPath"

Stop-Transcript | Out-Null
Write-Host "Transcript closed: $TranscriptPath"
