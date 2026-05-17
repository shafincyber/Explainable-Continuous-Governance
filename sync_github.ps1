# ==============================================================================
# Sentinel-GRC: Autonomous GitHub Sync Script
# ==============================================================================

Write-Host "==================================================" -ForegroundColor DarkGray
Write-Host "[*] INITIATING SENTINEL-GRC GITHUB UPLINK..." -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor DarkGray

# 1. Verify Git Repository
if (-not (Test-Path .git)) {
    Write-Host "[-] FATAL: No .git directory found. Ensure you are in the Sentinel-GRC root folder." -ForegroundColor Red
    exit 1
}

# 2. Stage All Changes (worker.py, regulatory_matrix.json, etc.)
Write-Host "[*] Staging patched architecture files..." -ForegroundColor Yellow
git add .

# 3. Generate Timestamped Commit
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm"
$commitMessage = "Core Architecture Patch ($timestamp): Implemented direct memory execution for Checkov Windows venv bypass and updated Neo4j schema."

Write-Host "[*] Committing payload: '$commitMessage'" -ForegroundColor Yellow
git commit -m "$commitMessage"

# 4. Push to Remote Origin
Write-Host "[*] Pushing architecture to remote GitHub repository..." -ForegroundColor Yellow
git push

# 5. Execution Validation
if ($LASTEXITCODE -eq 0) {
    Write-Host "`n[+] UPLINK SUCCESSFUL: Sentinel-GRC architecture is locked and secured on GitHub." -ForegroundColor Green
} else {
    Write-Host "`n[-] UPLINK FAILED: Review the Git error above. (You may need to run 'git push --set-upstream origin main' if this is your first push)." -ForegroundColor Red
}
Write-Host "==================================================`n" -ForegroundColor DarkGray