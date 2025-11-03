# Helper script to connect local repo to GitHub repository
# Run this after creating the repository on GitHub.com

param(
    [Parameter(Mandatory=$true)]
    [string]$GitHubUsername
)

$repoName = "MAMAN15_Security_Analysis"
$repoUrl = "https://github.com/$GitHubUsername/$repoName.git"

Write-Host "Setting up remote for $repoUrl" -ForegroundColor Green

# Add remote
git remote add origin $repoUrl 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Remote might already exist. Updating..." -ForegroundColor Yellow
    git remote set-url origin $repoUrl
}

# Verify remote
Write-Host "`nCurrent remotes:" -ForegroundColor Cyan
git remote -v

# Push to main branch
Write-Host "`nPushing to GitHub..." -ForegroundColor Green
git push -u origin main

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nSuccess! Repository pushed to GitHub." -ForegroundColor Green
    Write-Host "View your repo at: https://github.com/$GitHubUsername/$repoName" -ForegroundColor Cyan
} else {
    Write-Host "`nPush failed. Please check:" -ForegroundColor Red
    Write-Host "1. Repository exists on GitHub: https://github.com/$GitHubUsername/$repoName"
    Write-Host "2. You have proper authentication set up"
    Write-Host "3. Try: git push -u origin main --force (if repository was initialized with files)"
}

