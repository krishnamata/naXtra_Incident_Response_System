$ErrorActionPreference = "Stop"

$server = "192.168.18.162"
$target = "$env:ProgramFiles\naXtraSOAR_Agent"
$zipUrl = "http://$server:5001/static/windows_agent.zip"
$zipPath = "$target\windows_agent.zip"

Write-Host "[+] Creating agent directory"
New-Item -ItemType Directory -Path $target -Force | Out-Null

Write-Host "[+] Checking Python"
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "Python is not installed. Install Python 3.x and retry."
    exit 1
}

Write-Host "[+] Downloading agent package"
Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath

Write-Host "[+] Extracting agent"
Expand-Archive $zipPath -DestinationPath $target -Force

Write-Host "[+] Creating Windows service"
sc.exe create naxtrasoar-agent `
  binPath= "`"$env:ProgramFiles\Python39\python.exe`" `"$target\agent.py`"" `
  start= auto

sc.exe start naxtrasoar-agent

Write-Host "[+] naXtraSOAR Windows Agent installed and started"
