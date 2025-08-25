param(
    [string]$ServerIP
)

Write-Host "Installing naXtraSOAR Agent for Windows..."
# Simulate agent setup
$agentScript = @"
while ($true) {
    \$log = Get-EventLog -LogName Application -Newest 1 | ConvertTo-Json
    Invoke-RestMethod -Uri http://$ServerIP:5000/api/ingest -Method POST -Body @{log=\$log} -ContentType "application/json"
    Start-Sleep -Seconds 10
}
"@

$agentScript | Out-File -FilePath "naXtraAgent.ps1" -Encoding ASCII
Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File .\naXtraAgent.ps1" -WindowStyle Hidden
