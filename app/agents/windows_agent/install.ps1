$target = "$env:ProgramFiles\naXtraSOAR_Agent"
New-Item -ItemType Directory -Path $target -Force
Invoke-WebRequest -Uri http://<YOUR_NAXTRASOAR_IP>:5001/static/windows_agent.zip -OutFile "$target\windows_agent.zip"
Expand-Archive "$target\windows_agent.zip" -DestinationPath $target -Force
Start-Process "python" "$target\agent.py"
