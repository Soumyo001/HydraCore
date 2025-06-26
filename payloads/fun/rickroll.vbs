set ws = CreateObject("wscript.shell")

Dim i, messages
messages = Array( _
    "Something is watching you...", _
    "Did you hear that noise?", _
    "Check behind you!", _
    "Just kidding! Or am I?" _
)

For i = 0 To UBound(messages)
    MsgBox messages(i), vbExclamation, "Warning"
    WScript.Sleep 1000
Next

WScript.Sleep 3000

For i=0 To 3
    ws.run "powershell.exe", 3, False
    wscript.sleep(500)
    ws.SendKeys("curl.exe ascii.live/rick{ENTER}")
Next