set ws = CreateObject("wscript.shell")

Dim i

For i=0 To 5
    ws.run "powershell.exe", 3, False
    wscript.sleep(500)
    ws.SendKeys("curl.exe ascii.live/rick{ENTER}")
Next
WScript.Sleep 3000
Dim messages
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


'   -------------------------------------------------------------------
'   constants           |   value   |    Description
'   -------------------------------------------------------------------
'   
'   vbOkOnly	        |    0	    |    OK button only
'   vbOkCancel	        |    1	    |    OK and Cancel buttons
'   vbAbortRetryIgnore	|    2	    |    Abort, Retry, Ignore buttons
'   vbYesNoCancel	    |    3	    |    Yes, No, Cancel buttons
'   vbYesNo	            |    4	    |    Yes and No buttons
'   vbRetryCancel	    |    5	    |    Retry and Cancel buttons
'   vbCritical	        |    16	    |    Critical Error icon
'   vbQuestion	        |    32	    |    Question icon
'   vbExclamation	    |    48	    |    Exclamation icon
'   vbInformation	    |    64	    |    Information icon
'   vbDefaultButton1	|    0	    |    Default Button 1
'   vbDefaultButton2	|    256	|    Default Button 2
'   vbDefaultButton3	|    512	|    Default Button 3
'   vbSystemModal	    |    4096	|    System modal window