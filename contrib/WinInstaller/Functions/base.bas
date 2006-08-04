Attribute VB_Name = "base"

Public Sub Main()

    Dim lngError As Long, lngProcessHandle As Long
    Dim strCline As String
    Dim strCommand As String
    Dim strProcess As String
    Dim marker1 As Integer
    
    strCline = Command
    
    On Error Resume Next
    
    If Len(strCline) > 0 Then
    
        marker1 = InStr(1, strCline, "=", vbTextCompare)
        
        If marker1 > 0 Then
           strCommand = Trim(Left(strCline, marker1 - 1))
           strProcess = Trim(Right(strCline, Len(strCline) - marker1))
      
        
         If strCommand = "kill" Then
          'Unload process
          lngProcessHandle = GetPIDFromProcess(strProcess)
          If lngProcessHandle > 0 Then
            lngError = KillProcess(lngProcessHandle)
            Wait 1
          End If
          End
         End If
         
         If strCommand = "call" Then
           Form1.Connect strProcess
         End If
        Else
         
         If strCline = "user" Then
           Form1.Show
         End If
        End If
    End If
    
End Sub
