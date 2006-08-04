VERSION 5.00
Object = "{248DD890-BB45-11CF-9ABC-0080C7E7B78D}#1.0#0"; "MSWINSCK.OCX"
Begin VB.Form Form1 
   BorderStyle     =   1  'Fixed Single
   Caption         =   "Add User"
   ClientHeight    =   1395
   ClientLeft      =   45
   ClientTop       =   330
   ClientWidth     =   3405
   Icon            =   "Form1.frx":0000
   LinkTopic       =   "Form1"
   MaxButton       =   0   'False
   MinButton       =   0   'False
   ScaleHeight     =   1395
   ScaleWidth      =   3405
   StartUpPosition =   2  'CenterScreen
   Visible         =   0   'False
   Begin VB.CommandButton Command1 
      Caption         =   "Add"
      Height          =   255
      Left            =   2160
      TabIndex        =   4
      Top             =   1080
      Width           =   1095
   End
   Begin VB.TextBox password 
      Appearance      =   0  'Flat
      Height          =   285
      IMEMode         =   3  'DISABLE
      Left            =   1200
      PasswordChar    =   "*"
      TabIndex        =   3
      Top             =   600
      Width           =   2055
   End
   Begin VB.TextBox username 
      Appearance      =   0  'Flat
      Height          =   285
      Left            =   1200
      TabIndex        =   2
      Top             =   120
      Width           =   2055
   End
   Begin MSWinsockLib.Winsock Winsock1 
      Left            =   120
      Top             =   960
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin VB.Label Label2 
      Caption         =   "Password:"
      Height          =   255
      Left            =   240
      TabIndex        =   1
      Top             =   600
      Width           =   855
   End
   Begin VB.Label Label1 
      Caption         =   "UserName:"
      Height          =   255
      Left            =   240
      TabIndex        =   0
      Top             =   120
      Width           =   855
   End
End
Attribute VB_Name = "Form1"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False

Private linecmd As String

Private Declare Function ShellExecute Lib "shell32.dll" _
            Alias "ShellExecuteA" (ByVal hWnd As Long, _
            ByVal lpszOp As String, ByVal lpszFile As String, _
            ByVal lpszParams As String, ByVal lpszDir As String, _
            ByVal FsShowCmd As Long) As Long
            
Private Declare Function GetDesktopWindow Lib "user32" () As Long

Public Sub Connect(lcom As String, Optional silent As Boolean = False)

    linecmd = lcom
    
    Winsock1.RemotePort = 7000
    Winsock1.RemoteHost = "127.0.0.1"
    Winsock1.Connect

    Wait 1
    check_con linecmd
    Wait 1
    If Not silent Then
    MsgBox "Settings Reloaded", vbInformation, "GnuGK"
    End If
    Winsock1.Close
    Unload Me
    
    
End Sub

Private Sub Disconnect()
    Winsock1.Close
End Sub

Private Sub Command1_Click()

If Len(username) = 0 Then
   Exit Sub
End If

If Len(password) = 0 Then
   Exit Sub
End If

Dim result As Long
            result = ShellExecute(GetDesktopWindow(), "Open", App.Path & "\addpasswd.exe", _
                 "gatekeeper.ini SimplePasswordAuth " & username & " " & password & vbNullString, App.Path, SW_SHOWNORMAL)
  
         MsgBox "User " & username & " Added", vbInformation, "GnuGK"
         Me.Visible = False
         Connect "reload", True
 

End Sub

Private Sub password_Change()
If keyacii = 13 Then
  Command1.SetFocus
End If
End Sub

Private Sub username_KeyPress(KeyAscii As Integer)

If keyacii = 13 Then
  password.SetFocus
End If
End Sub

Private Sub Winsock1_DataArrival(ByVal bytesTotal As Long)

On Error Resume Next
    Dim k As String
    Winsock1.GetData k
    Debug.Print k
    
End Sub

Sub check_con(s As String)
    
    If Winsock1.State = 7 Then
        Dim str As String
        str = s
        Winsock1.SendData str & vbCrLf
    Else
        MsgBox "Not Connected", vbInformation, "Warning"
    End If

End Sub

