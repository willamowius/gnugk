# Microsoft Developer Studio Project File - Name="gk" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=gk - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "gk.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "gk.mak" CFG="gk - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "gk - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "gk - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "gk - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GR /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GR /GX /O2 /I "..\include" /D "NDEBUG" /D "PTRACING" /FD /c
# ADD BASE RSC /l 0x407 /d "NDEBUG"
# ADD RSC /l 0x407 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 ptclib.lib ptlib.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib wsock32.lib OpenH323.lib /nologo /subsystem:console /machine:I386 /libpath:"..\..\lib"
# SUBTRACT LINK32 /debug

!ELSEIF  "$(CFG)" == "gk - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GR /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /Gm /GR /GX /Zi /Od /I "..\include" /D "_DEBUG" /D "PTRACING" /FR /FD /GZ /c
# SUBTRACT CPP /YX /Yc /Yu
# ADD BASE RSC /l 0x407 /d "_DEBUG"
# ADD RSC /l 0x407 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept
# ADD LINK32 ptclibd.lib ptlibd.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib uuid.lib wsock32.lib OpenH323.lib /nologo /subsystem:console /incremental:no /debug /machine:I386 /pdbtype:sept /libpath:"..\..\lib"
# SUBTRACT LINK32 /nodefaultlib

!ENDIF 

# Begin Target

# Name "gk - Win32 Release"
# Name "gk - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\BroadcastListen.cxx
# End Source File
# Begin Source File

SOURCE=.\gk.cxx
# End Source File
# Begin Source File

SOURCE=.\GkStatus.cxx
# End Source File
# Begin Source File

SOURCE=.\h323util.cxx
# End Source File
# Begin Source File

SOURCE=.\main.cxx
# End Source File
# Begin Source File

SOURCE=.\MulticastGRQ.cxx
# End Source File
# Begin Source File

SOURCE=.\precompile.cxx
# End Source File
# Begin Source File

SOURCE=.\RasSrv.cxx
# End Source File
# Begin Source File

SOURCE=.\RasTbl.cxx
# End Source File
# Begin Source File

SOURCE=.\SignalChannel.cxx
# End Source File
# Begin Source File

SOURCE=.\SignalConnection.cxx
# End Source File
# Begin Source File

SOURCE=.\singleton.cxx
# End Source File
# Begin Source File

SOURCE=.\SoftPBX.cxx
# End Source File
# Begin Source File

SOURCE=.\Toolkit.cxx
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\ANSI.h
# End Source File
# Begin Source File

SOURCE=.\BroadcastListen.h
# End Source File
# Begin Source File

SOURCE=.\gk.h
# End Source File
# Begin Source File

SOURCE=.\gk_const.h
# End Source File
# Begin Source File

SOURCE=.\GkStatus.h
# End Source File
# Begin Source File

SOURCE=.\h323util.h
# End Source File
# Begin Source File

SOURCE=.\MulticastGRQ.h
# End Source File
# Begin Source File

SOURCE=.\RasSrv.h
# End Source File
# Begin Source File

SOURCE=.\RasTbl.h
# End Source File
# Begin Source File

SOURCE=.\SignalChannel.h
# End Source File
# Begin Source File

SOURCE=.\SignalConnection.h
# End Source File
# Begin Source File

SOURCE=.\singleton.h
# End Source File
# Begin Source File

SOURCE=.\SoftPBX.h
# End Source File
# Begin Source File

SOURCE=.\stl_supp.h
# End Source File
# Begin Source File

SOURCE=.\Toolkit.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# Begin Group "Doc Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\changes.txt
# End Source File
# Begin Source File

SOURCE=.\compiling.txt
# End Source File
# Begin Source File

SOURCE=.\gkstatus.txt
# End Source File
# Begin Source File

SOURCE=.\performance.txt
# End Source File
# Begin Source File

SOURCE=.\readme.txt
# End Source File
# Begin Source File

SOURCE=.\reference.txt
# End Source File
# Begin Source File

SOURCE=.\signalling.txt
# End Source File
# Begin Source File

SOURCE=".\test-status.txt"
# End Source File
# Begin Source File

SOURCE=.\todo.txt
# End Source File
# Begin Source File

SOURCE=.\tutorial.txt
# End Source File
# End Group
# End Target
# End Project
