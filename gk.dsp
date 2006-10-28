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
# ADD CPP /nologo /G6 /MD /W3 /GR /GX /Og /Oi /Os /Oy /Ob2 /D "NDEBUG" /D "PTRACING" /D HAS_RADIUS=1 /FD /c
# SUBTRACT CPP /Ox /Ot
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 /nologo /subsystem:console /machine:I386
# ADD LINK32 OpenH323s.lib ptclib.lib ptlibs.lib snmpapi.lib user32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib mpr.lib wsock32.lib /nologo /subsystem:console /machine:I386 /out:"Release/gnugk.exe"
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
# ADD CPP /nologo /G6 /MDd /W3 /Gm /GR /GX /Zi /Od /D "_DEBUG" /D "PTRACING" /D HAS_RADIUS=1 /FR /FD /GZ /c
# SUBTRACT CPP /YX /Yc /Yu
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept
# ADD LINK32 openh323d.lib ptclibd.lib ptlibd.lib snmpapi.lib Winmm.lib mpr.lib user32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib uuid.lib wsock32.lib /nologo /subsystem:console /incremental:no /debug /machine:I386 /out:"Debug/gnugk.exe" /pdbtype:sept

!ENDIF 

# Begin Target

# Name "gk - Win32 Release"
# Name "gk - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\cisco.cxx
# End Source File
# Begin Source File

SOURCE=.\clirw.cxx
# End Source File
# Begin Source File

SOURCE=.\gk.cxx
# End Source File
# Begin Source File

SOURCE=.\gk.rc
# End Source File
# Begin Source File

SOURCE=.\gkacct.cxx
# End Source File
# Begin Source File

SOURCE=.\gkauth.cxx
# End Source File
# Begin Source File

SOURCE=.\GkClient.cxx
# End Source File
# Begin Source File

SOURCE=.\gkconfig.cxx
# End Source File
# Begin Source File

SOURCE=.\gksql.cxx
# End Source File
# Begin Source File

SOURCE=.\gksql_mysql.cxx
# End Source File
# Begin Source File

SOURCE=.\gksql_pgsql.cxx
# End Source File
# Begin Source File

SOURCE=.\GkStatus.cxx
# End Source File
# Begin Source File

SOURCE=.\gktimer.cxx
# End Source File
# Begin Source File

SOURCE=.\h323util.cxx
# End Source File
# Begin Source File

SOURCE=.\ipauth.cxx
# End Source File
# Begin Source File

SOURCE=.\job.cxx
# End Source File
# Begin Source File

SOURCE=.\main.cxx
# End Source File
# Begin Source File

SOURCE=.\Neighbor.cxx
# End Source File
# Begin Source File

SOURCE=.\precompile.cxx
# End Source File
# Begin Source File

SOURCE=.\ProxyChannel.cxx
# End Source File
# Begin Source File

SOURCE=.\radacct.cxx
# End Source File
# Begin Source File

SOURCE=.\radauth.cxx
# End Source File
# Begin Source File

SOURCE=.\radproto.cxx
# End Source File
# Begin Source File

SOURCE=.\RasSrv.cxx
# End Source File
# Begin Source File

SOURCE=.\RasTbl.cxx
# End Source File
# Begin Source File

SOURCE=.\Routing.cxx
# End Source File
# Begin Source File

SOURCE=.\sigmsg.cxx
# End Source File
# Begin Source File

SOURCE=.\singleton.cxx
# End Source File
# Begin Source File

SOURCE=.\SoftPBX.cxx
# End Source File
# Begin Source File

SOURCE=.\sqlacct.cxx
# End Source File
# Begin Source File

SOURCE=.\sqlauth.cxx
# End Source File
# Begin Source File

SOURCE=.\statusacct.cxx
# End Source File
# Begin Source File

SOURCE=.\Toolkit.cxx
# End Source File
# Begin Source File

SOURCE=.\version.cxx
# End Source File
# Begin Source File

SOURCE=.\yasocket.cxx
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\cisco.h
# End Source File
# Begin Source File

SOURCE=.\clirw.h
# End Source File
# Begin Source File

SOURCE=.\factory.h
# End Source File
# Begin Source File

SOURCE=.\gk.h
# End Source File
# Begin Source File

SOURCE=.\gk_const.h
# End Source File
# Begin Source File

SOURCE=.\gkacct.h
# End Source File
# Begin Source File

SOURCE=.\gkauth.h
# End Source File
# Begin Source File

SOURCE=.\GkClient.h
# End Source File
# Begin Source File

SOURCE=.\gkconfig.h
# End Source File
# Begin Source File

SOURCE=.\gksql.h
# End Source File
# Begin Source File

SOURCE=.\GkStatus.h
# End Source File
# Begin Source File

SOURCE=.\gktimer.h
# End Source File
# Begin Source File

SOURCE=.\h323util.h
# End Source File
# Begin Source File

SOURCE=.\ipauth.h
# End Source File
# Begin Source File

SOURCE=.\job.h
# End Source File
# Begin Source File

SOURCE=.\name.h
# End Source File
# Begin Source File

SOURCE=.\Neighbor.h
# End Source File
# Begin Source File

SOURCE=.\ProxyChannel.h
# End Source File
# Begin Source File

SOURCE=.\pwlib_compat.h
# End Source File
# Begin Source File

SOURCE=.\radacct.h
# End Source File
# Begin Source File

SOURCE=.\radauth.h
# End Source File
# Begin Source File

SOURCE=.\radproto.h
# End Source File
# Begin Source File

SOURCE=.\rasinfo.h
# End Source File
# Begin Source File

SOURCE=.\RasPDU.h
# End Source File
# Begin Source File

SOURCE=.\RasSrv.h
# End Source File
# Begin Source File

SOURCE=.\RasTbl.h
# End Source File
# Begin Source File

SOURCE=.\Routing.h
# End Source File
# Begin Source File

SOURCE=.\rwlock.h
# End Source File
# Begin Source File

SOURCE=.\sigmsg.h
# End Source File
# Begin Source File

SOURCE=.\singleton.h
# End Source File
# Begin Source File

SOURCE=.\slist.h
# End Source File
# Begin Source File

SOURCE=.\SoftPBX.h
# End Source File
# Begin Source File

SOURCE=.\sqlacct.h
# End Source File
# Begin Source File

SOURCE=.\statusacct.h
# End Source File
# Begin Source File

SOURCE=.\stl_supp.h
# End Source File
# Begin Source File

SOURCE=.\Toolkit.h
# End Source File
# Begin Source File

SOURCE=.\version.h
# End Source File
# Begin Source File

SOURCE=.\yasocket.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# Begin Source File

SOURCE=.\gk.ico
# End Source File
# End Group
# Begin Group "Doc Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\changes.txt
# End Source File
# Begin Source File

SOURCE=.\readme.txt
# End Source File
# End Group
# End Target
# End Project
