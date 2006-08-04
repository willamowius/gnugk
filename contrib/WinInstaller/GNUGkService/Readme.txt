++++++++++++++++++++++++++++++

GNUGK NTService Installer

++++++++++++++++++++++++++++++

You will need the Visual Basic Runtime Libraries. 
Win2000 and XP should have them installed by default.

The PacPhone NTService Installer is another method to 
install programs as services under NT/2000/XP.

The pacGnuGKNTS acts as an service Host to run GNUGK. 
On Startup the GNUGK service runs pacGnuGKNTS with a commandline switch to launch GNUGK.


To Use
Copy the pacGnuGKNTS.exe, NTSVC.ocx, Install_GNUGK.bat & UnInstall_GNUGK.bat to a Trusted directory (A directory that you will not delete) 

Edit the Install_GNUGK.bat and change the 
"-command" entry to point to your GNUGK.exe binary location.
"-visible" entry to yes if you want GnuGK to run visibly.

Run the Batch file "Install_GNUGK.bat". This should install the GNUGK Service.

You can test the service by controlpanel > Administrative tools > Services
highlight GNUGK Service right click properties click start and stop.

To remove the service run uninstall_GNUGK.bat.

The GnuGK service will automatically run at computer startup and will automatically restart GnuGK if there is an error.


Complete Visual Basic source code is included in the source directory.


Simon Horne
Packetizer Labs 
s.horne@packetizer.com

==================================
PacPhone
The Secure NAT-Aware H.323 softphone 
(with GnuGK NAT technology and AES256 Voice Encryption)

www.pacphone.com
=================================


