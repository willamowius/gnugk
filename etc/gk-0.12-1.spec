#
# rpm spec file for package openh323gk
# 
# Author: Marco Budde, Jan Willamowius
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.                                                        


Vendor:       Jan Willamowius
Name:         gk
Release:      2
Copyright:    GPL
Group:        System Environment/Libraries

Version:      0.12
Summary:      H.323 gatekeeper
Url:          http://www.willamowius.de/openh323gk.html 
BuildRoot:    /tmp/gk_build
Source:       gk0.12.tar.gz
%description
A H.323 gatekeeper controls all H.323 clients (endpoints 
like MS Netmeeting) in his zone. Its most important 
function is address translation between symbolic alias 
addresses and IP addresses. This way you can call 
"jan" instead of knowing which IP address he currently 
works on.

%prep
%setup

%build
make opt

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/sbin
install -s obj_linux_x86_r/gk $RPM_BUILD_ROOT/usr/sbin/
mkdir -p $RPM_BUILD_ROOT/sbin/init.d/rc2.d
mkdir -p $RPM_BUILD_ROOT/sbin/init.d/rc3.d
install gk.initd.suse $RPM_BUILD_ROOT/sbin/init.d/gk
ln -sf ../gk $RPM_BUILD_ROOT/sbin/init.d/rc2.d/S20gk
ln -sf ../gk $RPM_BUILD_ROOT/sbin/init.d/rc2.d/K20gk
ln -sf ../gk $RPM_BUILD_ROOT/sbin/init.d/rc3.d/S20gk
ln -sf ../gk $RPM_BUILD_ROOT/sbin/init.d/rc3.d/K20gk

%clean
make clean

%files
/usr/sbin/gk
/sbin/init.d/rc2.d/S20gk
/sbin/init.d/rc2.d/K20gk
/sbin/init.d/rc3.d/S20gk
/sbin/init.d/rc3.d/K20gk
%doc *.html
%doc changes.txt gkstatus.txt readme.txt todo.txt
%config /sbin/init.d/gk

%changelog
* Sat Apr 9 2000 Jan Willamowius <jan@willamowius.de>
  updated for 0.12
* Tue Jan 25 2000 Marco Budde <budde@telos.de>
- initial release

