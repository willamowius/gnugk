#!/bin/sh
# .----------------------------.
# | Restart GnuGk on IP change |
# | Call this script via cron  |
# '----------------------------'

DYNHOST=my-name.dyndns.org
IPFILE=/root/scripts/dynamicIP.txt
RELOADCMD="/usr/local/etc/rc.d/gnugk reload"       # on FreeBSD
RESTARTCMD="/usr/local/etc/rc.d/gnugk restart"     # on FreeBSD

# CONFIG END

cat_dynfile () { cat $IPFILE; }
echo_dynip () { host $DYNHOST | awk '{print $4}'; }

if [ $(cat_dynfile) != $(echo_dynip) ]
then
echo "Dynamic IP changed from $(cat_dynfile) to $(echo_dynip). Reloading GnuGk..."
$RELOADCMD
echo $(echo_dynip) > $IPFILE
fi

if [ -z $(pidof gnugk) ]
then
echo "GnuGk not running. Restarting..."
$RESTARTCMD
fi

