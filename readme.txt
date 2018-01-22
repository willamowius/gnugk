The GNU Gatekeeper
------------------

It is covered by the GNU Public License (GPL) v2; for details
see the file COPYING. In addition to that, we explicitely grant
the right to link this code to the OpenH323/H323Plus and
OpenSSL library.

Project homepage: https://www.gnugk.org/
Project coordinator: Jan Willamowius <jan@willamowius.de>
Support: https://www.willamowus.com/gnugk-support.html

To ask questions or submit bugs, please subscribe to our mailing list:
https://lists.gnugk.org/cgi-bin/mailman/listinfo/gnugk-users

There are a number of documents in docs/ subdirectory to get you
started working with the gatekeeper. The most important is the
manual directory. The manual is in SGML (linuxdoc) format. You can convert
it into HTML or PDF with sgmltools:

$ sgml2html manual.sgml # HTML
$ sgml2latex --output=dvi --style=gnugk manual.sgml ; dvipdfm manual.dvi # PDF

There are a number of useful configuration examples in
the etc/ subdirectory. Modify them to suit your needs.

