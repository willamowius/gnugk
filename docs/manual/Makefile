# detect distribution: sgml2... is called differently on Ubuntu
distro := $(shell lsb_release -i -s 2> /dev/null)
ifeq ($(distro),Ubuntu)
	SGML2LATEX = linuxdoc -B latex
	SGML2HTML = linuxdoc -B html -T 2
	SGML2TXT = linuxdoc -B txt
else
	SGML2LATEX = sgml2latex
	SGML2HTML = sgml2html
	SGML2TXT = sgml2txt
endif
# DVIPDFM = dvipdfmx	# works also
DVIPDFM = dvipdfm

all:	html

html:
	$(SGML2HTML) -s 0 manual.sgml

html-fr:
	cd fr ; $(SGML2HTML) --language=fr -s 0 manual-fr.sgml

html-es:
	cd es ; $(SGML2HTML) --language=es -s 0 manual-es.sgml

html-zh_CN:
	cd zh_CN ; SP_CHARSET_FIXED=yes SP_ENCODING=xml $(SGML2HTML) --language=en -s 0 manual-zh_CN.sgml

pdf:
	$(SGML2LATEX) --output=dvi --style=gnugk manual.sgml ; $(DVIPDFM) manual.dvi ; rm -f manual.dvi ; pdfunite GnuGkManualTitle.pdf manual.pdf manual-out.pdf ; mv manual-out.pdf manual.pdf

pdf-fr:
	cd fr ; $(SGML2LATEX) --language=fr --style=gnugk manual-fr.sgml ; $(DVIPDFM) manual-fr.dvi ; rm -f manual-fr.dvi

pdf-es:
	cd es ; $(SGML2LATEX) --language=es --style=gnugk manual-es.sgml ; $(DVIPDFM) manual-es.dvi ; rm -f manual-es.dvi

pdf-zh_CN:
	cd zh_CN ; SP_CHARSET_FIXED=yes SP_ENCODING=xml $(SGML2LATEX) --language=en --style=gnugk manual-zh_CN.sgml ; $(DVIPDFM) manual-zh_CN.dvi ; rm -f manual-zh_CN.dvi

txt:
	$(SGML2TXT) --charset=latin manual.sgml

txt-fr:
	cd fr ; $(SGML2TXT) --language=fr --charset=latin manual-fr.sgml

txt-es:
	cd es ; $(SGML2TXT) --language=es --charset=latin manual-es.sgml

txt-zh_CN:
	cd zh_CN ; SP_CHARSET_FIXED=yes SP_ENCODING=xml $(SGML2TXT) --language=en --charset=latin manual-zh_CN.sgml

clean:
	rm -f *.html *.pdf *.dvi *.txt fr/*.html fr/*.pdf fr/*.dvi fr/[a-zA-Z]*.txt es/*.html es/*.pdf es/*.dvi es/*.txt zh_CN/*.html zh_CN/*.pdf zh_CN/*.dvi zh_CN/*.txt

