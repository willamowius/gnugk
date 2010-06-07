# detect distribution: sgml2... is called differently on Ubuntu
distro := $(shell lsb_release -i -s 2> /dev/null)
ifeq ($(distro),Ubuntu)
	SGML2LATEX = linuxdoc -B latex
	SGML2HTML = linuxdoc -B html
	SGML2TXT = linuxdoc -B txt
else
	SGML2LATEX = sgml2latex
	SGML2HTML = sgml2html
	SGML2TXT = sgml2txt
endif

all:	html pdf

html:
	$(SGML2HTML) -s 1 manual.sgml

html-fr:
	cd fr ; $(SGML2HTML) --language=fr -s 1 manual-fr.sgml

html-es:
	cd es ; $(SGML2HTML) --language=es -s 1 manual-es.sgml

pdf:
	$(SGML2LATEX) --output=dvi manual.sgml ; dvipdfm manual.dvi ; rm -f manual.dvi

pdf-fr:
	cd fr ; $(SGML2LATEX) --language=fr manual-fr.sgml ; dvipdfm manual-fr.dvi ; rm -f manual-fr.dvi

pdf-es:
	cd es ; $(SGML2LATEX) --language=es manual-es.sgml ; dvipdfm manual-es.dvi ; rm -f manual-es.dvi

txt:
	$(SGML2TXT) --charset=latin manual.sgml

txt-fr:
	cd fr ; $(SGML2TXT) --language=fr --charset=latin manual-fr.sgml

txt-es:
	cd es ; $(SGML2TXT) --language=es --charset=latin manual-es.sgml

clean:
	rm -f *.html *.pdf *.dvi *.txt fr/*.html fr/*.pdf fr/*.dvi fr/[a-zA-Z]*.txt es/*.html es/*.pdf es/*.dvi es/*.txt

