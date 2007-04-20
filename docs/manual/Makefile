all:	html pdf

html:
	sgml2html -s 1 manual.sgml

html-fr:
	cd fr ; sgml2html --language=fr -s 1 manual-fr.sgml

html-es:
	cd es ; sgml2html --language=es -s 1 manual-es.sgml

pdf:
	sgml2latex --output=dvi manual.sgml ; dvipdfm manual.dvi ; rm -f manual.dvi

pdf-fr:
	cd fr ; sgml2latex --language=fr manual-fr.sgml ; dvipdfm manual-fr.dvi ; rm -f manual-fr.dvi

pdf-es:
	cd es ; sgml2latex --language=es manual-es.sgml ; dvipdfm manual-es.dvi ; rm -f manual-es.dvi

txt:
	sgml2txt --charset=latin manual.sgml

txt-fr:
	cd fr ; sgml2txt --language=fr --charset=latin manual-fr.sgml

txt-es:
	cd es ; sgml2txt --language=es --charset=latin manual-es.sgml

clean:
	rm -f *.html *.pdf *.dvi *.txt fr/*.html fr/*.pdf fr/*.dvi fr/[a-zA-Z]*.txt es/*.html es/*.pdf es/*.dvi es/*.txt
