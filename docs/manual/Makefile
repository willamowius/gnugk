all:	html pdf

html:
	sgml2html -s 1 manual.sgml

html-fr:
	cd fr ; sgml2html --language=fr -s 1 manual-fr.sgml

html-es:
	cd es ; sgml2html --language=es -s 1 manual-es.sgml

pdf:
	sgml2latex manual.sgml ; dvipdfm manual.dvi ; rm manual.dvi

pdf-fr:
	cd fr ; sgml2latex --language=fr manual-fr.sgml ; dvipdfm manual-fr.dvi ; rm manual-fr.dvi

pdf-es:
	cd es ; sgml2latex --language=es manual-es.sgml ; dvipdfm manual-es.dvi ; rm manual-es.dvi

