all:	html pdf

html:
	sgml2html -s 0 manual.sgml

pdf:
	sgml2dvi manual.sgml ; dvipdfm manual.dvi ; rm manual.dvi

