all:	html pdf

html:
	sgml2html -s 1 manual.sgml

pdf:
	sgml2latex manual.sgml ; dvipdfm manual.dvi ; rm manual.dvi

