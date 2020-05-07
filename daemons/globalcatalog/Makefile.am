# This file will be processed with automake-1.7 to create Makefile.in
#
AUTOMAKE_OPTIONS = 1.7

appdir = $(libexecdir)/ipa/gc/
nodist_app_SCRIPTS = 		\
	ipa-gcsyncd

dist_noinst_DATA = 		\
	ipa-gcsyncd.service.in	\
	ipa-gcsyncd.in


systemdsystemunit_DATA = 	\
	ipa-gcsyncd.service

CLEANFILES = $(systemdsystemunit_DATA) $(nodist_app_SCRIPTS)

%: %.in Makefile
	sed \
		-e 's|@libexecdir[@]|$(libexecdir)|g' \
		'$(srcdir)/$@.in' >$@

PYTHON_SHEBANG = 		\
	$(nodist_app_SCRIPTS)	\
	$(NULL)

include $(top_srcdir)/Makefile.pythonscripts.am
