# $Id: Makefile.am,v 1.2 2008/11/22 09:10:08 proger Exp $

CLEANFILES = .libs/libapr_memcache *~

libapr_memcache_la_SOURCES = apr_memcache.c
libapr_memcache_la_CFLAGS = -Wall ${MODULE_CFLAGS}
libapr_memcache_la_LDFLAGS = -module -avoid-version ${MODULE_LIBS}
libapr_memcache_la_includedir=$(includedir)/apr_memcache-0
libapr_memcache_la_include_HEADERS = apr_memcache.h

lib_LTLIBRARIES = libapr_memcache.la 

make_so: ${lib_LTLIBRARIES}
	@if test ! -L apr_memcache.so ; then ln -s .libs/libapr_memcache.so apr_memcache.so ; fi

clean:
	rm -fr .libs
	rm -f *.o *.lo *.la
	rm -f apr_memcache.so

install: install-data install-exec
	@echo ""
	@echo ""
	@echo "***********************************************"
	@echo ""
	@echo "   Please read the documentation at            "
	@echo "   http://www.outoforder.cc "
	@echo "   for details on using this library.     "
	@echo ""
	@echo "***********************************************"
	@echo ""
