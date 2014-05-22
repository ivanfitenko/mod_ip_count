# $Id: Makefile.am,v 1.3 2008/11/24 15:58:54 sin Exp $ 

bin_PROGRAMS = mod_ip_count.so

EXTRA_DIST = memcache/apr_memcache.c \
	README

CLEANFILES = .libs/libmod_ip_count *~ memcache/*~ .libs/apr_memcache*

mod_ip_count.so$(EXEEXT): mod_ip_count.c memcache/apr_memcache.c memcache/apr_memcache.h
	@${APXS_BIN} -Wc $(AP_DEFS) -I memcache -c mod_ip_count.c memcache/apr_memcache.c 
	ln -sf .libs/mod_ip_count.so mod_ip_count.so

clean:
	rm -fr .libs
	rm -f *.o *.lo *.la
	rm -f mod_ip_count.so

install: mod_ip_count.so$(EXEEXT)
	@${APXS_BIN} -Wc $(AP_DEFS) -i -n ip_count mod_ip_count.so

activate: mod_ip_count.so$(EXEEXT)
	@${APXS_BIN} -i -a -n ip_count mod_ip_count.so

