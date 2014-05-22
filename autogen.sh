#!/bin/sh
# $Id: autogen.sh,v 1.2 2008/11/22 09:10:07 proger Exp $

# autogen.sh - generates configure using the autotools
libtoolize --force --copy
aclocal -I m4
autoheader
automake --add-missing --copy --foreign
autoconf
rm -rf autom4te.cache
