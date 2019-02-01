#!/bin/sh

rm -rf autom4te.cache >/dev/null 2>&1
rm -f aclocal.m4
case `uname` in
    Darwin*)
        glibtoolize --force --copy
    ;;
    *)
        libtoolize --force --copy
    ;;
esac
autoreconf --install
automake --add-missing --foreign --copy --force-missing
autoconf --force
rm -rf autom4te.cache
