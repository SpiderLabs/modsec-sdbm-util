dnl
dnl Autoconf configuration for ModSecurity
dnl
dnl     Use ./autogen.sh to produce a configure script
dnl

AC_PREREQ(2.63)

AC_INIT([modsec-sdbm-util], [1.0], [support@modsecurity.org])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([m4])
AC_CONFIG_SRCDIR([LICENSE])
AC_PREFIX_DEFAULT([/usr/local/modsecurity])
AC_CONFIG_HEADERS(modsec-sdbm-util-config.h)

AM_INIT_AUTOMAKE([-Wall foreign])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

LT_PREREQ([2.2])
LT_INIT([dlopen])

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_GREP
AC_PATH_PROGS(PERL, [perl perl5], )
AC_PATH_PROGS(ENV_CMD, [env printenv], )

# Checks for header files.
#AC_HEADER_STDC
#AC_CHECK_HEADERS([fcntl.h limits.h stdlib.h string.h unistd.h sys/types.h sys/stat.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_C_RESTRICT
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_STRUCT_TM
AC_TYPE_UINT8_T

CPPFLAGS="$CPPFLAGS -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE"

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_CHECK_FUNCS([atexit getcwd memmove memset strcasecmp strchr strdup strerror strncasecmp strrchr strstr strtol fchmod strcasestr])

# Some directories
MSC_BASE_DIR=`pwd`
MSC_PKGBASE_DIR="$MSC_BASE_DIR/.."

AC_SUBST(MSC_BASE_DIR)
AC_SUBST(MSC_PKGBASE_DIR)

AC_CANONICAL_HOST
CANONICAL_HOST=$host

AH_TEMPLATE([AIX],     [Define if the operating system is AIX])
AH_TEMPLATE([LINUX],   [Define if the operating system is LINUX])
AH_TEMPLATE([OPENBSD], [Define if the operating system is OpenBSD])
AH_TEMPLATE([SOLARIS], [Define if the operating system is SOLARIS])
AH_TEMPLATE([HPUX],    [Define if the operating system is HPUX])
AH_TEMPLATE([MACOSX],  [Define if the operating system is Macintosh OSX])
AH_TEMPLATE([FREEBSD], [Define if the operating system is FREEBSD])
AH_TEMPLATE([NETBSD],  [Define if the operating system is NetBSD])


case $host in
  *-*-aix*)
    echo "Checking plataform... Identified as AIX"
    aixos=true
    ;;
  *-*-hpux*)
    echo "Checking plataform... Identified as HPUX"
    hpuxos=true
    ;;
  *-*-darwin*)
    echo "Checking plataform... Identified as Macintosh OS X"
    macos=true
    ;;
  *-*-linux*)
    echo "Checking plataform... Identified as Linux"
    linuxos=true
        case "${host_cpu}" in
            s390x)
            cpu_type="-DLINUX_S390"
        ;;
        esac
    ;;
  *-*-solaris*)
    echo "Checking plataform... Identified as Solaris"
    solarisos=true
    ;;
  *-*-freebsd*)
    echo "Checking plataform... Identified as FreeBSD"
    freebsdos=true
    ;;
  *-*-netbsd*)
    echo "Checking plataform... Identified as NetBSD"
    netbsdos=true
    ;;
  *-*-openbsd*)
    echo "Checking plataform... Identified as OpenBSD"
    openbsdos=true
    ;;
  *-*-kfreebsd*)
    echo "Checking plataform... Identified as kFreeBSD, treating as linux"
    linuxos=true
    ;;
  *-*-gnu*.*)
    echo "Checking plataform... Identified as HURD, treating as linux"
    linuxos=true
    ;;
       *)
    echo "Unknown CANONICAL_HOST $host"
    exit
    ;;
esac

AM_CONDITIONAL([AIX], [test x$aixos = xtrue])
AM_CONDITIONAL([HPUX], [test x$hpuxos = xtrue])
AM_CONDITIONAL([MACOSX], [test x$macos = xtrue])
AM_CONDITIONAL([LINUX], [test x$linuxos = xtrue])
AM_CONDITIONAL([LINUX390], [test x$linuxos390 = xtrue])
AM_CONDITIONAL([SOLARIS], [test x$solarisos = xtrue])
AM_CONDITIONAL([FREEBSD], [test x$freebsdos = xtrue])
AM_CONDITIONAL([OPENBSD], [test x$openbsdos = xtrue])
AM_CONDITIONAL([NETBSD], [test x$netbsdos = xtrue])

# Verbose output
AC_ARG_ENABLE(verbose-output,
              AS_HELP_STRING([--enable-verbose-output],
                             [Enable more verbose configure output.]),
[
  if test "$enableval" != "no"; then
    verbose_output=1
  else
    verbose_output=0
  fi
],
[
  verbose_output=0
])


CHECK_APR()
CHECK_APU()
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
