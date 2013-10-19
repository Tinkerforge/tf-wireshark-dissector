# Makefile.in generated by automake 1.11.6 from Makefile.am.
# plugins/protoTF/Makefile.  Generated from Makefile.in by configure.

# Copyright (C) 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001, 2002,
# 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011 Free Software
# Foundation, Inc.
# This Makefile.in is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.



# Makefile.am
# Automake file for protoTF plugin
# By Steve Limkemann <stevelim@dgtech.com>
# Copyright 1998 Steve Limkemann
#
# $Id: Makefile.am 48261 2013-03-12 06:53:39Z jake $
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

# Makefile.am.inc
# Include file for Makefile.am files to get additional rules
#
# $Id: Makefile.am.inc 47879 2013-02-25 18:12:20Z rbalint $
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

# Makefile.common for protoTF plugin
#     Contains the stuff from Makefile.am and Makefile.nmake that is
#     a) common to both files and
#     b) portable between both files
#
# $Id: Makefile.common 47579 2013-02-09 05:31:15Z guy $
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#
# Common definitions for plugin Makefile.common files
#
# $Id$
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#
# Source files are divided up along several axes:
#
# C vs. C++ - this is used on Windows to generated lists of object files
# with .c=.obj or .cpp=.obj
#
# Register vs. non-register - register files are scanned for registration
# functions, non-register files aren't.
#
# Flex-generated, Lemon-generated, and non-generated:
#
#	we distribute non-generated files, as they're part of the source,
#	and distribute Flex-generated files, as we don't require that
#	people have Flex installed and don't distribute it ourself and
#	thus can't guarantee that we can run Flex in the build process,
#	but we don't distribute Lemon-generated files, as we distribute
#	Lemon and can run it in the build process;
#
#	"make maintainer-clean" on UN*X and "nmake maintainer-clean" on
#	Windows remove all generated files;
#
#	"make distclean" on UN*X removes Lemon-generated files, as they're
#	not in the distribution, but not Flex-generated files, as they
#	are in the distribution;
#
#	"make distclean" on Windows removes both Lemon-generated and
#	Flex-generated files, as the Flex-generated files in the
#	distribution were generated by Flex on UN*X, and won't compile
#	on Windows;
#
#	Flex-generated files can't be built with full warnings
#	turned on, and can't be run through the checkAPI scripts,
#	as they generate code that won't pass (we've tweaked
#	Lemon to generate code that will pass).
#


am__make_dryrun = \
  { \
    am__dry=no; \
    case $$MAKEFLAGS in \
      *\\[\ \	]*) \
        echo 'am--echo: ; @echo "AM"  OK' | $(MAKE) -f - 2>/dev/null \
          | grep '^AM OK$$' >/dev/null || am__dry=yes;; \
      *) \
        for am__flg in $$MAKEFLAGS; do \
          case $$am__flg in \
            *=*|--*) ;; \
            *n*) am__dry=yes; break;; \
          esac; \
        done;; \
    esac; \
    test $$am__dry = yes; \
  }
pkgdatadir = $(datadir)/wireshark
pkgincludedir = $(includedir)/wireshark
pkglibdir = $(libdir)/wireshark
pkglibexecdir = $(libexecdir)/wireshark
am__cd = CDPATH="$${ZSH_VERSION+.}$(PATH_SEPARATOR)" && cd
install_sh_DATA = $(install_sh) -c -m 644
install_sh_PROGRAM = $(install_sh) -c
install_sh_SCRIPT = $(install_sh) -c
INSTALL_HEADER = $(INSTALL_DATA)
transform = $(program_transform_name)
NORMAL_INSTALL = :
PRE_INSTALL = :
POST_INSTALL = :
NORMAL_UNINSTALL = :
PRE_UNINSTALL = :
POST_UNINSTALL = :
build_triplet = i686-pc-linux-gnu
host_triplet = i686-pc-linux-gnu
target_triplet = i686-pc-linux-gnu
DIST_COMMON = README $(srcdir)/../Makefile.common.inc \
	$(srcdir)/Makefile.am $(srcdir)/Makefile.common \
	$(srcdir)/Makefile.in $(top_srcdir)/Makefile.am.inc AUTHORS \
	COPYING ChangeLog INSTALL NEWS
subdir = plugins/protoTF
ACLOCAL_M4 = $(top_srcdir)/aclocal.m4
am__aclocal_m4_deps = $(top_srcdir)/aclocal-fallback/glib-2.0.m4 \
	$(top_srcdir)/aclocal-fallback/gtk-2.0.m4 \
	$(top_srcdir)/aclocal-fallback/gtk-3.0.m4 \
	$(top_srcdir)/aclocal-fallback/libgcrypt.m4 \
	$(top_srcdir)/aclocal-fallback/libsmi.m4 \
	$(top_srcdir)/aclocal-fallback/qt.m4 \
	$(top_srcdir)/acinclude.m4 $(top_srcdir)/configure.ac
am__configure_deps = $(am__aclocal_m4_deps) $(CONFIGURE_DEPENDENCIES) \
	$(ACLOCAL_M4)
mkinstalldirs = $(install_sh) -d
CONFIG_HEADER = $(top_builddir)/config.h
CONFIG_CLEAN_FILES =
CONFIG_CLEAN_VPATH_FILES =
am__vpath_adj_setup = srcdirstrip=`echo "$(srcdir)" | sed 's|.|.|g'`;
am__vpath_adj = case $$p in \
    $(srcdir)/*) f=`echo "$$p" | sed "s|^$$srcdirstrip/||"`;; \
    *) f=$$p;; \
  esac;
am__strip_dir = f=`echo $$p | sed -e 's|^.*/||'`;
am__install_max = 40
am__nobase_strip_setup = \
  srcdirstrip=`echo "$(srcdir)" | sed 's/[].[^$$\\*|]/\\\\&/g'`
am__nobase_strip = \
  for p in $$list; do echo "$$p"; done | sed -e "s|$$srcdirstrip/||"
am__nobase_list = $(am__nobase_strip_setup); \
  for p in $$list; do echo "$$p $$p"; done | \
  sed "s| $$srcdirstrip/| |;"' / .*\//!s/ .*/ ./; s,\( .*\)/[^/]*$$,\1,' | \
  $(AWK) 'BEGIN { files["."] = "" } { files[$$2] = files[$$2] " " $$1; \
    if (++n[$$2] == $(am__install_max)) \
      { print $$2, files[$$2]; n[$$2] = 0; files[$$2] = "" } } \
    END { for (dir in files) print dir, files[dir] }'
am__base_list = \
  sed '$$!N;$$!N;$$!N;$$!N;$$!N;$$!N;$$!N;s/\n/ /g' | \
  sed '$$!N;$$!N;$$!N;$$!N;s/\n/ /g'
am__uninstall_files_from_dir = { \
  test -z "$$files" \
    || { test ! -d "$$dir" && test ! -f "$$dir" && test ! -r "$$dir"; } \
    || { echo " ( cd '$$dir' && rm -f" $$files ")"; \
         $(am__cd) "$$dir" && rm -f $$files; }; \
  }
am__installdirs = "$(DESTDIR)$(plugindir)"
LTLIBRARIES = $(plugin_LTLIBRARIES)
protoTF_la_DEPENDENCIES =
am__objects_1 = packet-protoTF.lo
am__objects_2 = $(am__objects_1)
am__objects_3 = $(am__objects_2)
am__objects_4 =
am__objects_5 = $(am__objects_4)
am_protoTF_la_OBJECTS = plugin.lo $(am__objects_3) $(am__objects_5)
protoTF_la_OBJECTS = $(am_protoTF_la_OBJECTS)
AM_V_lt = $(am__v_lt_$(V))
am__v_lt_ = $(am__v_lt_$(AM_DEFAULT_VERBOSITY))
am__v_lt_0 = --silent
protoTF_la_LINK = $(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
	$(LIBTOOLFLAGS) --mode=link $(CCLD) $(AM_CFLAGS) $(CFLAGS) \
	$(protoTF_la_LDFLAGS) $(LDFLAGS) -o $@
DEFAULT_INCLUDES = -I. -I$(top_builddir)
depcomp = $(SHELL) $(top_srcdir)/depcomp
am__depfiles_maybe = depfiles
am__mv = mv -f
COMPILE = $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	$(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)
LTCOMPILE = $(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
	$(LIBTOOLFLAGS) --mode=compile $(CC) $(DEFS) \
	$(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) \
	$(AM_CFLAGS) $(CFLAGS)
AM_V_CC = $(am__v_CC_$(V))
am__v_CC_ = $(am__v_CC_$(AM_DEFAULT_VERBOSITY))
am__v_CC_0 = @echo "  CC    " $@;
AM_V_at = $(am__v_at_$(V))
am__v_at_ = $(am__v_at_$(AM_DEFAULT_VERBOSITY))
am__v_at_0 = @
CCLD = $(CC)
LINK = $(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
	$(LIBTOOLFLAGS) --mode=link $(CCLD) $(AM_CFLAGS) $(CFLAGS) \
	$(AM_LDFLAGS) $(LDFLAGS) -o $@
AM_V_CCLD = $(am__v_CCLD_$(V))
am__v_CCLD_ = $(am__v_CCLD_$(AM_DEFAULT_VERBOSITY))
am__v_CCLD_0 = @echo "  CCLD  " $@;
AM_V_GEN = $(am__v_GEN_$(V))
am__v_GEN_ = $(am__v_GEN_$(AM_DEFAULT_VERBOSITY))
am__v_GEN_0 = @echo "  GEN   " $@;
SOURCES = $(protoTF_la_SOURCES)
DIST_SOURCES = $(protoTF_la_SOURCES)
am__can_run_installinfo = \
  case $$AM_UPDATE_INFO_DIR in \
    n|no|NO) false;; \
    *) (install-info --version) >/dev/null 2>&1;; \
  esac
ETAGS = etags
CTAGS = ctags
DISTFILES = $(DIST_COMMON) $(DIST_SOURCES) $(TEXINFOS) $(EXTRA_DIST)
A2X = 
ACLOCAL = ${SHELL} /home/ishraq/wireshark-1.10.2/missing --run aclocal-1.11
AC_MIN_VERSION = 2.60
ADNS_LIBS = 
AMTAR = $${TAR-tar}
AM_DEFAULT_VERBOSITY = 0
APPLICATIONSERVICES_FRAMEWORKS = 
AR = ar
AUTOCONF = ${SHELL} /home/ishraq/wireshark-1.10.2/missing --run autoconf
AUTOHEADER = ${SHELL} /home/ishraq/wireshark-1.10.2/missing --run autoheader
AUTOMAKE = ${SHELL} /home/ishraq/wireshark-1.10.2/missing --run automake-1.11
AWK = gawk
CC = gcc
CCDEPMODE = depmode=gcc3
CC_FOR_BUILD = gcc
CFLAGS = -g -O2 -Wall -W -Wextra -Wdeclaration-after-statement -Wendif-labels -Wpointer-arith -Wno-pointer-sign -Warray-bounds -Wcast-align -Wformat-security -Wold-style-definition -Wstrict-prototypes -Wjump-misses-init -Wvla -Waddress -Warray-bounds -Wattributes -Wdiv-by-zero -Wignored-qualifiers -Wpragmas -Wno-overlength-strings -Wwrite-strings -Wno-long-long -Wc++-compat -Wshadow -Wlogical-op -fexcess-precision=fast -fvisibility=hidden -pthread -I/usr/include/gtk-2.0 -I/usr/lib/i386-linux-gnu/gtk-2.0/include -I/usr/include/atk-1.0 -I/usr/include/cairo -I/usr/include/gdk-pixbuf-2.0 -I/usr/include/pango-1.0 -I/usr/include/gio-unix-2.0/ -I/usr/include/glib-2.0 -I/usr/lib/i386-linux-gnu/glib-2.0/include -I/usr/include/pixman-1 -I/usr/include/freetype2 -I/usr/include/libpng12 -I/usr/include/harfbuzz  
CFLAGS_FOR_BUILD =  -Wall -W -Wextra -Wdeclaration-after-statement -Wendif-labels -Wpointer-arith -Wno-pointer-sign -Warray-bounds -Wcast-align -Wformat-security -Wold-style-definition -Wstrict-prototypes -Wjump-misses-init -Wvla -Waddress -Warray-bounds -Wattributes -Wdiv-by-zero -Wignored-qualifiers -Wpragmas -Wno-overlength-strings -Wwrite-strings -Wno-long-long -Wc++-compat -Wshadow -Wlogical-op -fexcess-precision=fast -fvisibility=hidden -fPIE
COREFOUNDATION_FRAMEWORKS = 
CPP = gcc -E
CPPFLAGS = -DINET6 -DG_DISABLE_DEPRECATED -DG_DISABLE_SINGLE_INCLUDES -DGSEAL_ENABLE -DGTK_DISABLE_SINGLE_INCLUDES -DGTK_DISABLE_DEPRECATED -DGDK_DISABLE_DEPRECATED -DGDK_PIXBUF_DISABLE_DEPRECATED  -D_FORTIFY_SOURCE=2 -I/usr/local/include -I/usr/include '-DPLUGIN_DIR="$(plugindir)"'
CXX = g++
CXXCPP = g++ -E
CXXDEPMODE = depmode=gcc3
CXXFLAGS = -g -O2 -Wall -W -Wextra -Wendif-labels -Wpointer-arith -Warray-bounds -Wcast-align -Wformat-security -Wvla -Waddress -Warray-bounds -Wattributes -Wdiv-by-zero -Wignored-qualifiers -Wpragmas -Wno-overlength-strings -Wwrite-strings -Wno-long-long -fexcess-precision=fast -fvisibility=hidden -pthread -I/usr/include/gtk-2.0 -I/usr/lib/i386-linux-gnu/gtk-2.0/include -I/usr/include/atk-1.0 -I/usr/include/cairo -I/usr/include/gdk-pixbuf-2.0 -I/usr/include/pango-1.0 -I/usr/include/gio-unix-2.0/ -I/usr/include/glib-2.0 -I/usr/lib/i386-linux-gnu/glib-2.0/include -I/usr/include/pixman-1 -I/usr/include/freetype2 -I/usr/include/libpng12 -I/usr/include/harfbuzz  
CYGPATH_W = echo
C_ARES_LIBS = 
DEFS = -DHAVE_CONFIG_H
DEPDIR = .deps
DESKTOP_FILE_INSTALL = /usr/bin/desktop-file-install
DLLTOOL = false
DOXYGEN = /usr/bin/doxygen
DSYMUTIL = 
DUMPBIN = 
DUMPCAP_GROUP = 
ECHO_C = 
ECHO_N = -n
ECHO_T = 
EGREP = /bin/grep -E
ELINKS = 
ENABLE_STATIC = 
EXEEXT = 
FGREP = /bin/grep -F
FOP = 
GEOIP_LIBS = 
GETOPT_LO = 
GLIB_CFLAGS = -pthread -I/usr/include/glib-2.0 -I/usr/lib/i386-linux-gnu/glib-2.0/include  
GLIB_GENMARSHAL = glib-genmarshal
GLIB_LIBS = -pthread -Wl,--export-dynamic -lgthread-2.0 -lgmodule-2.0 -lglib-2.0  
GLIB_MIN_VERSION = 2.14.0
GLIB_MKENUMS = glib-mkenums
GOBJECT_QUERY = gobject-query
GREP = /bin/grep
GTK2_MIN_VERSION = 2.12.0
GTK3_MIN_VERSION = 3.0.0
GTK_CFLAGS = -pthread -I/usr/include/gtk-2.0 -I/usr/lib/i386-linux-gnu/gtk-2.0/include -I/usr/include/atk-1.0 -I/usr/include/cairo -I/usr/include/gdk-pixbuf-2.0 -I/usr/include/pango-1.0 -I/usr/include/gio-unix-2.0/ -I/usr/include/glib-2.0 -I/usr/lib/i386-linux-gnu/glib-2.0/include -I/usr/include/pixman-1 -I/usr/include/freetype2 -I/usr/include/libpng12 -I/usr/include/harfbuzz  
GTK_LIBS = -lgtk-x11-2.0 -lgdk-x11-2.0 -latk-1.0 -lgio-2.0 -lpangoft2-1.0 -lpangocairo-1.0 -lgdk_pixbuf-2.0 -lcairo -lpango-1.0 -lfreetype -lfontconfig -lgobject-2.0 -lglib-2.0  
HAVE_A2X = no
HAVE_BLESS = yes
HAVE_DOXYGEN = yes
HAVE_DPKG_BUILDPACKAGE = yes
HAVE_ELINKS = no
HAVE_FOP = no
HAVE_HDIUTIL = no
HAVE_LYNX = no
HAVE_OSX_PACKAGING = no
HAVE_PKGMK = no
HAVE_PKGPROTO = no
HAVE_PKGTRANS = no
HAVE_RPM = 
HAVE_SVR4_PACKAGING = no
HAVE_W3M = no
HAVE_XCODEBUILD = no
HAVE_XMLLINT = yes
HAVE_XSLTPROC = no
HTML_VIEWER = /usr/bin/xdg-open
INET_ATON_LO = 
INET_NTOP_LO = 
INET_PTON_LO = 
INSTALL = /usr/bin/install -c
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_PROGRAM = ${INSTALL}
INSTALL_SCRIPT = ${INSTALL}
INSTALL_STRIP_PROGRAM = $(install_sh) -c -s
KRB5_CONFIG = 
KRB5_LIBS = 
LD = /usr/bin/ld
LDFLAGS =  -Wl,--as-needed -L/usr/local/lib -L/usr/local/lib -L/usr/local/lib -L/usr/local/lib -L/usr/local/lib
LDFLAGS_SHAREDLIB = 
LEX = /usr/bin/flex
LEXLIB = -lfl
LEX_OUTPUT_ROOT = lex.yy
LIBCAP_LIBS = 
LIBGCRYPT_CFLAGS = 
LIBGCRYPT_CONFIG = no
LIBGCRYPT_LIBS = 
LIBGNUTLS_CFLAGS = 
LIBGNUTLS_LIBS = 
LIBNL1_CFLAGS = 
LIBNL1_LIBS = 
LIBNL2_CFLAGS = 
LIBNL2_LIBS = 
LIBNL3_CFLAGS = 
LIBNL3_LIBS = 
LIBOBJS = 

# Libs must be cleared, or else libtool won't create a shared module.
# If your module needs to be linked against any particular libraries,
# add them here.
LIBS = 
LIBSMI_CFLAGS = 
LIBSMI_LDFLAGS = 
LIBSMI_VERSION = 
LIBTOOL = $(SHELL) $(top_builddir)/libtool
LIBTOOL_DEPS = ./ltmain.sh
LIPO = 
LN_S = ln -s
LTLIBOBJS = 
LUA_INCLUDES = 
LUA_LIBS = 
LYNX = 
MAKEINFO = ${SHELL} /home/ishraq/wireshark-1.10.2/missing --run makeinfo
MANIFEST_TOOL = :
MKDIR_P = /bin/mkdir -p
MOC = /usr/bin/moc
NM = /usr/bin/nm -B
NMEDIT = 
NSL_LIBS = 
OBJDUMP = objdump
OBJEXT = o
OSX_APP_FLAGS = 
OSX_MIN_VERSION = 
OTOOL = 
OTOOL64 = 
PACKAGE = wireshark
PACKAGE_BUGREPORT = http://bugs.wireshark.org/
PACKAGE_NAME = wireshark
PACKAGE_STRING = wireshark 1.10.2
PACKAGE_TARNAME = wireshark
PACKAGE_URL = http://www.wireshark.org/
PACKAGE_VERSION = 1.10.2
PATH_SEPARATOR = :
PCAP_CONFIG = /usr/bin/pcap-config
PCAP_LIBS = -L/usr/lib/i386-linux-gnu  -lpcap
PERL = /usr/bin/perl
PIE_CFLAGS = -fPIE
PIE_LDFLAGS = -pie
PKG_CONFIG = /usr/bin/pkg-config
PKG_CONFIG_LIBDIR = 
PKG_CONFIG_PATH = 
PLUGIN_LIBS = 
POD2HTML = /usr/bin/pod2html
POD2MAN = /usr/bin/pod2man
PORTAUDIO_INCLUDES = 
PORTAUDIO_LIBS = 
PYTHON = /usr/bin/python
PY_CFLAGS = 
PY_LIBS = 
QT_MIN_VERSION = 4.6.0
Qt_LIBS = 
RANLIB = ranlib
SED = /bin/sed
SETCAP = /sbin/setcap
SET_MAKE = 
SHELL = /bin/bash
SOCKET_LIBS = 
SSL_LIBS = 
STRIP = strip
STRNCASECMP_LO = 
STRPTIME_C = 
STRPTIME_LO = 
SYSTEMCONFIGURATION_FRAMEWORKS = 
UIC = /usr/bin/uic
VERSION = 1.10.2
W3M = 
XMLLINT = /usr/bin/xmllint
XSLTPROC = 
YACC = bison -y
YACCDUMMY = /usr/bin/bison
YFLAGS = 
abs_builddir = /home/ishraq/wireshark-1.10.2/plugins/protoTF
abs_srcdir = /home/ishraq/wireshark-1.10.2/plugins/protoTF
abs_top_builddir = /home/ishraq/wireshark-1.10.2
abs_top_srcdir = /home/ishraq/wireshark-1.10.2
ac_ct_AR = ar
ac_ct_CC = gcc
ac_ct_CXX = g++
ac_ct_DUMPBIN = 
ac_cv_wireshark_have_rpm = no
am__include = include
am__leading_dot = .
am__quote = 
am__tar = tar --format=ustar -chf - "$$tardir"
am__untar = tar -xf -
bindir = ${exec_prefix}/bin
build = i686-pc-linux-gnu
build_alias = 
build_cpu = i686
build_os = linux-gnu
build_vendor = pc
builddir = .
capinfos_bin = capinfos$(EXEEXT)
capinfos_man = capinfos.1
datadir = ${datarootdir}
datarootdir = ${prefix}/share
dftest_bin = dftest$(EXEEXT)
dftest_man = dftest.1
docdir = /usr/local/share/doc/wireshark
dumpcap_bin = dumpcap$(EXEEXT)
dumpcap_man = dumpcap.1
dvidir = ${docdir}
editcap_bin = editcap$(EXEEXT)
editcap_man = editcap.1
exec_prefix = ${prefix}
host = i686-pc-linux-gnu
host_alias = 
host_cpu = i686
host_os = linux-gnu
host_vendor = pc
htmldir = ${docdir}
includedir = ${prefix}/include
infodir = ${datarootdir}/info
install_sh = ${SHELL} /home/ishraq/wireshark-1.10.2/install-sh
libdir = ${exec_prefix}/lib
libexecdir = ${exec_prefix}/libexec
localedir = ${datarootdir}/locale
localstatedir = ${prefix}/var
mandir = ${datarootdir}/man
mergecap_bin = mergecap$(EXEEXT)
mergecap_man = mergecap.1
mkdir_p = /bin/mkdir -p
oldincludedir = /usr/include
pdfdir = ${docdir}
plugindir = ${libdir}/wireshark/plugins/${VERSION}
prefix = /usr/local
program_transform_name = s,x,x,
psdir = ${docdir}
pythondir = 
randpkt_bin = randpkt$(EXEEXT)
randpkt_man = randpkt.1
rawshark_bin = rawshark$(EXEEXT)
rawshark_man = rawshark.1
reordercap_bin = reordercap$(EXEEXT)
reordercap_man = reordercap.1
sbindir = ${exec_prefix}/sbin
sharedstatedir = ${prefix}/com
srcdir = .
sysconfdir = ${prefix}/etc
target = i686-pc-linux-gnu
target_alias = 
target_cpu = i686
target_os = linux-gnu
target_vendor = pc
text2pcap_bin = text2pcap$(EXEEXT)
text2pcap_man = text2pcap.1
top_build_prefix = ../../
top_builddir = ../..
top_srcdir = ../..
tshark_bin = tshark$(EXEEXT)
tshark_man = tshark.1
wireshark_SUBDIRS = codecs ui/gtk
wireshark_bin = wireshark$(EXEEXT)
wireshark_man = wireshark.1
wiresharkfilter_man = wireshark-filter.4
AUTOMAKE_OPTIONS = -Wno-portability
AM_V_AWK = $(am__v_AWK_$(V))
am__v_AWK_ = $(am__v_AWK_$(AM_DEFAULT_VERBOSITY))
am__v_AWK_0 = @echo "  AWK     " $@;
AM_V_LEMON = $(am__v_LEMON_$(V))
am__v_LEMON_ = $(am__v_LEMON_$(AM_DEFAULT_VERBOSITY))
am__v_LEMON_0 = @echo "  LEMON   " $@;
AM_V_RUNLEX = $(am__v_RUNLEX_$(V))
am__v_RUNLEX_ = $(am__v_RUNLEX_$(AM_DEFAULT_VERBOSITY))
am__v_RUNLEX_0 = @echo "  RUNLEX  " $@;
AM_V_SED = $(am__v_SED_$(V))
am__v_SED_ = $(am__v_SED_$(AM_DEFAULT_VERBOSITY))
am__v_SED_0 = @echo "  SED     " $@;

# abi-compliance-checker descriptor
INCLUDE_DIRS = $(subst -I,NEWLINE,$(filter -I%, $(CFLAGS) -I$(abs_top_srcdir) -I$(abs_srcdir)))
AM_CPPFLAGS = -I$(top_srcdir)

# the name of the plugin
PLUGIN_NAME = protoTF

# Non-generated sources to be scanned for registration routines
NONGENERATED_REGISTER_C_FILES = \
	packet-protoTF.c


# Non-generated sources
NONGENERATED_C_FILES = \
	$(NONGENERATED_REGISTER_C_FILES)


# Headers.
CLEAN_HEADER_FILES = \

HEADER_FILES = \
	$(CLEAN_HEADER_FILES)


#
# All source files to be scanned for registration routines.
#
REGISTER_SRC_FILES = \
	$(FLEX_GENERATED_REGISTER_C_FILES) \
	$(FLEX_GENERATED_REGISTER_CPP_FILES) \
	$(LEMON_GENERATED_REGISTER_C_FILES) \
	$(LEMON_GENERATED_REGISTER_CPP_FILES) \
	$(NONGENERATED_REGISTER_C_FILES) \
	$(NONGENERATED_REGISTER_CPP_FILES)


#
# All distributed source files.
#
SRC_FILES = \
	$(FLEX_GENERATED_C_FILES) \
	$(FLEX_GENERATED_CPP_FILES) \
	$(NONGENERATED_C_FILES) \
	$(NONGENERATED_CPP_FILES)


#
# All non-distributed source files.
#
NODIST_SRC_FILES = \
	$(LEMON_GENERATED_C_FILES) \
	$(LEMON_GENERATED_CPP_FILES)


#
# All non-distributed header files.
#
NODIST_HEADER_FILES = \
	$(LEMON_GENERATED_HEADER_FILES)


#
# All Flex-generated source files.
#
FLEX_GENERATED_SRC_FILES = \
	$(FLEX_GENERATED_C_FILES) \
	$(FLEX_GENERATED_CPP_FILES)


#
# All Lemon-generated source files.
#
LEMON_GENERATED_SRC_FILES = \
	$(LEMON_GENERATED_C_FILES) \
	$(LEMON_GENERATED_CPP_FILES)


#
# All generated source files.
#
GENERATED_SRC_FILES = \
	$(FLEX_GENERATED_SRC_FILES) \
	$(LEMON_GENERATED_SRC_FILES)


#
# All generated header files.
#
GENERATED_HEADER_FILES = \
	$(FLEX_GENERATED_HEADER_FILES) \
	$(LEMON_GENERATED_HEADER_FILES) 


#
# All "clean" source files; they can be compiled with the regular
# warning options, including -Werror with GCC-compatible compilers,
# and can be run through checkAPI.  Neither Flex-generated nor
# Lemon-generated files can currently be guaranteed to be clean.
#
CLEAN_SRC_FILES = \
	$(NONGENERATED_C_FILES) \
	$(NONGENERATED_CPP_FILES)


# C source files
C_FILES = \
	$(FLEX_GENERATED_C_FILES) \
	$(LEMON_GENERATED_C_FILES) \
	$(NONGENERATED_C_FILES)


# C++ source files
CPP_FILES = \
	$(FLEX_GENERATED_CPP_FILES) \
	$(LEMON_GENERATED_CPP_FILES) \
	$(NONGENERATED_CPP_FILES)

#AM_CFLAGS = -Werror
plugin_LTLIBRARIES = protoTF.la
protoTF_la_SOURCES = \
	plugin.c \
	moduleinfo.h \
	$(SRC_FILES)	\
	$(HEADER_FILES)

protoTF_la_LDFLAGS = -module -avoid-version
protoTF_la_LIBADD = 

#
# Currently plugin.c can be included in the distribution because
# we always build all protocol dissectors. We used to have to check
# whether or not to build the snmp dissector. If we again need to
# variably build something, making plugin.c non-portable, uncomment
# the dist-hook line below.
#
# Oh, yuk.  We don't want to include "plugin.c" in the distribution, as
# its contents depend on the configuration, and therefore we want it
# to be built when the first "make" is done; however, Automake insists
# on putting *all* source into the distribution.
#
# We work around this by having a "dist-hook" rule that deletes
# "plugin.c", so that "dist" won't pick it up.
#
#dist-hook:
#	@rm -f $(distdir)/plugin.c
CLEANFILES = \
	protoTF \
	*~

MAINTAINERCLEANFILES = \
	Makefile.in	\
	plugin.c

EXTRA_DIST = \
	Makefile.common		\
	Makefile.nmake		\
	moduleinfo.nmake	\
	plugin.rc.in		\
	CMakeLists.txt

all: all-am

.SUFFIXES:
.SUFFIXES: .c .def .l .lo .o .obj .sym
$(srcdir)/Makefile.in:  $(srcdir)/Makefile.am $(top_srcdir)/Makefile.am.inc $(srcdir)/Makefile.common $(srcdir)/../Makefile.common.inc $(am__configure_deps)
	@for dep in $?; do \
	  case '$(am__configure_deps)' in \
	    *$$dep*) \
	      ( cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh ) \
	        && { if test -f $@; then exit 0; else break; fi; }; \
	      exit 1;; \
	  esac; \
	done; \
	echo ' cd $(top_srcdir) && $(AUTOMAKE) --gnu plugins/protoTF/Makefile'; \
	$(am__cd) $(top_srcdir) && \
	  $(AUTOMAKE) --gnu plugins/protoTF/Makefile
.PRECIOUS: Makefile
Makefile: $(srcdir)/Makefile.in $(top_builddir)/config.status
	@case '$?' in \
	  *config.status*) \
	    cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh;; \
	  *) \
	    echo ' cd $(top_builddir) && $(SHELL) ./config.status $(subdir)/$@ $(am__depfiles_maybe)'; \
	    cd $(top_builddir) && $(SHELL) ./config.status $(subdir)/$@ $(am__depfiles_maybe);; \
	esac;
$(top_srcdir)/Makefile.am.inc $(srcdir)/Makefile.common $(srcdir)/../Makefile.common.inc:

$(top_builddir)/config.status: $(top_srcdir)/configure $(CONFIG_STATUS_DEPENDENCIES)
	cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh

$(top_srcdir)/configure:  $(am__configure_deps)
	cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh
$(ACLOCAL_M4):  $(am__aclocal_m4_deps)
	cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh
$(am__aclocal_m4_deps):
install-pluginLTLIBRARIES: $(plugin_LTLIBRARIES)
	@$(NORMAL_INSTALL)
	@list='$(plugin_LTLIBRARIES)'; test -n "$(plugindir)" || list=; \
	list2=; for p in $$list; do \
	  if test -f $$p; then \
	    list2="$$list2 $$p"; \
	  else :; fi; \
	done; \
	test -z "$$list2" || { \
	  echo " $(MKDIR_P) '$(DESTDIR)$(plugindir)'"; \
	  $(MKDIR_P) "$(DESTDIR)$(plugindir)" || exit 1; \
	  echo " $(LIBTOOL) $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=install $(INSTALL) $(INSTALL_STRIP_FLAG) $$list2 '$(DESTDIR)$(plugindir)'"; \
	  $(LIBTOOL) $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=install $(INSTALL) $(INSTALL_STRIP_FLAG) $$list2 "$(DESTDIR)$(plugindir)"; \
	}

uninstall-pluginLTLIBRARIES:
	@$(NORMAL_UNINSTALL)
	@list='$(plugin_LTLIBRARIES)'; test -n "$(plugindir)" || list=; \
	for p in $$list; do \
	  $(am__strip_dir) \
	  echo " $(LIBTOOL) $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=uninstall rm -f '$(DESTDIR)$(plugindir)/$$f'"; \
	  $(LIBTOOL) $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=uninstall rm -f "$(DESTDIR)$(plugindir)/$$f"; \
	done

clean-pluginLTLIBRARIES:
	-test -z "$(plugin_LTLIBRARIES)" || rm -f $(plugin_LTLIBRARIES)
	@list='$(plugin_LTLIBRARIES)'; for p in $$list; do \
	  dir="`echo $$p | sed -e 's|/[^/]*$$||'`"; \
	  test "$$dir" != "$$p" || dir=.; \
	  echo "rm -f \"$${dir}/so_locations\""; \
	  rm -f "$${dir}/so_locations"; \
	done
protoTF.la: $(protoTF_la_OBJECTS) $(protoTF_la_DEPENDENCIES) $(EXTRA_protoTF_la_DEPENDENCIES) 
	$(AM_V_CCLD)$(protoTF_la_LINK) -rpath $(plugindir) $(protoTF_la_OBJECTS) $(protoTF_la_LIBADD) $(LIBS)

mostlyclean-compile:
	-rm -f *.$(OBJEXT)

distclean-compile:
	-rm -f *.tab.c

include ./$(DEPDIR)/packet-protoTF.Plo
include ./$(DEPDIR)/plugin.Plo

.c.o:
	$(AM_V_CC)$(COMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ $<
	$(AM_V_at)$(am__mv) $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Po
#	$(AM_V_CC)source='$<' object='$@' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(COMPILE) -c $<

.c.obj:
	$(AM_V_CC)$(COMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ `$(CYGPATH_W) '$<'`
	$(AM_V_at)$(am__mv) $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Po
#	$(AM_V_CC)source='$<' object='$@' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(COMPILE) -c `$(CYGPATH_W) '$<'`

.c.lo:
	$(AM_V_CC)$(LTCOMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ $<
	$(AM_V_at)$(am__mv) $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Plo
#	$(AM_V_CC)source='$<' object='$@' libtool=yes \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(LTCOMPILE) -c -o $@ $<

mostlyclean-libtool:
	-rm -f *.lo

clean-libtool:
	-rm -rf .libs _libs

ID: $(HEADERS) $(SOURCES) $(LISP) $(TAGS_FILES)
	list='$(SOURCES) $(HEADERS) $(LISP) $(TAGS_FILES)'; \
	unique=`for i in $$list; do \
	    if test -f "$$i"; then echo $$i; else echo $(srcdir)/$$i; fi; \
	  done | \
	  $(AWK) '{ files[$$0] = 1; nonempty = 1; } \
	      END { if (nonempty) { for (i in files) print i; }; }'`; \
	mkid -fID $$unique
tags: TAGS

TAGS:  $(HEADERS) $(SOURCES)  $(TAGS_DEPENDENCIES) \
		$(TAGS_FILES) $(LISP)
	set x; \
	here=`pwd`; \
	list='$(SOURCES) $(HEADERS)  $(LISP) $(TAGS_FILES)'; \
	unique=`for i in $$list; do \
	    if test -f "$$i"; then echo $$i; else echo $(srcdir)/$$i; fi; \
	  done | \
	  $(AWK) '{ files[$$0] = 1; nonempty = 1; } \
	      END { if (nonempty) { for (i in files) print i; }; }'`; \
	shift; \
	if test -z "$(ETAGS_ARGS)$$*$$unique"; then :; else \
	  test -n "$$unique" || unique=$$empty_fix; \
	  if test $$# -gt 0; then \
	    $(ETAGS) $(ETAGSFLAGS) $(AM_ETAGSFLAGS) $(ETAGS_ARGS) \
	      "$$@" $$unique; \
	  else \
	    $(ETAGS) $(ETAGSFLAGS) $(AM_ETAGSFLAGS) $(ETAGS_ARGS) \
	      $$unique; \
	  fi; \
	fi
ctags: CTAGS
CTAGS:  $(HEADERS) $(SOURCES)  $(TAGS_DEPENDENCIES) \
		$(TAGS_FILES) $(LISP)
	list='$(SOURCES) $(HEADERS)  $(LISP) $(TAGS_FILES)'; \
	unique=`for i in $$list; do \
	    if test -f "$$i"; then echo $$i; else echo $(srcdir)/$$i; fi; \
	  done | \
	  $(AWK) '{ files[$$0] = 1; nonempty = 1; } \
	      END { if (nonempty) { for (i in files) print i; }; }'`; \
	test -z "$(CTAGS_ARGS)$$unique" \
	  || $(CTAGS) $(CTAGSFLAGS) $(AM_CTAGSFLAGS) $(CTAGS_ARGS) \
	     $$unique

GTAGS:
	here=`$(am__cd) $(top_builddir) && pwd` \
	  && $(am__cd) $(top_srcdir) \
	  && gtags -i $(GTAGS_ARGS) "$$here"

distclean-tags:
	-rm -f TAGS ID GTAGS GRTAGS GSYMS GPATH tags

distdir: $(DISTFILES)
	@srcdirstrip=`echo "$(srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	topsrcdirstrip=`echo "$(top_srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	list='$(DISTFILES)'; \
	  dist_files=`for file in $$list; do echo $$file; done | \
	  sed -e "s|^$$srcdirstrip/||;t" \
	      -e "s|^$$topsrcdirstrip/|$(top_builddir)/|;t"`; \
	case $$dist_files in \
	  */*) $(MKDIR_P) `echo "$$dist_files" | \
			   sed '/\//!d;s|^|$(distdir)/|;s,/[^/]*$$,,' | \
			   sort -u` ;; \
	esac; \
	for file in $$dist_files; do \
	  if test -f $$file || test -d $$file; then d=.; else d=$(srcdir); fi; \
	  if test -d $$d/$$file; then \
	    dir=`echo "/$$file" | sed -e 's,/[^/]*$$,,'`; \
	    if test -d "$(distdir)/$$file"; then \
	      find "$(distdir)/$$file" -type d ! -perm -700 -exec chmod u+rwx {} \;; \
	    fi; \
	    if test -d $(srcdir)/$$file && test $$d != $(srcdir); then \
	      cp -fpR $(srcdir)/$$file "$(distdir)$$dir" || exit 1; \
	      find "$(distdir)/$$file" -type d ! -perm -700 -exec chmod u+rwx {} \;; \
	    fi; \
	    cp -fpR $$d/$$file "$(distdir)$$dir" || exit 1; \
	  else \
	    test -f "$(distdir)/$$file" \
	    || cp -p $$d/$$file "$(distdir)/$$file" \
	    || exit 1; \
	  fi; \
	done
check-am: all-am
check: check-am
all-am: Makefile $(LTLIBRARIES)
installdirs:
	for dir in "$(DESTDIR)$(plugindir)"; do \
	  test -z "$$dir" || $(MKDIR_P) "$$dir"; \
	done
install: install-am
install-exec: install-exec-am
install-data: install-data-am
uninstall: uninstall-am

install-am: all-am
	@$(MAKE) $(AM_MAKEFLAGS) install-exec-am install-data-am

installcheck: installcheck-am
install-strip:
	if test -z '$(STRIP)'; then \
	  $(MAKE) $(AM_MAKEFLAGS) INSTALL_PROGRAM="$(INSTALL_STRIP_PROGRAM)" \
	    install_sh_PROGRAM="$(INSTALL_STRIP_PROGRAM)" INSTALL_STRIP_FLAG=-s \
	      install; \
	else \
	  $(MAKE) $(AM_MAKEFLAGS) INSTALL_PROGRAM="$(INSTALL_STRIP_PROGRAM)" \
	    install_sh_PROGRAM="$(INSTALL_STRIP_PROGRAM)" INSTALL_STRIP_FLAG=-s \
	    "INSTALL_PROGRAM_ENV=STRIPPROG='$(STRIP)'" install; \
	fi
mostlyclean-generic:

clean-generic:
	-test -z "$(CLEANFILES)" || rm -f $(CLEANFILES)

distclean-generic:
	-test -z "$(CONFIG_CLEAN_FILES)" || rm -f $(CONFIG_CLEAN_FILES)
	-test . = "$(srcdir)" || test -z "$(CONFIG_CLEAN_VPATH_FILES)" || rm -f $(CONFIG_CLEAN_VPATH_FILES)

maintainer-clean-generic:
	@echo "This command is intended for maintainers to use"
	@echo "it deletes files that may require special tools to rebuild."
	-test -z "$(MAINTAINERCLEANFILES)" || rm -f $(MAINTAINERCLEANFILES)
clean: clean-am

clean-am: clean-generic clean-libtool clean-pluginLTLIBRARIES \
	mostlyclean-am

distclean: distclean-am
	-rm -rf ./$(DEPDIR)
	-rm -f Makefile
distclean-am: clean-am distclean-compile distclean-generic \
	distclean-tags

dvi: dvi-am

dvi-am:

html: html-am

html-am:

info: info-am

info-am:

install-data-am: install-pluginLTLIBRARIES

install-dvi: install-dvi-am

install-dvi-am:

install-exec-am:

install-html: install-html-am

install-html-am:

install-info: install-info-am

install-info-am:

install-man:

install-pdf: install-pdf-am

install-pdf-am:

install-ps: install-ps-am

install-ps-am:

installcheck-am:

maintainer-clean: maintainer-clean-am
	-rm -rf ./$(DEPDIR)
	-rm -f Makefile
maintainer-clean-am: distclean-am maintainer-clean-generic

mostlyclean: mostlyclean-am

mostlyclean-am: mostlyclean-compile mostlyclean-generic \
	mostlyclean-libtool

pdf: pdf-am

pdf-am:

ps: ps-am

ps-am:

uninstall-am: uninstall-pluginLTLIBRARIES

.MAKE: install-am install-strip

.PHONY: CTAGS GTAGS all all-am check check-am clean clean-generic \
	clean-libtool clean-pluginLTLIBRARIES ctags distclean \
	distclean-compile distclean-generic distclean-libtool \
	distclean-tags distdir dvi dvi-am html html-am info info-am \
	install install-am install-data install-data-am install-dvi \
	install-dvi-am install-exec install-exec-am install-html \
	install-html-am install-info install-info-am install-man \
	install-pdf install-pdf-am install-pluginLTLIBRARIES \
	install-ps install-ps-am install-strip installcheck \
	installcheck-am installdirs maintainer-clean \
	maintainer-clean-generic mostlyclean mostlyclean-compile \
	mostlyclean-generic mostlyclean-libtool pdf pdf-am ps ps-am \
	tags uninstall uninstall-am uninstall-pluginLTLIBRARIES


.l.c:
	$(AM_V_RUNLEX)$(RUNLEX) "$(LEX)" -o$@ $<

.def.sym:
	$(AM_V_AWK)$(AWK) '/^EXPORTS$$/ {next;}; ${def_sym_filter_symbols} /^[^;]/ { print $$1;}' < $< > $@
abi-descriptor.xml: ../abi-descriptor.template
	$(AM_V_SED)sed "s|@INCLUDE_DIRS@|$(INCLUDE_DIRS)|g;s/NEWLINE/\n    /g;s|@LIBRARY_OUTPUT_PATH@|{RELPATH}/.libs|" $< > $@

#
# Build plugin.c, which contains the plugin version[] string, a
# function plugin_register() that calls the register routines for all
# protocols, and a function plugin_reg_handoff() that calls the handoff
# registration routines for all protocols.
#
# We do this by scanning sources.  If that turns out to be too slow,
# maybe we could just require every .o file to have an register routine
# of a given name (packet-aarp.o -> proto_register_aarp, etc.).
#
# Formatting conventions:  The name of the proto_register_* routines an
# proto_reg_handoff_* routines must start in column zero, or must be
# preceded only by "void " starting in column zero, and must not be
# inside #if.
#
# REGISTER_SRC_FILES is assumed to have all the files that need to be scanned.
#
# For some unknown reason, having a big "for" loop in the Makefile
# to scan all the files doesn't work with some "make"s; they seem to
# pass only the first few names in the list to the shell, for some
# reason.
#
# Therefore, we have a script to generate the plugin.c file.
# The shell script runs slowly, as multiple greps and seds are run
# for each input file; this is especially slow on Windows.  Therefore,
# if Python is present (as indicated by PYTHON being defined), we run
# a faster Python script to do that work instead.
#
# The first argument is the directory in which the source files live.
# The second argument is "plugin", to indicate that we should build
# a plugin.c file for a plugin.
# All subsequent arguments are the files to scan.
#
plugin.c: $(REGISTER_SRC_FILES) Makefile.common $(top_srcdir)/tools/make-dissector-reg \
    $(top_srcdir)/tools/make-dissector-reg.py
	@if test -n "$(PYTHON)"; then \
		echo Making plugin.c with python ; \
		$(PYTHON) $(top_srcdir)/tools/make-dissector-reg.py $(srcdir) \
		    plugin $(REGISTER_SRC_FILES) ; \
	else \
		echo Making plugin.c with shell script ; \
		$(top_srcdir)/tools/make-dissector-reg $(srcdir) \
		    $(plugin_src) plugin $(REGISTER_SRC_FILES) ; \
	fi

checkapi:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g abort -g termoutput -build \
		$(CLEAN_SRC_FILES) $(CLEAN_HEADER_FILES)

# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
