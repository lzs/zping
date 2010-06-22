# Generated automatically from Makefile.in by configure.
# Main Makefile for Mark Galassi's stupid "marklib" library
# Copyright (C) 1996 Mark Galassi.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

VERS = 0.9
SHELL = /bin/sh
top_srcdir = .
srcdir = .

.SUFFIXES:
.SUFFIXES: .c .o

OPT=-g -O

AR = ar
AR_FLAGS = rc
RANLIB = @RANLIB@

CC = gcc
CFLAGS = -I. -g -O2
LDFLAGS = 
LIBS = -lm -lnsl  -lnet
INSTALL = $/usr/bin/install -c
prefix = /usr/local
exec_prefix = ${prefix}
bindir = $(exec_prefix)/bin
libdir = $(prefix)/lib
infodir = $(prefix)/info

# ??? replace these with your own list of files
SOURCES=zping.c
DOCS=
MISC=configure mkinstalldirs install-sh
OBJS=zping.o
LIB_OBJS=

# ??? replace with your targets
all: zping

# ??? here I make the bindir, libdir and infodir directories; you
# might not need all of these.  also, I assumed the names PROG and
# libMYPROG.a for the program and library.
install: all
	$(top_srcdir)/mkinstalldirs $(bindir)
	$(INSTALL) --mode=4755 zping $(bindir)/zping

uninstall:
	/bin/rm -f $(bindir)/zping

zping: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

clean:
	/bin/rm -f core *.o zping $(OBJS) $(LIB_OBJS)

distclean: clean
	/bin/rm -f Makefile config.h config.status config.cache config.log

mostlyclean: clean

maintainer-clean: clean

# a rule to make snapshots
snapshot: $(SOURCES) $(DOCS) $(OTHERFILES)
	@echo
	@echo "->Note: The version for now is hacked into Makefile.in as"
	@echo "->" $(VERS)
	@echo
	@echo "->copying all release files to the directory " zping-$(VERS)
	@echo
	tar cf - $(SOURCES) $(DOCS) $(OTHERFILES) | gzip > zping-$(VERS).tar.gz
	-mkdir zping-$(VERS)
	zcat zping-$(VERS).tar.gz | (cd zping-$(VERS); tar xf -)
	/bin/rm -f zping-$(VERS).tar.gz
	@echo
	@echo "->making the compressed tar file " zping-$(VERS).tar.gz
	@echo
	tar cf - zping-$(VERS) | gzip > zping-$(VERS).tar.gz
	@echo
#	@echo "->placing the snapshot for anonymous ftp in " $(FTPDIR)
#	@echo
#	rcp zping-$(VERS).tar.gz $(FTPDIR)
	echo "->removnig the temporary directory " zping-$(VERS)
	/bin/rm -rf zping-$(VERS)             # remove the old directory


# automatic re-running of configure if the ocnfigure.in file has changed
${srcdir}/configure: configure.in
	cd ${srcdir} && autoconf

# autoheader might not change config.h.in, so touch a stamp file
${srcdir}/config.h.in: stamp-h.in
${srcdir}/stamp-h.in: configure.in
		cd ${srcdir} && autoheader
		echo timestamp > ${srcdir}/stamp-h.in

config.h: stamp-h
stamp-h: config.h.in config.status
	./config.status
Makefile: Makefile.in config.status
	./config.status
config.status: configure
	./config.status --recheck


