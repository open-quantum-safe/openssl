#
# crypto/oqs/Makefile
#

DIR=	oqs
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g -Wall
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=oqstest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=	oqs.c

LIBOBJ=	oqs.o

SRC= $(LIBSRC)

EXHEADER= oqs.h
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o */*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

oqs.o: ../../crypto/asn1/asn1_locl.h ../../crypto/evp/evp_locl.h
oqs.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
oqs.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
oqs.o: ../../include/openssl/cms.h ../../include/openssl/comp.h
oqs.o: ../../include/openssl/crypto.h ../../include/openssl/dtls1.h
oqs.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
oqs.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
oqs.o: ../../include/openssl/err.h ../../include/openssl/evp.h
oqs.o: ../../include/openssl/hmac.h ../../include/openssl/kssl.h
oqs.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
oqs.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
oqs.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
oqs.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
oqs.o: ../../include/openssl/pkcs7.h ../../include/openssl/pqueue.h
oqs.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
oqs.o: ../../include/openssl/srtp.h ../../include/openssl/ssl.h
oqs.o: ../../include/openssl/ssl2.h ../../include/openssl/ssl23.h
oqs.o: ../../include/openssl/ssl3.h ../../include/openssl/stack.h
oqs.o: ../../include/openssl/symhacks.h ../../include/openssl/tls1.h
oqs.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
oqs.o: ../../include/oqs/common.h ../../include/oqs/kex.h
oqs.o: ../../include/oqs/rand.h ../../include/oqs/sig.h oqs.c oqs.h
