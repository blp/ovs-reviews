EXTRA_DIST += \
	build-aux/calculate-schema-cksum \
	build-aux/cccl \
	build-aux/cksum-schema-check \
	build-aux/dist-docs \
	build-aux/sodepends.pl \
	build-aux/soexpand.pl \
	build-aux/text2c \
	build-aux/xml2nroff

FLAKE8_PYFILES += \
    $(srcdir)/build-aux/xml2nroff
