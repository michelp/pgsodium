#http://blog.pgxn.org/post/4783001135/extension-makefiles pg makefiles

EXTENSION = pgsodium
PG_CONFIG ?= pg_config
DATA = $(wildcard sql/*--*.sql)
PGXS := $(shell $(PG_CONFIG) --pgxs)
MODULE_big = pgsodium
OBJS = $(patsubst %.c,%.o,$(wildcard src/*.c))
SHLIB_LINK = -lsodium
PG_CPPFLAGS = -O0

# TESTS        = $(wildcard test/*.sql)
# REGRESS      = $(patsubst test/%.sql,%,$(TESTS))
# REGRESS_OPTS = --inputdir=test --load-language=plpgsql
include $(PGXS)

dist:
	git archive --format zip --prefix=$(EXTENSION)-$(DISTVERSION)/ -o $(EXTENSION)-$(DISTVERSION).zip HEAD
