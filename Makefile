#http://blog.pgxn.org/post/4783001135/extension-makefiles pg makefiles
EXTENSION = pgsodium
PG_CONFIG ?= pg_config
DATA = $(wildcard *--*.sql)
PGXS := $(shell $(PG_CONFIG) --pgxs)
MODULE_big = pgsodium
OBJS = $(patsubst %.c,%.o,$(wildcard src/*.c))
#TESTS        = $(wildcard test/sql/*.sql)
#REGRESS      = $(patsubst test/sql/%.sql,%,$(TESTS))
#REGRESS_OPTS = --inputdir=test --load-language=plpgsql
include $(PGXS)

