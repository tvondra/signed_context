MODULE_big = signed_context
OBJS = signed_context.o

EXTENSION = signed_context
DATA = sql/signed_context--1.0.0.sql
MODULES = signed_context

CFLAGS=`pg_config --includedir-server`

TESTS        = $(wildcard test/sql/*.sql)
REGRESS      = $(patsubst test/sql/%.sql,%,$(TESTS))
REGRESS_OPTS = --inputdir=test

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

SHLIB_LINK += -lsodium
