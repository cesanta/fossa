# Copyright (c) 2014 Cesanta Software
# All rights reserved

# Note: order is important
SUBDIRS = modules docs test examples

.PHONY: all $(SUBDIRS)

all: $(SUBDIRS)

$(SUBDIRS): %:
	@$(MAKE) -C $@

difftest:
	@TMP=`mktemp -t checkout-diff.XXXXXX`; \
	git diff docs/index.html fossa.c fossa.h >$$TMP ; \
	if [ -s "$$TMP" ]; then echo found diffs in checkout:; git status -s;  exit 1; fi; \
	rm $$TMP
