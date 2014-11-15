# Copyright (c) 2014 Cesanta Software
# All rights reserved

# Note: order is important
all:
	$(MAKE) -C modules
	$(MAKE) -C docs
	$(MAKE) -C test
	$(MAKE) -C examples

difftest:
	@TMP=`mktemp -t checkout-diff.XXXXXX`; \
	git diff docs/index.html fossa.c fossa.h >$$TMP ; \
	if [ -s "$$TMP" ]; then echo found diffs in checkout:; git status -s;  exit 1; fi; \
	rm $$TMP
