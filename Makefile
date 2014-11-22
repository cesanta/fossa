# Copyright (c) 2014 Cesanta Software
# All rights reserved

# Note: order is important
SUBDIRS = modules docs test examples

.PHONY: all $(SUBDIRS)

all: $(SUBDIRS)

$(SUBDIRS): %:
	@$(MAKE) -C $@

# full test suite, requiring more dependencies on the dev's machine
alltests: all
	@$(MAKE) -C test docker valgrind cpplint

difftest:
	@TMP=`mktemp -t checkout-diff.XXXXXX`; \
	git diff docs/index.html fossa.c fossa.h >$$TMP ; \
	if [ -s "$$TMP" ]; then echo found diffs in checkout:; git status -s;  exit 1; fi; \
	rm $$TMP

update-frozen:
	git subtree pull --prefix deps/frozen https://github.com/cesanta/frozen master --squash

setup-hooks:
	for i in .hooks/*; do ln -s ../../.hooks/$$(basename $$i) .git/hooks; done
