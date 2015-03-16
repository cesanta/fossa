# Copyright (c) 2014 Cesanta Software
# All rights reserved

# Note: order is important
SUBDIRS = src docs test examples apps

CLANG_FORMAT:=clang-format

ifneq ("$(wildcard /usr/local/bin/clang-3.6)","")
	CLANG:=/usr/local/bin/clang-3.6
	CLANG_FORMAT:=/usr/local/bin/clang-format-3.6
endif

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

clean:
	@for i in $(SUBDIRS); do $(MAKE) -C $$i clean ; done

format:
	@/usr/bin/find src -name "*.[ch]" | grep -v sha1.c | grep -v md5.c | xargs $(CLANG_FORMAT) -i
	@$(CLANG_FORMAT) -i test/unit_test.c
