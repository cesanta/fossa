# Copyright (c) 2014 Cesanta Software
# All rights reserved

SUBDIRS = test examples apps

.PHONY: $(SUBDIRS)

all: $(SUBDIRS)

$(SUBDIRS): %:
	@$(MAKE) -C $@
