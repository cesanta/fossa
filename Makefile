# Copyright (c) 2014 Cesanta Software
# All rights reserved

# Note: order is important
all:
	$(MAKE) -C modules
	$(MAKE) -C docs
	$(MAKE) -C test
	$(MAKE) -C examples
