# Copyright (c) 2014 Cesanta Software
# All rights reserved

DOCGEN=../scripts/docgen.py
GEN_ADOCS = skeleton.adoc http.adoc util.adoc mqtt.adoc json-rpc.adoc sha1.adoc
ADOCS = $(wildcard *.adoc) $(GEN_ADOCS)

all: index.html

# deps:
# gem install pygments.rb
# gem install pygmentize
index.html: $(ADOCS) Makefile style.css
	asciidoctor -b html5 \
	  -d book \
	  -a icons \
	  -a data-uri \
	  -a toc \
	  -a stylesheet=style.css \
	  index.adoc -o $@

skeleton.adoc: ../modules/skeleton.c Makefile $(DOCGEN)
	../scripts/docgen.py -o $@ $<

http.adoc: ../modules/http.c Makefile $(DOCGEN)
	../scripts/docgen.py -o $@ $<

util.adoc: ../modules/util.c Makefile $(DOCGEN)
	../scripts/docgen.py -o $@ $<

mqtt.adoc: ../modules/mqtt.c Makefile $(DOCGEN)
	../scripts/docgen.py -o $@ $<

json-rpc.adoc: ../modules/json-rpc.c Makefile $(DOCGEN)
	../scripts/docgen.py -o $@ $<

sha1.adoc: ../modules/sha1.c Makefile $(DOCGEN)
	../scripts/docgen.py -o $@ $<
