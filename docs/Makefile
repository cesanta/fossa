# Copyright (c) 2014 Cesanta Software
# All rights reserved

DOCGEN=../scripts/docgen.py
GEN_ADOCS = skeleton.adoc http.adoc util.adoc mqtt.adoc json-rpc.adoc sha1.adoc
ADOCS = $(wildcard *.adoc) $(GEN_ADOCS)

all: index.html

# deps:
# gem install pygments.rb
# gem install pygmentize
index.html: $(ADOCS) Makefile style.css index-docinfo.html
	asciidoctor -b html5 \
	  -d book \
	  -a icons \
	  -a data-uri \
	  -a toc \
	  -a stylesheet=style.css \
	  index.adoc -o index.html.tmp
	@git checkout index.html
	@sed 's/^Last updated.*//' index.html >index.html.tmp.A
	@sed 's/^Last updated.*//' index.html.tmp >index.html.tmp.B
	@if ! diff -q index.html.tmp.A index.html.tmp.B; then \
	  mv index.html.tmp $@; \
	else \
	  touch $@; \
	fi
	@rm -f index.html.tmp*

%.adoc: ../modules/%.c
	$(DOCGEN) -o $@ $<

index-docinfo.html: doc.js jquery.min.js Makefile
	(echo '<script>'; cat jquery.min.js jquery.scrollTo.min.js doc.js ; echo '</script>') > $@

clean:
	rm -rf $(GEN_ADOCS) index-docinfo.html
