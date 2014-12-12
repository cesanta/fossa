# Copyright (c) 2014 Cesanta Software
# All rights reserved

DOCGEN=../scripts/docgen.py
GEN_ADOCS = net.adoc iobuf.adoc http.adoc util.adoc mqtt.adoc mqtt-broker.adoc json-rpc.adoc sha1.adoc dns.adoc dns-server.adoc
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
	  index.adoc -o index.html

%.adoc: ../src/%.c ../src/%.h
	$(DOCGEN) -o $@ $<

index-docinfo.html: doc.js jquery.min.js Makefile
	(echo '<script>'; cat jquery.min.js jquery.scrollTo.min.js doc.js ; echo '</script>') > $@

clean:
	rm -rf $(GEN_ADOCS) index-docinfo.html
