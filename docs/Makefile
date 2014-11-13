# Copyright (c) 2014 Cesanta Software
# All rights reserved

ADOCS = $(wildcard *.adoc)

all: index.html

# deps:
# gem install pygments.rb
# gem install pygmentize
index.html: $(ADOCS) Makefile style.css
	asciidoctor -b html5 \
	  -a icons \
	  -a data-uri \
	  -a toc \
	  -a stylesheet=style.css \
	  index.adoc -o $@
