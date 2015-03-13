all: build push

build: ../fossa.c ../fossa.h
	cp ../fossa.[ch] .
	docker build -t cesanta/fossa .

push:
	docker push cesanta/fossa
