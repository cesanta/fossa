FROM ubuntu:trusty

MAINTAINER Marko Mikulicic <mkm@cesanta.com>

RUN apt-get update && apt-get install -y --no-install-recommends build-essential libssl-dev

VOLUME ['/cesanta']

ENTRYPOINT make -C /cesanta/fossa/test CFLAGS_EXTRA=-DTEST_UNDER_VIRTUALBOX
