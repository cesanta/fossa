# TODO(mkm) use a smaller base image
#FROM buildpack-deps:jessie
FROM ubuntu:trusty

RUN apt-get update && apt-get install -y --no-install-recommends build-essential libssl-dev && rm -rf /var/lib/apt/lists/*

RUN mkdir /fossa
COPY fossa.* /fossa/

