FROM cesanta/fossa

COPY load_balancer.c /fossa/
WORKDIR /fossa
RUN mkdir /fossa/certs; \
    sed -i 's:#include "../../fossa.h":#include "fossa.h":' load_balancer.c; \
    cc load_balancer.c fossa.c -o load_balancer -W -Wall -pthread -DNS_ENABLE_SSL -lssl -lcrypto
EXPOSE 8000
VOLUME ["/fossa/certs"]
ENTRYPOINT ["/fossa/load_balancer"]
