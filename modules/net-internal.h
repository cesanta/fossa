/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

/* internals that need to be accessible in unit tests */

typedef void (*ns_parse_address_callback_t)(struct ns_mgr *, int,
                                            union socket_address, int, void *);

NS_INTERNAL void ns_parse_address(struct ns_mgr *,
                                        const char *,
                                        char **,
                                        int,
                                        ns_parse_address_callback_t,
                                        void *);
