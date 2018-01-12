/*
   Copyright (c) 2015 Red Hat, Inc. <http://www.redhat.com>
   This file is part of GlusterFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/

#ifndef _WORM_COMMON_UTILS_H
#define _WORM_COMMON_UTILS_H

#include "iatt.h"

#define WORM_CONF_HEADER                           \
        "GlusterFS Worm conf | version: v1.0\n"

typedef enum {
        GF_WORM_CONF_TYPE_DIR = 1,
} gf_worm_conf_type_t;

struct _worm_meta {
        int64_t start;
        int64_t dura;
} __attribute__ ((__packed__));
typedef struct _worm_meta worm_meta_t;

gf_boolean_t
worm_meta_is_null (const worm_meta_t *meta);

int32_t
worm_dict_get_meta (dict_t *dict, char *key, worm_meta_t *meta);

int32_t
worm_dict_set_meta (dict_t *dict, char *key, const worm_meta_t *meta,
                     ia_type_t ia_type);

int32_t
worm_conf_read_header (int fd, char *buf);

int32_t
worm_conf_read_gfid (int fd, void *buf, char *type);

int32_t
worm_conf_skip_header (int fd);

#endif /* _WORM_COMMON_UTILS_H */
