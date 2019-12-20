#ifndef _XQUOTA_COMMON_UTILS_H
#define _XQUOTA_COMMON_UTILS_H

#include "iatt.h"

#define GF_XQUOTA_CONF_VERSION 1.0
#define XQUOTA_CONF_HEADER                           \
        "GlusterFS XQuota conf | version: v1.0\n"

typedef enum {
        GF_XQUOTA_CONF_TYPE_USAGE = 1,
} gf_xquota_conf_type_t;

struct _xquota_meta {
        uint64_t hl;
        uint64_t sl;
        uint64_t usage;
        uint32_t projid;
} __attribute__ ((__packed__));
typedef struct _xquota_meta xquota_meta_t;

int32_t
xquota_conf_read_header (int fd, char *buf);

int32_t
xquota_conf_read_version (int fd, float *version);

int32_t
xquota_conf_read_gfid (int fd, void *buf, char *type, float version);

int32_t
xquota_conf_skip_header (int fd);

#endif /* _XQUOTA_COMMON_UTILS_H */
