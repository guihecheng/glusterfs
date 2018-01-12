/*
   Copyright (c) 2015 Red Hat, Inc. <http://www.redhat.com>
   This file is part of GlusterFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/


#include "dict.h"
#include "logging.h"
#include "byte-order.h"
#include "worm-common-utils.h"
#include "common-utils.h"
#include "libglusterfs-messages.h"

gf_boolean_t
worm_meta_is_null (const worm_meta_t *meta)
{
        if (meta->start == 0 &&
            meta->dura == 0)
                return _gf_true;

        return _gf_false;
}

static int32_t
worm_data_to_meta (data_t *data, char *key, worm_meta_t *meta)
{
        int32_t        ret      = -1;
        worm_meta_t   *value    = NULL;
        int64_t       *size     = NULL;

        if (!data || !key || !meta)
                goto out;

        value = (worm_meta_t *) data->data;
        meta->start = ntoh64 (value->start);
        meta->dura = ntoh64 (value->dura);

        ret = 0;
out:
        return ret;
}

int32_t
worm_dict_get_meta (dict_t *dict, char *key, worm_meta_t *meta)
{
        int32_t        ret      = -1;
        data_t        *data     = NULL;

        if (!dict || !key || !meta)
                goto out;

        data = dict_get (dict, key);
        if (!data || !data->data)
                goto out;

        ret = worm_data_to_meta (data, key, meta);
out:
        return ret;
}

int32_t
worm_dict_set_meta (dict_t *dict, char *key, const worm_meta_t *meta,
                    ia_type_t ia_type)
{
        int32_t         ret      = -ENOMEM;
        worm_meta_t   *value    = NULL;

        value = GF_CALLOC (1, sizeof (worm_meta_t), gf_common_worm_meta_t);
        if (value == NULL) {
                goto out;
        }

        value->start = hton64 (meta->start);
        value->dura = hton64 (meta->dura);

        ret = dict_set_bin (dict, key, value, sizeof (*value));

        if (ret < 0) {
                gf_msg_callingfn ("worm", GF_LOG_ERROR, 0,
                                  LG_MSG_DICT_SET_FAILED, "dict set failed");
                GF_FREE (value);
        }

out:
        return ret;
}

int32_t
worm_conf_read_header (int fd, char *buf)
{
        int    header_len      = 0;
        int    ret             = 0;

        header_len = strlen (WORM_CONF_HEADER);

        ret = gf_nread (fd, buf, header_len);
        if (ret <= 0) {
                goto out;
        } else if (ret > 0 && ret != header_len) {
                ret = -1;
                goto out;
        }

        buf[header_len-1] = 0;

out:
        if (ret < 0)
                gf_msg_callingfn ("worm", GF_LOG_ERROR, 0,
                                  LG_MSG_WORM_CONF_ERROR, "failed to read "
                                  "header from a worm conf");

        return ret;
}

int32_t
worm_conf_read_gfid (int fd, void *buf, char *type)
{
        int           ret         = 0;

        ret = gf_nread (fd, buf, 16);
        if (ret <= 0)
                goto out;

        if (ret != 16) {
                ret = -1;
                goto out;
        }

        *type = GF_WORM_CONF_TYPE_DIR;

out:
        if (ret < 0)
                gf_msg_callingfn ("worm", GF_LOG_ERROR, 0,
                                  LG_MSG_WORM_CONF_ERROR, "failed to "
                                  "read gfid from a worm conf");

        return ret;
}

int32_t
worm_conf_skip_header (int fd)
{
        return gf_skip_header_section (fd, strlen (WORM_CONF_HEADER));
}

