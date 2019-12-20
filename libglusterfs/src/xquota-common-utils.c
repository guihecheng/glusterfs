#include "dict.h"
#include "logging.h"
#include "byte-order.h"
#include "xquota-common-utils.h"
#include "common-utils.h"
#include "libglusterfs-messages.h"

int32_t
xquota_conf_read_header (int fd, char *buf)
{
        int    header_len      = 0;
        int    ret             = 0;

        header_len = strlen (XQUOTA_CONF_HEADER);

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
                gf_msg_callingfn ("xquota", GF_LOG_ERROR, 0,
                                  LG_MSG_XQUOTA_CONF_ERROR, "failed to read "
                                  "header from a xquota conf");

        return ret;
}

int32_t
xquota_conf_read_version (int fd, float *version)
{
        int    ret             = 0;
        char   buf[PATH_MAX]   = "";
        char  *tail            = NULL;
        float  value           = 0.0f;

        ret = xquota_conf_read_header (fd, buf);
        if (ret == 0) {
                /* xquota.conf is empty */
                value = GF_XQUOTA_CONF_VERSION;
                goto out;
        } else if (ret < 0) {
                goto out;
        }

        value = strtof ((buf + strlen(buf) - 3), &tail);
        if (tail[0] != '\0') {
                ret = -1;
                gf_msg_callingfn ("xquota", GF_LOG_ERROR, 0,
                                  LG_MSG_XQUOTA_CONF_ERROR, "invalid xquota conf"
                                  " version");
                goto out;
        }

        ret = 0;

out:
        if (ret >= 0)
                *version = value;
        else
                gf_msg_callingfn ("xquota", GF_LOG_ERROR, 0,
                                  LG_MSG_XQUOTA_CONF_ERROR, "failed to "
                                  "read version from a xquota conf header");

        return ret;
}

int32_t
xquota_conf_read_gfid (int fd, void *buf, char *type, float version)
{
        int           ret         = 0;

        ret = gf_nread (fd, buf, 16);
        if (ret <= 0)
                goto out;

        if (ret != 16) {
                ret = -1;
                goto out;
        }

        ret = gf_nread (fd, type, 1);
        if (ret != 1) {
                ret = -1;
                goto out;
        }
        ret = 17;

out:
        if (ret < 0)
                gf_msg_callingfn ("xquota", GF_LOG_ERROR, 0,
                                  LG_MSG_XQUOTA_CONF_ERROR, "failed to "
                                  "read gfid from a xquota conf");

        return ret;
}

int32_t
xquota_conf_skip_header (int fd)
{
        return gf_skip_header_section (fd, strlen (XQUOTA_CONF_HEADER));
}
