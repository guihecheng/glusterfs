#include "common-utils.h"
#include "cli1-xdr.h"
#include "xdr-generic.h"
#include "glusterd.h"
#include "glusterd-op-sm.h"
#include "glusterd-store.h"
#include "glusterd-utils.h"
#include "glusterd-nfs-svc.h"
#include "glusterd-xquotad-svc.h"
#include "glusterd-volgen.h"
#include "glusterd-messages.h"
#include "run.h"
#include "syscall.h"
#include "byte-order.h"
#include "compat-errno.h"
#include "xquota-common-utils.h"
#include "glusterd-xquota.h"

#include <sys/wait.h>
#include <dlfcn.h>

#ifndef _PATH_SETFATTR
# ifdef GF_LINUX_HOST_OS
#  define _PATH_SETFATTR "/usr/bin/setfattr"
# endif
# ifdef __NetBSD__
#  define _PATH_SETFATTR "/usr/pkg/bin/setfattr"
# endif
#endif


#define XFS_QUOTA "/usr/sbin/xfs_quota"
#define XFS_IO "/usr/sbin/xfs_io"

const char *gd_xquota_op_list[GF_XQUOTA_OPTION_TYPE_MAX + 1] = {
        [GF_XQUOTA_OPTION_TYPE_NONE]                   = "none",
        [GF_XQUOTA_OPTION_TYPE_ENABLE]                 = "enable",
        [GF_XQUOTA_OPTION_TYPE_DISABLE]                = "disable",
        [GF_XQUOTA_OPTION_TYPE_PROJECT_LIMIT_USAGE]    = "project limit-usage",
        [GF_XQUOTA_OPTION_TYPE_PROJECT_REMOVE_USAGE]   = "project remove-usage",
        [GF_XQUOTA_OPTION_TYPE_PROJECT_LIST_USAGE]     = "project list-usage",
        [GF_XQUOTA_OPTION_TYPE_VERSION]                = "version",
        [GF_XQUOTA_OPTION_TYPE_ALERT_TIME]             = "alert-time",
        [GF_XQUOTA_OPTION_TYPE_SOFT_TIMEOUT]           = "soft-timeout",
        [GF_XQUOTA_OPTION_TYPE_HARD_TIMEOUT]           = "hard-timeout",
        [GF_XQUOTA_OPTION_TYPE_DEFAULT_SOFT_LIMIT]     = "default-soft-limit",
        [GF_XQUOTA_OPTION_TYPE_MAX]                    = NULL
};


gf_boolean_t
glusterd_is_xquota_supported (int32_t type, char **op_errstr)
{
        xlator_t           *this        = NULL;
        glusterd_conf_t    *conf        = NULL;
        gf_boolean_t        supported   = _gf_false;

        this = THIS;
        GF_VALIDATE_OR_GOTO ("glusterd", this, out);

        conf = this->private;
        GF_VALIDATE_OR_GOTO (this->name, conf, out);

        supported = _gf_true;

out:
        if (!supported && op_errstr != NULL && conf)
                gf_asprintf (op_errstr, "Volume xquota failed. The cluster is "
                             "operating at version %d. XQuota command"
                             " %s is unavailable in this version.",
                             conf->op_version, gd_xquota_op_list[type]);

        return supported;
}

int
__glusterd_handle_xquota (rpcsvc_request_t *req)
{
        int32_t                         ret = -1;
        gf_cli_req                      cli_req = {{0,}};
        dict_t                         *dict = NULL;
        glusterd_op_t                   cli_op = GD_OP_XQUOTA;
        char                           *volname = NULL;
        int32_t                         type = 0;
        char                            msg[2048] = {0,};
        xlator_t                       *this = NULL;
        glusterd_conf_t                *conf = NULL;

        GF_ASSERT (req);
        this = THIS;
        GF_ASSERT (this);
        conf = this->private;
        GF_ASSERT (conf);

        ret = xdr_to_generic (req->msg[0], &cli_req, (xdrproc_t)xdr_gf_cli_req);
        if (ret < 0) {
                //failed to decode msg;
                req->rpc_err = GARBAGE_ARGS;
                goto out;
        }

        if (cli_req.dict.dict_len) {
                /* Unserialize the dictionary */
                dict  = dict_new ();

                ret = dict_unserialize (cli_req.dict.dict_val,
                                        cli_req.dict.dict_len,
                                        &dict);
                if (ret < 0) {
                        gf_msg (this->name, GF_LOG_ERROR, 0,
                                GD_MSG_DICT_UNSERIALIZE_FAIL, "failed to "
                                    "unserialize req-buffer to dictionary");
                        snprintf (msg, sizeof (msg), "Unable to decode the "
                                  "command");
                        goto out;
                } else {
                        dict->extra_stdfree = cli_req.dict.dict_val;
                }
        }

        ret = dict_get_str (dict, "volname", &volname);
        if (ret) {
                snprintf (msg, sizeof (msg), "Unable to get volume name");
                gf_msg (this->name, GF_LOG_ERROR, 0,
                        GD_MSG_DICT_GET_FAILED, "Unable to get volume name, "
                        "while handling xquota command");
                goto out;
        }

        ret = dict_get_int32 (dict, "type", &type);
        if (ret) {
                snprintf (msg, sizeof (msg), "Unable to get type of command");
                gf_msg (this->name, GF_LOG_ERROR, 0,
                        GD_MSG_DICT_GET_FAILED, "Unable to get type of cmd, "
                        "while handling xquota command");
                goto out;
        }

        if (!glusterd_is_xquota_supported (type, NULL)) {
                snprintf (msg, sizeof (msg), "Volume xquota failed. The cluster "
                          "is operating at version %d. XQuota command"
                          " %s is unavailable in this version.",
                          conf->op_version, gd_xquota_op_list[type]);
                ret = -1;
                goto out;
        }

        ret = glusterd_op_begin_synctask (req, GD_OP_XQUOTA, dict);

out:
        if (ret) {
                if (msg[0] == '\0')
                        snprintf (msg, sizeof (msg), "Operation failed");
                ret = glusterd_op_send_cli_response (cli_op, ret, 0, req,
                                                     dict, msg);
        }

        return ret;
}

int
glusterd_handle_xquota (rpcsvc_request_t *req)
{
        return glusterd_big_locked_handler (req, __glusterd_handle_xquota);
}

int32_t
glusterd_check_if_xquota_trans_enabled (glusterd_volinfo_t *volinfo)
{
        int32_t  ret           = 0;
        int      flag          = _gf_false;

        flag = glusterd_volinfo_get_boolean (volinfo, VKEY_FEATURES_XQUOTA);
        if (flag == -1) {
                gf_msg ("glusterd", GF_LOG_ERROR, 0,
                        GD_MSG_XQUOTA_GET_STAT_FAIL,
                        "failed to get the xquota status");
                ret = -1;
                goto out;
        }

        if (flag == _gf_false) {
                ret = -1;
                goto out;
        }
        ret = 0;
out:
        return ret;
}

int32_t
glusterd_xquota_get_default_soft_limit (glusterd_volinfo_t *volinfo,
                                        dict_t *rsp_dict)
{
        int32_t            ret             = 0;
        xlator_t          *this            = NULL;
        glusterd_conf_t   *conf            = NULL;
        char              *default_limit   = NULL;
        char              *val             = NULL;

        if (rsp_dict == NULL)
                return -1;

        this = THIS;
        GF_ASSERT (this);
        conf = this->private;
        GF_ASSERT (conf);

        ret = glusterd_volinfo_get (volinfo, "features.xquota-default-soft-limit",
                                    &default_limit);
        if (default_limit)
                val = gf_strdup (default_limit);
        else
                val = gf_strdup ("80%");

        ret = dict_set_dynstr (rsp_dict, "xquota-default-soft-limit", val);
        if (ret) {
                gf_msg (this->name, GF_LOG_ERROR, 0,
                        GD_MSG_DICT_SET_FAILED, "Failed to set xquota default "
                        "soft-limit into dict");
                goto out;
        }
        ret = 0;

out:
        return ret;
}

int32_t
glusterd_xquota_enable (glusterd_volinfo_t *volinfo, char **op_errstr)
{
        int32_t         ret     = -1;
        xlator_t        *this         = NULL;

        this = THIS;
        GF_ASSERT (this);

        GF_VALIDATE_OR_GOTO (this->name, volinfo, out);
        GF_VALIDATE_OR_GOTO (this->name, op_errstr, out);

        if (glusterd_is_volume_started (volinfo) == 0) {
                *op_errstr = gf_strdup ("Volume is stopped, start volume "
                                        "to enable xquota.");
                ret = -1;
                goto out;
        }

        ret = glusterd_check_if_xquota_trans_enabled (volinfo);
        if (ret == 0) {
                *op_errstr = gf_strdup ("XQuota is already enabled");
                ret = -1;
                goto out;
        }

        ret = dict_set_dynstr_with_alloc (volinfo->dict, VKEY_FEATURES_XQUOTA,
                                          "on");
        if (ret) {
                gf_msg (this->name, GF_LOG_ERROR, errno,
                        GD_MSG_DICT_SET_FAILED, "dict set failed");
                goto out;
        }

        ret = dict_set_dynstr_with_alloc (volinfo->dict,
                                          "features.xquota-quota-deem-statfs",
                                          "on");
        if (ret) {
                gf_msg (this->name, GF_LOG_ERROR, errno,
                        GD_MSG_DICT_SET_FAILED, "setting xquota-quota-deem-statfs"
                        "in volinfo failed");
                goto out;
        }

        ret = glusterd_store_xquota_config (volinfo, NULL, NULL,
                                            GF_XQUOTA_OPTION_TYPE_ENABLE,
                                            op_errstr);

        ret = 0;
out:
        if (ret && op_errstr && !*op_errstr)
                gf_asprintf (op_errstr, "Enabling xquota on volume %s has been "
                             "unsuccessful", volinfo->volname);
        return ret;
}

int32_t
glusterd_xquota_disable (glusterd_volinfo_t *volinfo, char **op_errstr)
{
        int32_t    ret            = -1;
        int        i              =  0;
        char      *value          = NULL;
        xlator_t  *this           = NULL;
        glusterd_conf_t *conf     = NULL;
        char *xquota_options[]     = {"features.xquota-soft-timeout",
                                     "features.xquota-hard-timeout",
                                     "features.xquota-alert-time",
                                     "features.xquota-default-soft-limit",
                                     "features.xquota-quota-deem-statfs",
                                     "features.xquota-timeout", NULL};

        this = THIS;
        GF_ASSERT (this);
        conf = this->private;
        GF_ASSERT (conf);

        GF_VALIDATE_OR_GOTO (this->name, volinfo, out);
        GF_VALIDATE_OR_GOTO (this->name, op_errstr, out);

        ret = glusterd_check_if_xquota_trans_enabled (volinfo);
        if (ret == -1) {
                *op_errstr = gf_strdup ("XQuota is already disabled");
                goto out;
        }

        ret = dict_set_dynstr_with_alloc (volinfo->dict, VKEY_FEATURES_XQUOTA,
                                          "off");
        if (ret) {
                gf_msg (this->name, GF_LOG_ERROR, errno,
                        GD_MSG_DICT_SET_FAILED, "dict set failed");
                goto out;
        }

        for (i = 0; xquota_options [i]; i++) {
                ret = glusterd_volinfo_get (volinfo, xquota_options[i], &value);
                if (ret) {
                        gf_msg (this->name, GF_LOG_INFO, 0,
                                GD_MSG_VOLINFO_GET_FAIL, "failed to get option"
                                " %s", xquota_options[i]);
                } else {
                        dict_del (volinfo->dict, xquota_options[i]);
                }
        }

        (void) glusterd_clean_up_xquota_store (volinfo);

        ret = 0;
out:
        if (ret && op_errstr && !*op_errstr)
                gf_asprintf (op_errstr, "Disabling xquota on volume %s has been "
                             "unsuccessful", volinfo->volname);
        return ret;
}

static int
glusterd_set_xquota_xfsquota (glusterd_volinfo_t *volinfo, char *path, char *projid,
                              char* hard_limit, char* soft_limit, char **op_errstr)
{
        int                    ret                    = -1;
        char                   backend_path[PATH_MAX] = {0,};
        xlator_t              *this                   = NULL;
        glusterd_conf_t       *priv                   = NULL;
        glusterd_brickinfo_t  *brickinfo              = NULL;
        char                   pjcmd[PATH_MAX]        = {0,};
        char                  *mnt_pt                 = NULL;

        this = THIS;
        GF_ASSERT (this);
        priv = this->private;
        GF_ASSERT (priv);

        cds_list_for_each_entry (brickinfo, &volinfo->bricks, brick_list) {
                ret = glusterd_resolve_brick (brickinfo);
                if (ret) {
                        gf_msg (this->name, GF_LOG_ERROR, 0,
                                GD_MSG_RESOLVE_BRICK_FAIL, FMTSTR_RESOLVE_BRICK,
                                brickinfo->hostname, brickinfo->path);
                        goto out;
                }

                if (gf_uuid_compare (brickinfo->uuid, MY_UUID))
                        continue;

                if (brickinfo->vg[0])
                        continue;

                snprintf (backend_path, sizeof (backend_path), "%s%s",
                          brickinfo->path, path);

                ret = gf_lstat_dir (backend_path, NULL);
                if (ret) {
                        gf_msg (this->name, GF_LOG_INFO, errno,
                                GD_MSG_DIR_OP_FAILED, "Failed to find "
                                "directory %s.", backend_path);
                        ret = 0;
                        continue;
                }

                ret = glusterd_get_brick_root (backend_path, &mnt_pt);
                if (ret) {
                    goto out;
                }

                snprintf (pjcmd, sizeof (pjcmd), "project -s -p %s %s",
                          backend_path, projid);

                ret = runcmd (XFS_QUOTA, "-x", "-c", pjcmd, mnt_pt, NULL);
                if (ret) {
                    ret = -errno;
                    goto out;
                }

                if (!soft_limit) {
                    snprintf (pjcmd, sizeof (pjcmd), "limit -p bhard=%s %s",
                              hard_limit, projid);
                } else {
                    snprintf (pjcmd, sizeof (pjcmd), "limit -p bhard=%s bsoft=%s %s",
                              hard_limit, soft_limit, projid);
                }

                ret = runcmd (XFS_QUOTA, "-x", "-c", pjcmd, mnt_pt, NULL);
                if (ret) {
                    ret = -errno;
                    goto out;
                }
        }

        ret = 0;
out:
        GF_FREE (mnt_pt);
        return ret;
}

static int
glusterd_get_xfs_projid (char* backend_path, uint32_t *projid)
{
        runner_t     runner         = {0,};
        int          ret            = 0;
        char         cmd[1024]      = {0,};
        char         msg[1024]      = {0,};
        char         buf[1024]      = {0,};
        char        *token          = NULL;
        const char  *delim          = " \t";
        char        *saveptr        = NULL;
        int          i              = 0;

        runinit (&runner);
        runner_add_args (&runner, XFS_IO, backend_path, "-c", "lsproj", NULL);
        snprintf (msg, sizeof (msg), "Get projid of path %s", backend_path);
        runner_log (&runner, THIS->name, GF_LOG_DEBUG, msg);
        runner_redir (&runner, STDOUT_FILENO, RUN_PIPE);
        ret = runner_start (&runner);
        if (ret) {
                gf_msg (THIS->name, GF_LOG_ERROR, errno,
                        GD_MSG_DIR_OP_FAILED, "failed to get projid for "
                        "path: %s stat: %s",
                        backend_path, strerror (errno));
                runner_end (&runner);
                goto out;
        }

        fgets (buf, sizeof (buf), runner_chio (&runner, STDOUT_FILENO));
        runner_end (&runner);

        for (token = strtok_r (buf, delim, &saveptr); token;
                token = strtok_r (NULL, delim, &saveptr), i++) {
            if (i == 2) {
                ret = gf_string2uint32 (gf_trim (token), projid);
                if (ret) {
                        gf_msg (THIS->name, GF_LOG_ERROR, errno,
                                GD_MSG_DIR_OP_FAILED, "failed to parse projid for "
                                "path: %s token: %s stat: %s",
                                backend_path, gf_trim (token), strerror (errno));
                }
                break;
            }
        }
out:
        return ret;
}

static int
glusterd_clear_xquota_xfsquota (glusterd_volinfo_t *volinfo, char *path,
                                char **op_errstr)
{
        int                    ret                    = -1;
        char                   backend_path[PATH_MAX] = {0,};
        xlator_t              *this                   = NULL;
        glusterd_conf_t       *priv                   = NULL;
        glusterd_brickinfo_t  *brickinfo              = NULL;
        char                   pjcmd[PATH_MAX]        = {0,};
        char                  *mnt_pt                 = NULL;
        uint32_t               projid                 = 0;

        this = THIS;
        GF_ASSERT (this);
        priv = this->private;
        GF_ASSERT (priv);

        cds_list_for_each_entry (brickinfo, &volinfo->bricks, brick_list) {
                ret = glusterd_resolve_brick (brickinfo);
                if (ret) {
                        gf_msg (this->name, GF_LOG_ERROR, 0,
                                GD_MSG_RESOLVE_BRICK_FAIL, FMTSTR_RESOLVE_BRICK,
                                brickinfo->hostname, brickinfo->path);
                        goto out;
                }

                if (gf_uuid_compare (brickinfo->uuid, MY_UUID))
                        continue;

                if (brickinfo->vg[0])
                        continue;

                snprintf (backend_path, sizeof (backend_path), "%s%s",
                          brickinfo->path, path);

                ret = gf_lstat_dir (backend_path, NULL);
                if (ret) {
                        gf_msg (this->name, GF_LOG_INFO, errno,
                                GD_MSG_DIR_OP_FAILED, "Failed to find "
                                "directory %s.", backend_path);
                        ret = 0;
                        continue;
                }
                ret = glusterd_get_brick_root (backend_path, &mnt_pt);
                if (ret) {
                        gf_msg (this->name, GF_LOG_INFO, errno,
                                GD_MSG_DIR_OP_FAILED, "Failed to get "
                                "brick root for directory %s.", backend_path);
                        goto out;
                }

                ret = glusterd_get_xfs_projid (backend_path, &projid);
                if (ret) {
                        gf_msg (this->name, GF_LOG_INFO, errno,
                                GD_MSG_DIR_OP_FAILED, "Failed to get "
                                "projid for directory %s.", backend_path);
                        goto out;
                }

                snprintf (pjcmd, sizeof (pjcmd), "limit -p bhard=0 bsoft=0 %u",
                          projid);

                ret = runcmd (XFS_QUOTA, "-x", "-c", pjcmd, mnt_pt, NULL);
                if (ret) {
                    ret = -errno;
                    goto out;
                }
        }

        ret = 0;
out:
        GF_FREE (mnt_pt);
        return ret;
}

static int
glusterd_update_xquota_conf_version (glusterd_volinfo_t *volinfo)
{
        volinfo->xquota_conf_version++;
        return 0;
}

static gf_boolean_t
glusterd_find_gfid_match (uuid_t gfid, char gfid_type, unsigned char *buf,
                          size_t bytes_read, int opcode,
                          size_t *write_byte_count)
{
        int                 gfid_index  = 0;
        int                 shift_count = 0;
        unsigned char       tmp_buf[17] = {0,};
        char                type        = 0;
        xlator_t           *this        = NULL;
        glusterd_conf_t    *conf        = NULL;

        this = THIS;
        GF_VALIDATE_OR_GOTO ("glusterd", this, out);

        conf = this->private;
        GF_VALIDATE_OR_GOTO (this->name, conf, out);

        while (gfid_index != bytes_read) {
                memcpy ((void *)tmp_buf, (void *)&buf[gfid_index], 16);
                type = buf[gfid_index + 16];

                if (!gf_uuid_compare (gfid, tmp_buf) && type == gfid_type) {
                        if (opcode == GF_XQUOTA_OPTION_TYPE_PROJECT_REMOVE_USAGE) {
                                shift_count = bytes_read - (gfid_index + 17);
                                memmove ((void *)&buf[gfid_index],
                                         (void *)&buf[gfid_index + 17],
                                         shift_count);
                                *write_byte_count = bytes_read - 17;
                        } else {
                                *write_byte_count = bytes_read;
                        }
                        return _gf_true;
                } else {
                        gfid_index += 17;
                }
        }
        if (gfid_index == bytes_read)
                *write_byte_count = bytes_read;

out:

        return _gf_false;
}

/* The function glusterd_copy_to_tmp_file() reads the "remaining" bytes from
 * the source fd and writes them to destination fd, at the rate of 128K bytes
 * of read+write at a time.
 */

static int
glusterd_copy_to_tmp_file (int src_fd, int dst_fd)
{
        int            ret         = 0;
        size_t         entry_sz    = 131072;
        ssize_t        bytes_read  = 0;
        unsigned char  buf[131072] = {0,};
        xlator_t      *this        = NULL;

        this = THIS;
        GF_ASSERT (this);

        while ((bytes_read = sys_read (src_fd, (void *)&buf, entry_sz)) > 0) {
                if (bytes_read % 16 != 0) {
                        gf_msg (this->name, GF_LOG_ERROR, 0,
                                GD_MSG_XQUOTA_CONF_CORRUPT, "xquota.conf "
                                "corrupted");
                        ret = -1;
                        goto out;
                }
                ret = sys_write (dst_fd, (void *) buf, bytes_read);
                if (ret == -1) {
                        gf_msg (this->name, GF_LOG_ERROR, errno,
                                GD_MSG_XQUOTA_CONF_WRITE_FAIL,
                                "write into xquota.conf failed.");
                        goto out;
                }
        }
        ret = 0;

out:
        return ret;
}

int
glusterd_store_xquota_config (glusterd_volinfo_t *volinfo, char *path,
                              char *gfid_str, int opcode, char **op_errstr)
{
        int                ret                   = -1;
        int                fd                    = -1;
        int                conf_fd               = -1;
        ssize_t            bytes_read            = 0;
        size_t             bytes_to_write        = 0;
        unsigned char      buf[131072]           = {0,};
        uuid_t             gfid                  = {0,};
        xlator_t          *this                  = NULL;
        gf_boolean_t       found                 = _gf_false;
        gf_boolean_t       modified              = _gf_false;
        gf_boolean_t       is_file_empty         = _gf_false;
        gf_boolean_t       is_first_read         = _gf_true;
        glusterd_conf_t   *conf                  = NULL;
        float              version               = 0.0f;
        char               type                  = 0;
        int                xquota_conf_line_sz   = 17;

        this = THIS;
        GF_ASSERT (this);
        conf = this->private;
        GF_ASSERT (conf);

        glusterd_store_create_xquota_conf_sh_on_absence (volinfo);

        conf_fd = open (volinfo->xquota_conf_shandle->path, O_RDONLY);
        if (conf_fd == -1) {
                ret = -1;
                goto out;
        }

        ret = xquota_conf_read_version (conf_fd, &version);
        if (ret)
                goto out;

        fd = gf_store_mkstemp (volinfo->xquota_conf_shandle);
        if (fd < 0) {
                ret = -1;
                goto out;
        }

        ret = glusterd_xquota_conf_write_header (fd);
        if (ret)
                goto out;


        /* Just create empty xquota.conf file if create */
        if (GF_XQUOTA_OPTION_TYPE_ENABLE == opcode) {
                modified = _gf_true;
                goto out;
        }

        /* Check if gfid_str is given for opts other than ENABLE */
        if (!gfid_str) {
                ret = -1;
                goto out;
        }
        gf_uuid_parse (gfid_str, gfid);

        type = GF_XQUOTA_CONF_TYPE_USAGE;

        for (;;) {
                bytes_read = sys_read (conf_fd, (void *)&buf, sizeof (buf));
                if (bytes_read <= 0) {
                        /*The flag @is_first_read is TRUE when the loop is
                         * entered, and is set to false if the first read
                         * reads non-zero bytes of data. The flag is used to
                         * detect if xquota.conf is an empty file, but for the
                         * header. This is done to log appropriate error message
                         * when 'x:quota remove' is attempted when there are no
                         * limits set on the given volume.
                         */
                        if (is_first_read)
                                is_file_empty = _gf_true;
                        break;
                }
                if ((bytes_read % xquota_conf_line_sz) != 0) {
                        gf_msg (this->name, GF_LOG_ERROR, 0,
                                GD_MSG_XQUOTA_CONF_CORRUPT, "xquota.conf "
                                "corrupted");
                        ret = -1;
                        goto out;
                }
                found = glusterd_find_gfid_match (gfid, type, buf, bytes_read,
                                                  opcode, &bytes_to_write);

                ret = sys_write (fd, (void *) buf, bytes_to_write);
                if (ret == -1) {
                        gf_msg (this->name, GF_LOG_ERROR, errno,
                                GD_MSG_XQUOTA_CONF_WRITE_FAIL,
                                "write into xquota.conf failed.");
                        goto out;
                }

                /*If the match is found in this iteration, copy the rest of
                 * xquota.conf into xquota.conf.tmp and break.
                 * Else continue with the search.
                 */
                if (found) {
                        ret = glusterd_copy_to_tmp_file (conf_fd, fd);
                        if (ret)
                                goto out;
                        break;
                }
                is_first_read = _gf_false;
        }

        switch (opcode) {
        case GF_XQUOTA_OPTION_TYPE_PROJECT_LIMIT_USAGE:
                if (!found) {
                        ret = glusterd_xquota_conf_write_gfid (fd, gfid,
                                GF_XQUOTA_CONF_TYPE_USAGE);
                        if (ret == -1) {
                                gf_msg (this->name, GF_LOG_ERROR, errno,
                                        GD_MSG_XQUOTA_CONF_WRITE_FAIL,
                                        "write into xquota.conf failed. ");
                                goto out;
                        }
                        modified = _gf_true;
                }
                break;

        case GF_XQUOTA_OPTION_TYPE_PROJECT_REMOVE_USAGE:
                if (is_file_empty) {
                        gf_asprintf (op_errstr, "Cannot remove limit on"
                                     " %s. The xquota configuration file"
                                     " for volume %s is empty.", path,
                                     volinfo->volname);
                        ret = -1;
                        goto out;
                } else {
                        if (!found) {
                                gf_asprintf (op_errstr, "Error. gfid %s"
                                             " for path %s not found in"
                                             " store", gfid_str, path);
                                ret = -1;
                                goto out;
                        } else {
                                modified = _gf_true;
                        }
                }
                break;

        default:
                ret = 0;
                break;
        }

        if (modified)
                glusterd_update_xquota_conf_version (volinfo);

        ret = 0;
out:
        if (conf_fd != -1) {
                sys_close (conf_fd);
        }

        if (ret && (fd > 0)) {
                gf_store_unlink_tmppath (volinfo->xquota_conf_shandle);
        } else if (!ret) {
                ret = gf_store_rename_tmppath (volinfo->xquota_conf_shandle);
                if (modified) {
                        ret = glusterd_compute_cksum (volinfo, _gf_false, _gf_true);
                        if (ret) {
                                gf_msg (this->name, GF_LOG_ERROR, 0,
                                        GD_MSG_CKSUM_COMPUTE_FAIL, "Failed to "
                                        "compute cksum for xquota conf file");
                                return ret;
                        }

                        ret = glusterd_store_save_xquota_version_and_cksum(volinfo);
                        if (ret)
                                gf_msg (this->name, GF_LOG_ERROR, 0,
                                        GD_MSG_XQUOTA_CKSUM_VER_STORE_FAIL,
                                        "Failed to "
                                        "store xquota version and cksum");
                }
        }

        return ret;
}

int32_t
glusterd_xquota_limit_usage (glusterd_volinfo_t *volinfo, dict_t *dict,
                             int opcode, char **op_errstr)
{
        int32_t          ret                = -1;
        char            *path               = NULL;
        char            *hard_limit         = NULL;
        char            *soft_limit         = NULL;
        char            *gfid_str           = NULL;
        char            *projid             = NULL;
        xlator_t        *this               = NULL;

        this = THIS;
        GF_ASSERT (this);

        GF_VALIDATE_OR_GOTO (this->name, dict, out);
        GF_VALIDATE_OR_GOTO (this->name, volinfo, out);
        GF_VALIDATE_OR_GOTO (this->name, op_errstr, out);

        ret = glusterd_check_if_xquota_trans_enabled (volinfo);
        if (ret == -1) {
                *op_errstr = gf_strdup ("XQuota is disabled, please enable "
                                        "xquota");
                goto out;
        }

        ret = dict_get_str (dict, "path", &path);
        if (ret) {
                gf_msg (this->name, GF_LOG_ERROR, 0,
                        GD_MSG_DICT_GET_FAILED, "Unable to fetch path");
                goto out;
        }
        ret = gf_canonicalize_path (path);
        if (ret)
                goto out;

        ret = dict_get_str (dict, "hard-limit", &hard_limit);
        if (ret) {
                gf_msg (this->name, GF_LOG_ERROR, 0,
                        GD_MSG_DICT_GET_FAILED, "Unable to fetch hard limit");
                goto out;
        }

        if (dict_get (dict, "soft-limit")) {
                ret = dict_get_str (dict, "soft-limit", &soft_limit);
                if (ret) {
                        gf_msg (this->name, GF_LOG_ERROR, 0,
                                GD_MSG_DICT_GET_FAILED, "Unable to fetch "
                                "soft limit");
                        goto out;
                }
        }

        ret = dict_get_str (dict, "projid", &projid);
        if (ret) {
                gf_msg (this->name, GF_LOG_ERROR, 0,
                        GD_MSG_DICT_GET_FAILED, "Unable to fetch projid");
                goto out;
        }

        ret = glusterd_set_xquota_xfsquota (volinfo, path, projid,
                                            hard_limit, soft_limit,
                                            op_errstr);
        if (ret)
                goto out;

        ret = dict_get_str (dict, "gfid", &gfid_str);
        if (ret) {
                gf_msg (this->name, GF_LOG_ERROR, 0,
                        GD_MSG_DICT_GET_FAILED, "Failed to get gfid of path "
                        "%s", path);
                goto out;
        }

        ret = glusterd_store_xquota_config (volinfo, path, gfid_str, opcode,
                                            op_errstr);
        if (ret)
                goto out;

        ret = 0;
out:

        if (ret && op_errstr && !*op_errstr)
                gf_asprintf (op_errstr, "Failed to set hard limit on path %s "
                             "for volume %s", path, volinfo->volname);
        return ret;
}

int32_t
glusterd_xquota_remove_limits (glusterd_volinfo_t *volinfo, dict_t *dict,
                               int opcode, char **op_errstr)
{
        int32_t         ret                   = -1;
        char            *path                 = NULL;
        char            *gfid_str             = NULL;
        xlator_t        *this                 = NULL;

        this = THIS;
        GF_ASSERT (this);

        GF_VALIDATE_OR_GOTO (this->name, dict, out);
        GF_VALIDATE_OR_GOTO (this->name, volinfo, out);
        GF_VALIDATE_OR_GOTO (this->name, op_errstr, out);

        ret = glusterd_check_if_xquota_trans_enabled (volinfo);
        if (ret == -1) {
                *op_errstr = gf_strdup ("XQuota is disabled, please enable "
                                        "xquota");
                goto out;
        }

        ret = dict_get_str (dict, "path", &path);
        if (ret) {
                gf_msg (this->name, GF_LOG_ERROR, 0,
                        GD_MSG_DICT_GET_FAILED, "Unable to fetch path");
                goto out;
        }

        ret = gf_canonicalize_path (path);
        if (ret)
                goto out;

        ret = glusterd_clear_xquota_xfsquota (volinfo, path, op_errstr);

        ret = dict_get_str (dict, "gfid", &gfid_str);
        if (ret) {
                gf_msg (this->name, GF_LOG_ERROR, 0,
                        GD_MSG_DICT_GET_FAILED, "Failed to get gfid of path "
                        "%s", path);
                goto out;
        }

        ret = glusterd_store_xquota_config (volinfo, path, gfid_str, opcode,
                                            op_errstr);
        if (ret)
                goto out;


        ret = 0;

out:
        return ret;
}

int
glusterd_set_xquota_option (glusterd_volinfo_t *volinfo, dict_t *dict,
                            char *key, char **op_errstr)
{
        int        ret    = 0;
        char      *value  = NULL;
        xlator_t  *this   = NULL;
        char      *option = NULL;

        this = THIS;
        GF_ASSERT (this);

        ret = glusterd_check_if_xquota_trans_enabled (volinfo);
        if (ret == -1) {
                gf_asprintf (op_errstr, "Cannot set %s. XQuota on volume %s is "
                                        "disabled", key, volinfo->volname);
                return -1;
        }

        ret = dict_get_str (dict, "value", &value);
        if(ret) {
                gf_msg (this->name, GF_LOG_ERROR, 0,
                        GD_MSG_DICT_GET_FAILED, "Option value absent.");
                return -1;
        }

        option = gf_strdup (value);
        ret = dict_set_dynstr (volinfo->dict, key, option);
        if(ret) {
                gf_msg (this->name, GF_LOG_ERROR, 0,
                        GD_MSG_DICT_GET_FAILED, "Failed to set option %s",
                        key);
                return -1;
        }

        return 0;
}

static int
glusterd_xquotad_op (int opcode)
{
        int              ret  = -1;
        xlator_t        *this = NULL;
        glusterd_conf_t *priv = NULL;

        this = THIS;
        GF_ASSERT (this);

        priv = this->private;
        GF_ASSERT (priv);

        switch (opcode) {
                case GF_XQUOTA_OPTION_TYPE_ENABLE:
                case GF_XQUOTA_OPTION_TYPE_DISABLE:

                        if (glusterd_all_volumes_with_xquota_stopped ())
                                ret = glusterd_svc_stop (&(priv->xquotad_svc),
                                                         SIGTERM);
                        else
                                ret = priv->xquotad_svc.manager
                                                (&(priv->xquotad_svc), NULL,
                                                 PROC_START);
                        break;

                default:
                        ret = 0;
                        break;
        }
        return ret;
}

int
glusterd_op_xquota (dict_t *dict, char **op_errstr, dict_t *rsp_dict)
{
        glusterd_volinfo_t     *volinfo      = NULL;
        int32_t                 ret          = -1;
        char                   *volname      = NULL;
        int                     type         = -1;
        glusterd_conf_t        *priv         = NULL;
        xlator_t               *this         = NULL;

        GF_ASSERT (dict);
        GF_ASSERT (op_errstr);

        this = THIS;
        GF_ASSERT (this);
        priv = this->private;
        GF_ASSERT (priv);

        ret = dict_get_str (dict, "volname", &volname);
        if (ret) {
                gf_msg (this->name, GF_LOG_ERROR, 0,
                        GD_MSG_DICT_GET_FAILED, "Unable to get volume name");
                goto out;
        }

        ret = glusterd_volinfo_find (volname, &volinfo);
        if (ret) {
                gf_asprintf (op_errstr, FMTSTR_CHECK_VOL_EXISTS, volname);
                goto out;
        }

        ret = dict_get_int32 (dict, "type", &type);

        if (!glusterd_is_xquota_supported (type, op_errstr)) {
                ret = -1;
                goto out;
        }

        switch (type) {
                case GF_XQUOTA_OPTION_TYPE_ENABLE:
                        ret = glusterd_xquota_enable (volinfo, op_errstr);
                        if (ret < 0)
                                goto out;
                        break;

                case GF_XQUOTA_OPTION_TYPE_DISABLE:
                        ret = glusterd_xquota_disable (volinfo, op_errstr);
                        if (ret < 0)
                                goto out;

                        break;

                case GF_XQUOTA_OPTION_TYPE_PROJECT_LIMIT_USAGE:
                        ret = glusterd_xquota_limit_usage (volinfo, dict, type,
                                                           op_errstr);
                        goto out;

                case GF_XQUOTA_OPTION_TYPE_PROJECT_REMOVE_USAGE:
                        ret = glusterd_xquota_remove_limits (volinfo, dict, type,
                                                             op_errstr);
                        goto out;

                case GF_XQUOTA_OPTION_TYPE_PROJECT_LIST_USAGE:
                        ret = glusterd_check_if_xquota_trans_enabled (volinfo);
                        if (ret == -1) {
                                *op_errstr = gf_strdup ("Cannot list limits, "
                                                        "xquota is disabled");
                                goto out;
                        }
                        ret = glusterd_xquota_get_default_soft_limit (volinfo,
                                                                      rsp_dict);
                        goto out;

                case GF_XQUOTA_OPTION_TYPE_SOFT_TIMEOUT:
                        ret = glusterd_set_xquota_option (volinfo, dict,
                                                          "features.xquota-soft-timeout",
                                                          op_errstr);
                        if (ret)
                                goto out;
                        break;

                case GF_XQUOTA_OPTION_TYPE_HARD_TIMEOUT:
                        ret = glusterd_set_xquota_option (volinfo, dict,
                                                          "features.xquota-hard-timeout",
                                                          op_errstr);
                        if (ret)
                                goto out;
                        break;

                case GF_XQUOTA_OPTION_TYPE_ALERT_TIME:
                        ret = glusterd_set_xquota_option (volinfo, dict,
                                                          "features.xquota-alert-time",
                                                          op_errstr);
                        if (ret)
                                goto out;
                        break;

                case GF_XQUOTA_OPTION_TYPE_DEFAULT_SOFT_LIMIT:
                        ret = glusterd_set_xquota_option (volinfo, dict,
                                                          "features.xquota-default-soft-limit",
                                                          op_errstr);
                        if (ret)
                                goto out;
                        break;

                default:
                        gf_asprintf (op_errstr, "XQuota command failed. Invalid "
                                     "opcode");
                        ret = -1;
                        goto out;
        }

        if (priv->op_version > GD_OP_VERSION_MIN) {
                ret = glusterd_xquotad_op (type);
                if (ret)
                        goto out;
        }


        if (GF_XQUOTA_OPTION_TYPE_ENABLE == type)
                volinfo->xquota_xattr_version++;
        ret = glusterd_store_volinfo (volinfo,
                                      GLUSTERD_VOLINFO_VER_AC_INCREMENT);
        if (ret) {
                if (GF_XQUOTA_OPTION_TYPE_ENABLE == type)
                        volinfo->xquota_xattr_version--;
                goto out;
        }

        ret = glusterd_create_volfiles_and_notify_services (volinfo);
        if (ret) {
                gf_msg (this->name, GF_LOG_ERROR, 0,
                        GD_MSG_VOLFILE_CREATE_FAIL, "Unable to re-create "
                                                  "volfiles");
                if (GF_XQUOTA_OPTION_TYPE_ENABLE == type) {
                        /* rollback volinfo */
                        volinfo->xquota_xattr_version--;
                        ret = glusterd_store_volinfo (volinfo,
                                                      GLUSTERD_VOLINFO_VER_AC_INCREMENT);
                }

                ret = -1;
                goto out;
        }

        if (GLUSTERD_STATUS_STARTED == volinfo->status) {
                if (priv->op_version == GD_OP_VERSION_MIN)
                        ret = priv->nfs_svc.manager (&(priv->nfs_svc), NULL, 0);
        }

        ret = 0;
out:
        return ret;
}

/*
 * glusterd_get_gfid_from_brick() fetches the 'trusted.gfid' attribute of @path
 * from each brick in the backend and places the same in the rsp_dict with the
 * keys being gfid0, gfid1, gfid2 and so on. The absence of @path in the backend
 * is not treated as error.
 */
static int
glusterd_get_gfid_from_brick (dict_t *dict, glusterd_volinfo_t *volinfo,
                              dict_t *rsp_dict, char **op_errstr)
{
        int                    ret                    = -1;
        int                    count                  = 0;
        char                  *path                   = NULL;
        char                   backend_path[PATH_MAX] = {0,};
        xlator_t              *this                   = NULL;
        glusterd_conf_t       *priv                   = NULL;
        glusterd_brickinfo_t  *brickinfo              = NULL;
        char                   key[256]               = {0,};
        char                  *gfid_str               = NULL;
        uuid_t                 gfid;

        this = THIS;
        GF_ASSERT (this);
        priv = this->private;
        GF_ASSERT (priv);

        ret = dict_get_str (dict, "path", &path);
        if (ret) {
                gf_msg (this->name, GF_LOG_ERROR, 0,
                        GD_MSG_DICT_GET_FAILED, "Failed to get path");
                goto out;
        }

        cds_list_for_each_entry (brickinfo, &volinfo->bricks, brick_list) {
                ret = glusterd_resolve_brick (brickinfo);
                if (ret) {
                        gf_msg (this->name, GF_LOG_ERROR, 0,
                                GD_MSG_RESOLVE_BRICK_FAIL, FMTSTR_RESOLVE_BRICK,
                                brickinfo->hostname, brickinfo->path);
                        goto out;
                }

                if (gf_uuid_compare (brickinfo->uuid, MY_UUID))
                        continue;

                if (brickinfo->vg[0])
                        continue;

                snprintf (backend_path, sizeof (backend_path), "%s%s",
                          brickinfo->path, path);

                ret = gf_lstat_dir (backend_path, NULL);
                if (ret) {
                        gf_msg (this->name, GF_LOG_INFO, errno,
                                GD_MSG_DIR_OP_FAILED, "Failed to find "
                                "directory %s.", backend_path);
                        ret = 0;
                        continue;
                }
                ret = sys_lgetxattr (backend_path, GFID_XATTR_KEY, gfid, 16);
                if (ret < 0) {
                        gf_msg (this->name, GF_LOG_INFO, errno,
                                GD_MSG_SETXATTR_FAIL, "Failed to get "
                                "extended attribute %s for directory %s. ",
                                GFID_XATTR_KEY, backend_path);
                        ret = 0;
                        continue;
                }
                snprintf (key, sizeof (key), "gfid%d", count);

                gfid_str = gf_strdup (uuid_utoa (gfid));
                if (!gfid_str) {
                        ret = -1;
                        goto out;
                }

                ret = dict_set_dynstr (rsp_dict, key, gfid_str);
                if (ret) {
                        gf_msg (this->name, GF_LOG_ERROR, 0,
                                GD_MSG_DICT_SET_FAILED, "Failed to place "
                                "gfid of %s in dict", backend_path);
                        GF_FREE (gfid_str);
                        goto out;
                }
                count++;
        }

        ret = dict_set_int32 (rsp_dict, "count", count);
        if (ret) {
                gf_msg (this->name, GF_LOG_ERROR, 0,
                        GD_MSG_DICT_SET_FAILED, "Failed to set count");
                goto out;
        }

        ret = 0;
out:
        return ret;
}

static int
_glusterd_validate_xquota_opts (dict_t *dict, int type, char **errstr)
{
        int                     ret = -1;
        xlator_t                *this = THIS;
        void                    *xquota_xl = NULL;
        volume_opt_list_t       opt_list = {{0},};
        volume_option_t         *opt = NULL;
        char                    *key = NULL;
        char                    *value = NULL;

        GF_ASSERT (dict);
        GF_ASSERT (this);

        ret = xlator_volopt_dynload ("features/xquota", &xquota_xl, &opt_list);
        if (ret)
                goto out;

        switch (type) {
        case GF_XQUOTA_OPTION_TYPE_SOFT_TIMEOUT:
        case GF_XQUOTA_OPTION_TYPE_HARD_TIMEOUT:
        case GF_XQUOTA_OPTION_TYPE_ALERT_TIME:
        case GF_XQUOTA_OPTION_TYPE_DEFAULT_SOFT_LIMIT:
                key = (char *)gd_xquota_op_list[type];
                break;
        default:
                ret = -1;
                goto out;
        }

        opt = xlator_volume_option_get_list (&opt_list, key);
        if (!opt) {
                ret = -1;
                gf_msg (this->name, GF_LOG_ERROR, EINVAL,
                        GD_MSG_UNKNOWN_KEY, "Unknown option: %s", key);
                goto out;
        }
        ret = dict_get_str (dict, "value", &value);
        if (ret) {
                gf_msg (this->name, GF_LOG_ERROR, 0,
                        GD_MSG_DICT_GET_FAILED, "Value not found for key %s",
                        key);
                goto out;
        }

        ret = xlator_option_validate (this, key, value, opt, errstr);

out:
        if (xquota_xl) {
                dlclose (xquota_xl);
                xquota_xl = NULL;
        }
        return ret;
}

int
glusterd_op_stage_xquota (dict_t *dict, char **op_errstr, dict_t *rsp_dict)
{
        int                 ret            = 0;
        char               *volname        = NULL;
        gf_boolean_t        exists         = _gf_false;
        int                 type           = 0;
        xlator_t           *this           = NULL;
        glusterd_conf_t    *priv           = NULL;
        glusterd_volinfo_t *volinfo        = NULL;
        char               *hard_limit_str = NULL;
        int64_t             hard_limit     = 0;
        gf_boolean_t        get_gfid       = _gf_false;

        this = THIS;
        GF_ASSERT (this);
        priv = this->private;
        GF_ASSERT (priv);

        GF_ASSERT (dict);
        GF_ASSERT (op_errstr);

        ret = dict_get_str (dict, "volname", &volname);
        if (ret) {
                gf_msg (this->name, GF_LOG_ERROR, 0,
                        GD_MSG_DICT_GET_FAILED, "Unable to get volume name");
                goto out;
        }

        exists = glusterd_check_volume_exists (volname);
        if (!exists) {
                gf_asprintf (op_errstr, FMTSTR_CHECK_VOL_EXISTS, volname);
                ret = -1;
                goto out;
        }
        ret = glusterd_volinfo_find (volname, &volinfo);
        if (ret) {
                gf_asprintf (op_errstr, FMTSTR_CHECK_VOL_EXISTS, volname);
                goto out;
        }

        if (!glusterd_is_volume_started (volinfo)) {
                *op_errstr = gf_strdup ("Volume is stopped, start volume "
                                        "before executing xquota command.");
                ret = -1;
                goto out;
        }

        ret = dict_get_int32 (dict, "type", &type);
        if (ret) {
                *op_errstr = gf_strdup ("Volume xquota failed, internal error, "
                                        "unable to get type of operation");
                goto out;
        }

        if ((!glusterd_is_volume_xquota_enabled (volinfo)) &&
            (type != GF_XQUOTA_OPTION_TYPE_ENABLE)) {
                *op_errstr = gf_strdup ("XQuota is disabled, please enable "
                                        "xquota");
                ret = -1;
                goto out;
        }

        if (!glusterd_is_xquota_supported (type, op_errstr)) {
                ret = -1;
                goto out;
        }

        if ((GF_XQUOTA_OPTION_TYPE_ENABLE != type) &&
            (glusterd_check_if_xquota_trans_enabled (volinfo) != 0)) {
                ret = -1;
                gf_asprintf (op_errstr, "XQuota is not enabled on volume %s",
                             volname);
                goto out;
        }

        switch (type) {
        case GF_XQUOTA_OPTION_TYPE_PROJECT_LIMIT_USAGE:
                ret = dict_get_str (dict, "hard-limit", &hard_limit_str);
                if (ret) {
                        gf_msg (this->name, GF_LOG_ERROR, 0,
                                GD_MSG_DICT_GET_FAILED,
                                "Failed to get hard-limit from dict");
                        goto out;
                }
                ret = gf_string2bytesize_int64 (hard_limit_str, &hard_limit);
                if (ret) {
                        if (errno == ERANGE || hard_limit < 0)
                                gf_asprintf (op_errstr, "Hard-limit "
                                        "value out of range (0 - %"PRId64
                                        "): %s", hard_limit_str);
                        else
                                gf_msg (this->name, GF_LOG_ERROR, errno,
                                        GD_MSG_CONVERSION_FAILED,
                                        "Failed to convert hard-limit "
                                        "string to value");
                        goto out;
                }
                get_gfid = _gf_true;
                break;

        case GF_XQUOTA_OPTION_TYPE_PROJECT_REMOVE_USAGE:
                get_gfid = _gf_true;
                break;

        case GF_XQUOTA_OPTION_TYPE_SOFT_TIMEOUT:
        case GF_XQUOTA_OPTION_TYPE_HARD_TIMEOUT:
        case GF_XQUOTA_OPTION_TYPE_ALERT_TIME:
        case GF_XQUOTA_OPTION_TYPE_DEFAULT_SOFT_LIMIT:
                ret = _glusterd_validate_xquota_opts (dict, type, op_errstr);
                if (ret)
                        goto out;
                break;

        default:
                break;
        }

        if (get_gfid == _gf_true) {
                ret = glusterd_get_gfid_from_brick (dict, volinfo, rsp_dict,
                                                    op_errstr);
                if (ret)
                        goto out;
        }

        ret = 0;

 out:
        if (ret && op_errstr && *op_errstr)
                gf_msg (this->name, GF_LOG_ERROR, 0,
                        GD_MSG_OP_STAGE_XQUOTA_FAIL, "%s", *op_errstr);
        gf_msg_debug (this->name, 0, "Returning %d", ret);

         return ret;
}
