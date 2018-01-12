#include "common-utils.h"
#include "cli1-xdr.h"
#include "xdr-generic.h"
#include "glusterd.h"
#include "glusterd-op-sm.h"
#include "glusterd-store.h"
#include "glusterd-utils.h"
#include "glusterd-volgen.h"
#include "glusterd-messages.h"
#include "run.h"
#include "syscall.h"
#include "byte-order.h"
#include "compat-errno.h"
#include "worm-common-utils.h"
#include "glusterd-worm.h"

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

/* Any negative pid to make it special client */
#define WORM_CRAWL_PID "-200"

const char *gd_worm_op_list[GF_WORM_OPTION_TYPE_MAX + 1] = {
        [GF_WORM_OPTION_TYPE_NONE]               = "none",
        [GF_WORM_OPTION_TYPE_ENABLE]             = "enable",
        [GF_WORM_OPTION_TYPE_DISABLE]            = "disable",
        [GF_WORM_OPTION_TYPE_SET]                = "set",
        [GF_WORM_OPTION_TYPE_GET]                = "get",
        [GF_WORM_OPTION_TYPE_CLEAR]              = "clear",
        [GF_WORM_OPTION_TYPE_LIST]               = "list",
        [GF_WORM_OPTION_TYPE_MAX]                = NULL
};

int
__glusterd_handle_worm (rpcsvc_request_t *req)
{
        int32_t                         ret = -1;
        gf_cli_req                      cli_req = {{0,}};
        dict_t                         *dict = NULL;
        glusterd_op_t                   cli_op = GD_OP_WORM;
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
                req->rpc_err = GARBAGE_ARGS;
                goto out;
        }

        if (cli_req.dict.dict_len) {
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
                        "while handling worm command");
                goto out;
        }

        ret = dict_get_int32 (dict, "type", &type);
        if (ret) {
                snprintf (msg, sizeof (msg), "Unable to get type of command");
                gf_msg (this->name, GF_LOG_ERROR, 0,
                        GD_MSG_DICT_GET_FAILED, "Unable to get type of cmd, "
                        "while handling worm command");
                goto out;
        }

        ret = glusterd_op_begin_synctask (req, GD_OP_WORM, dict);

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
glusterd_handle_worm (rpcsvc_request_t *req)
{
        return glusterd_big_locked_handler (req, __glusterd_handle_worm);
}

int32_t
glusterd_check_if_worm_trans_enabled (glusterd_volinfo_t *volinfo)
{
        int32_t  ret           = 0;
        int      flag          = _gf_false;

        flag = glusterd_volinfo_get_boolean (volinfo, VKEY_FEATURES_WORM);
        if (flag == -1) {
                gf_msg ("glusterd", GF_LOG_ERROR, 0,
                        GD_MSG_WORM_GET_STAT_FAIL,
                        "failed to get the worm status");
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


#if 0
int32_t
_glusterd_worm_initiate_fs_crawl (glusterd_conf_t *priv,
                                  glusterd_volinfo_t *volinfo,
                                  glusterd_brickinfo_t *brick, int type,
                                  char *pid_dir)
{
        pid_t                      pid;
        int32_t                    ret                 = -1;
        int                        status              = 0;
        char                       mountdir[PATH_MAX]  = {0,};
        char                       logfile[PATH_MAX]   = {0,};
        char                       brickpath[PATH_MAX] = {0,};
        char                       vol_id[PATH_MAX]    = {0,};
        char                       pidfile[PATH_MAX]   = {0,};
        runner_t                   runner              = {0};
        char                      *volfileserver       = NULL;
        FILE                      *pidfp               = NULL;

        GF_VALIDATE_OR_GOTO ("glusterd", THIS, out);

        GLUSTERD_GET_TMP_PATH (mountdir, "/");
        ret = sys_mkdir (mountdir, 0777);
        if (ret && errno != EEXIST) {
                gf_msg (THIS->name, GF_LOG_WARNING, errno,
                        GD_MSG_MOUNT_REQ_FAIL, "failed to create temporary "
                        "directory %s", mountdir);
                ret = -1;
                goto out;
        }

        strcat (mountdir, "mntYYYYYY");
        if (mkdtemp (mountdir) == NULL) {
                gf_msg (THIS->name, GF_LOG_WARNING, errno,
                        GD_MSG_MOUNT_REQ_FAIL, "failed to create a temporary "
                        "mount directory: %s", mountdir);
                ret = -1;
                goto out;
        }

        GLUSTERD_REMOVE_SLASH_FROM_PATH (brick->path, brickpath);
        snprintf (logfile, sizeof (logfile),
                  DEFAULT_WORM_CRAWL_LOG_DIRECTORY"/%s.log",
                  brickpath);

        if (dict_get_str (THIS->options, "transport.socket.bind-address",
                          &volfileserver) != 0)
                volfileserver = "localhost";

        snprintf (vol_id, sizeof (vol_id), "client_per_brick/%s.%s.%s.%s.vol",
                  volinfo->volname, "client", brick->hostname, brickpath);

        runinit (&runner);

        if (type == GF_WORM_OPTION_TYPE_ENABLE)
                runner_add_args (&runner, SBIN_DIR"/glusterfs",
                                 "-s", volfileserver,
                                 "--volfile-id", vol_id,
                                 "--use-readdirp=yes",
                                 "--client-pid", WORM_CRAWL_PID,
                                 "-l", logfile, mountdir, NULL);
        else
                runner_add_args (&runner, SBIN_DIR"/glusterfs",
                                 "-s", volfileserver,
                                 "--volfile-id", vol_id,
                                 "--use-readdirp=no",
                                 "--client-pid", WORM_CRAWL_PID,
                                 "-l", logfile, mountdir, NULL);

        synclock_unlock (&priv->big_lock);
        ret = runner_run_reuse (&runner);
        synclock_lock (&priv->big_lock);
        if (ret == -1) {
                runner_log (&runner, "glusterd", GF_LOG_DEBUG, "command failed");
                runner_end (&runner);
                goto out;
        }
        runner_end (&runner);

        if ((pid = fork ()) < 0) {
                gf_msg (THIS->name, GF_LOG_WARNING, 0,
                        GD_MSG_FORK_FAIL, "fork from parent failed");
                gf_umount_lazy ("glusterd", mountdir, 1);
                ret = -1;
                goto out;
        } else if (pid == 0) {//first child
                /* fork one more to not hold back main process on
                 * blocking call below
                 */
                pid = fork ();
                if (pid < 0) {
                        gf_umount_lazy ("glusterd", mountdir, 1);
                        _exit (EXIT_FAILURE);
                } else if (pid > 0) {
                        _exit (EXIT_SUCCESS);
                }

                ret = chdir (mountdir);
                if (ret == -1) {
                        gf_msg (THIS->name, GF_LOG_WARNING, errno,
                                GD_MSG_DIR_OP_FAILED, "chdir %s failed",
                                mountdir);
                        gf_umount_lazy ("glusterd", mountdir, 1);
                        exit (EXIT_FAILURE);
                }
                runinit (&runner);

                if (type == GF_WORM_OPTION_TYPE_ENABLE)
                        runner_add_args (&runner, "/usr/bin/find", ".", NULL);

                else if (type == GF_WORM_OPTION_TYPE_DISABLE) {

#if defined(GF_DARWIN_HOST_OS)
                        runner_add_args (&runner, "/usr/bin/find", ".",
                                         "-exec", "/usr/bin/xattr", "-w",
                                         VIRTUAL_WORM_XATTR_CLEANUP_KEY, "1",
                                         "{}", "\\", ";", NULL);
#elif defined(__FreeBSD__)
                        runner_add_args (&runner, "/usr/bin/find", ".",
                                         "-exec", "/usr/sbin/setextattr",
                                         EXTATTR_NAMESPACE_USER,
                                         VIRTUAL_WORM_XATTR_CLEANUP_KEY, "1",
                                         "{}", "\\", ";", NULL);
#else
                        runner_add_args (&runner, "/usr/bin/find", ".",
                                         "-exec", _PATH_SETFATTR, "-n",
                                         VIRTUAL_WORM_XATTR_CLEANUP_KEY, "-v",
                                         "1", "{}", "\\", ";", NULL);
#endif

                }

                if (runner_start (&runner) == -1) {
                        gf_umount_lazy ("glusterd", mountdir, 1);
                        _exit (EXIT_FAILURE);
                }

                snprintf (pidfile, sizeof (pidfile), "%s/%s.pid", pid_dir,
                          brickpath);
                pidfp = fopen (pidfile, "w");
                if (pidfp) {
                        fprintf (pidfp, "%d\n", runner.chpid);
                        fflush (pidfp);
                        fclose (pidfp);
                }

#ifndef GF_LINUX_HOST_OS
                runner_end (&runner); /* blocks in waitpid */
#endif
                gf_umount_lazy ("glusterd", mountdir, 1);

                _exit (EXIT_SUCCESS);
        }
        ret = (waitpid (pid, &status, 0) == pid &&
               WIFEXITED (status) && WEXITSTATUS (status) == EXIT_SUCCESS) ? 0 : -1;

out:
        return ret;
}

void
glusterd_stop_all_worm_crawl_service (glusterd_conf_t *priv,
                                      glusterd_volinfo_t *volinfo, int type)
{
        DIR                       *dir                = NULL;
        struct dirent             *entry              = NULL;
        struct dirent              scratch[2]         = {{0,},};
        char                       pid_dir[PATH_MAX]  = {0,};
        char                       pidfile[PATH_MAX]  = {0,};

        GLUSTERD_GET_WORM_CRAWL_PIDDIR (pid_dir, volinfo, type);

        dir = sys_opendir (pid_dir);
        if (dir == NULL)
                return;

        GF_SKIP_IRRELEVANT_ENTRIES (entry, dir, scratch);
        while (entry) {
                snprintf (pidfile, sizeof (pidfile), "%s/%s",
                          pid_dir, entry->d_name);

                glusterd_service_stop_nolock ("worm_crawl", pidfile, SIGKILL,
                                              _gf_true);
                sys_unlink (pidfile);

                GF_SKIP_IRRELEVANT_ENTRIES (entry, dir, scratch);
        }
        sys_closedir (dir);
}

int32_t
glusterd_worm_initiate_fs_crawl (glusterd_conf_t *priv,
                                 glusterd_volinfo_t *volinfo, int type)
{
        int32_t                    ret                = -1;
        glusterd_brickinfo_t      *brick              = NULL;
        char                       pid_dir[PATH_MAX]  = {0, };

        GF_VALIDATE_OR_GOTO ("glusterd", THIS, out);

        ret = glusterd_generate_client_per_brick_volfile (volinfo);
        if (ret) {
                gf_msg (THIS->name, GF_LOG_ERROR, 0,
                        GD_MSG_GLUSTERD_OP_FAILED,
                        "failed to generate client volume file");
                goto out;
        }

        ret = mkdir_p (DEFAULT_WORM_CRAWL_LOG_DIRECTORY, 0777, _gf_true);
        if (ret) {
                gf_msg (THIS->name, GF_LOG_ERROR, errno,
                        GD_MSG_GLUSTERD_OP_FAILED,
                        "failed to create dir %s: %s",
                        DEFAULT_WORM_CRAWL_LOG_DIRECTORY, strerror (errno));
                goto out;
        }

        GLUSTERD_GET_WORM_CRAWL_PIDDIR (pid_dir, volinfo, type);
        ret = mkdir_p (pid_dir, 0777, _gf_true);
        if (ret) {
                gf_msg (THIS->name, GF_LOG_ERROR, errno,
                        GD_MSG_GLUSTERD_OP_FAILED,
                        "failed to create dir %s: %s",
                        pid_dir, strerror (errno));
                goto out;
        }

        glusterd_stop_all_worm_crawl_service (priv, volinfo,
                                              GF_WORM_OPTION_TYPE_ENABLE);
        if (type == GF_WORM_OPTION_TYPE_DISABLE)
                glusterd_stop_all_worm_crawl_service (priv, volinfo,
                                              GF_WORM_OPTION_TYPE_DISABLE);

        cds_list_for_each_entry (brick, &volinfo->bricks, brick_list) {
                if (gf_uuid_compare (brick->uuid, MY_UUID))
                        continue;

                ret = _glusterd_worm_initiate_fs_crawl (priv, volinfo, brick,
                                                        type, pid_dir);

                if (ret)
                        goto out;
        }

        ret = 0;
out:
        return ret;
}
#endif

int32_t
glusterd_worm_enable (glusterd_volinfo_t *volinfo, char **op_errstr)
{
        int32_t         ret     = -1;
        xlator_t        *this   = NULL;

        this = THIS;
        GF_ASSERT (this);

        GF_VALIDATE_OR_GOTO (this->name, volinfo, out);
        GF_VALIDATE_OR_GOTO (this->name, op_errstr, out);

        if (glusterd_is_volume_started (volinfo) == 0) {
                *op_errstr = gf_strdup ("Volume is stopped, start volume "
                                        "to enable worm.");
                ret = -1;
                goto out;
        }

        ret = glusterd_check_if_worm_trans_enabled (volinfo);
        if (ret == 0) {
                *op_errstr = gf_strdup ("Worm is already enabled");
                ret = -1;
                goto out;
        }

        ret = dict_set_dynstr_with_alloc (volinfo->dict, VKEY_FEATURES_WORM,
                                          "on");
        if (ret) {
                gf_msg (this->name, GF_LOG_ERROR, errno,
                        GD_MSG_DICT_SET_FAILED, "dict set failed");
                goto out;
        }

        ret = glusterd_store_worm_config (volinfo, NULL, NULL,
                                          GF_WORM_OPTION_TYPE_ENABLE,
                                          op_errstr);

        ret = 0;
out:
        if (ret && op_errstr && !*op_errstr)
                gf_asprintf (op_errstr, "Enabling worm on volume %s has been "
                             "unsuccessful", volinfo->volname);
        return ret;
}

int32_t
glusterd_worm_disable (glusterd_volinfo_t *volinfo, char **op_errstr)
{
        int32_t    ret            = -1;
        xlator_t  *this           = NULL;
        glusterd_conf_t *conf     = NULL;

        this = THIS;
        GF_ASSERT (this);
        conf = this->private;
        GF_ASSERT (conf);

        GF_VALIDATE_OR_GOTO (this->name, volinfo, out);
        GF_VALIDATE_OR_GOTO (this->name, op_errstr, out);

        ret = glusterd_check_if_worm_trans_enabled (volinfo);
        if (ret == -1) {
                *op_errstr = gf_strdup ("Worm is already disabled");
                goto out;
        }

        ret = dict_set_dynstr_with_alloc (volinfo->dict, VKEY_FEATURES_WORM,
                                          "off");
        if (ret) {
                gf_msg (this->name, GF_LOG_ERROR, errno,
                        GD_MSG_DICT_SET_FAILED, "dict set failed");
                goto out;
        }

        (void) glusterd_clean_up_worm_store (volinfo);

        ret = 0;
out:
        if (ret && op_errstr && !*op_errstr)
                gf_asprintf (op_errstr, "Disabling worm on volume %s has been "
                             "unsuccessful", volinfo->volname);
        return ret;
}

static int
_glusterd_worm_set (char *volname, char *path, char *start,
                    char *dura, char *key,
                    char **op_errstr)
{
        int               ret                = -1;
        xlator_t         *this               = NULL;
        char              abspath[PATH_MAX]  = {0,};
        glusterd_conf_t  *priv               = NULL;
	worm_meta_t       new_meta           = {0,};

        this = THIS;
        GF_ASSERT (this);
        priv = this->private;
        GF_ASSERT (priv);

        GLUSTERD_GET_WORM_MOUNT_PATH (abspath, volname, path);
        ret = gf_lstat_dir (abspath, NULL);
        if (ret) {
                gf_asprintf (op_errstr, "Failed to find the directory %s. "
                             "Reason : %s", abspath, strerror (errno));
                goto out;
        }

        ret = gf_string2int64 (start, &new_meta.start);
        if (ret)
                goto out;
        new_meta.start = hton64(new_meta.start);

        ret = gf_string2int64 (dura, &new_meta.dura);
        if (ret)
                goto out;
        new_meta.dura = hton64(new_meta.dura);

        ret = sys_lsetxattr (abspath, key, (char *)(void *)&new_meta,
                             sizeof (new_meta), 0);
        if (ret == -1) {
                gf_asprintf (op_errstr, "setxattr of %s failed on %s."
                             " Reason : %s", key, abspath, strerror (errno));
                goto out;
        }
        ret = 0;

out:
        return ret;
}

static gf_boolean_t
glusterd_find_gfid_match (uuid_t gfid, char gfid_type, unsigned char *buf,
                          size_t bytes_read, int opcode,
                          size_t *write_byte_count)
{
        int                 gfid_index  = 0;
        int                 shift_count = 0;
        unsigned char       tmp_buf[17] = {0,};
        xlator_t           *this        = NULL;
        glusterd_conf_t    *conf        = NULL;

        this = THIS;
        GF_VALIDATE_OR_GOTO ("glusterd", this, out);

        conf = this->private;
        GF_VALIDATE_OR_GOTO (this->name, conf, out);

        while (gfid_index != bytes_read) {
                memcpy ((void *)tmp_buf, (void *)&buf[gfid_index], 16);
                if (!gf_uuid_compare (gfid, tmp_buf)) {
                        if (opcode == GF_WORM_OPTION_TYPE_CLEAR) {
                                shift_count = bytes_read - (gfid_index + 16);
                                memmove ((void *)&buf[gfid_index],
                                         (void *)&buf[gfid_index+16],
                                         shift_count);
                                *write_byte_count = bytes_read - 16;
                        } else {
                                *write_byte_count = bytes_read;
                        }
                        return _gf_true;
                } else {
                        gfid_index += 16;
                }
        }
        if (gfid_index == bytes_read)
                *write_byte_count = bytes_read;

out:

        return _gf_false;
}

/* The function glusterd_copy_to_tmp_file() reads the "remaining" bytes from
 * the source fd and writes them to destination fd, at the rate of 1000 entries
 * a time (wconf_line_sz is the size of an entry)
 */

static int
glusterd_copy_to_tmp_file (int src_fd, int dst_fd, int wconf_line_sz)
{
        int            ret         = 0;
        ssize_t        bytes_read  = 0;
        xlator_t      *this        = NULL;
        unsigned char  *buf        = 0;
        int            buf_sz      = wconf_line_sz * 1000;

        this = THIS;
        GF_ASSERT (this);
        GF_ASSERT (buf_sz > 0);

        buf = GF_CALLOC(buf_sz, 1, gf_common_mt_char);
        if (!buf) {
                ret = -1;
                goto out;
        }

        while ((bytes_read = sys_read (src_fd, buf, buf_sz)) > 0) {
                if (bytes_read % wconf_line_sz != 0) {
                        gf_msg (this->name, GF_LOG_ERROR, 0,
                                GD_MSG_WORM_CONF_CORRUPT, "worm.conf "
                                "corrupted");
                        ret = -1;
                        goto out;
                }
                ret = sys_write (dst_fd, (void *) buf, bytes_read);
                if (ret == -1) {
                        gf_msg (this->name, GF_LOG_ERROR, errno,
                                GD_MSG_WORM_CONF_WRITE_FAIL,
                                "write into worm.conf failed.");
                        goto out;
                }
        }
        ret = 0;

out:
        if (buf)
                GF_FREE(buf);
        return ret;
}

int
glusterd_store_worm_config (glusterd_volinfo_t *volinfo, char *path,
                            char *gfid_str, int opcode, char **op_errstr)
{
        int                ret                   = -1;
        int                fd                    = -1;
        int                conf_fd               = -1;
        ssize_t            bytes_read            = 0;
        size_t             bytes_to_write        = 0;
        uuid_t             gfid                  = {0,};
        xlator_t          *this                  = NULL;
        gf_boolean_t       found                 = _gf_false;
        gf_boolean_t       is_file_empty         = _gf_false;
        gf_boolean_t       is_first_read         = _gf_true;
        glusterd_conf_t   *conf                  = NULL;
        char               type                  = GF_WORM_CONF_TYPE_DIR;
        int                worm_conf_line_sz     = 16;
        unsigned char      *buf                  = 0;
        int                buf_sz                = 0;

        this = THIS;
        GF_ASSERT (this);
        conf = this->private;
        GF_ASSERT (conf);

        glusterd_store_create_worm_conf_sh_on_absence (volinfo);

        conf_fd = open (volinfo->worm_conf_shandle->path, O_RDONLY);
        if (conf_fd == -1) {
                goto out;
        }

        ret = worm_conf_skip_header (conf_fd);
        if (ret)
                goto out;

        buf_sz = worm_conf_line_sz * 1000;

        buf = GF_CALLOC(buf_sz, 1, gf_common_mt_char);
        if (!buf) {
                ret = -1;
                goto out;
        }

        fd = gf_store_mkstemp (volinfo->worm_conf_shandle);
        if (fd < 0) {
                ret = -1;
                goto out;
        }

        ret = glusterd_worm_conf_write_header (fd);
        if (ret)
                goto out;


        /* Just create empty worm.conf file if create */
        if (GF_WORM_OPTION_TYPE_ENABLE == opcode) {
                goto out;
        }

        /* Check if gfid_str is given for opts other than ENABLE */
        if (!gfid_str) {
                ret = -1;
                goto out;
        }
        gf_uuid_parse (gfid_str, gfid);

        for (;;) {
                bytes_read = sys_read (conf_fd, buf, buf_sz);
                if (bytes_read <= 0) {
                        /*The flag @is_first_read is TRUE when the loop is
                         * entered, and is set to false if the first read
                         * reads non-zero bytes of data. The flag is used to
                         * detect if worm.conf is an empty file, but for the
                         * header. This is done to log appropriate error message
                         * when 'worm clear' is attempted when there are no
                         * limits set on the given volume.
                         */
                        if (is_first_read)
                                is_file_empty = _gf_true;
                        break;
                }
                if ((bytes_read % worm_conf_line_sz) != 0) {
                        gf_msg (this->name, GF_LOG_ERROR, 0,
                                GD_MSG_WORM_CONF_CORRUPT, "worm.conf "
                                "corrupted");
                        ret = -1;
                        goto out;
                }
                found = glusterd_find_gfid_match (gfid, type, buf, bytes_read,
                                                  opcode, &bytes_to_write);

                ret = sys_write (fd, (void *) buf, bytes_to_write);
                if (ret == -1) {
                        gf_msg (this->name, GF_LOG_ERROR, errno,
                                GD_MSG_WORM_CONF_WRITE_FAIL,
                                "write into worm.conf failed.");
                        goto out;
                }

                /*If the match is found in this iteration, copy the rest of
                 * worm.conf into worm.conf.tmp and break.
                 * Else continue with the search.
                 */
                if (found) {
                        ret = glusterd_copy_to_tmp_file (conf_fd, fd,
                                                         worm_conf_line_sz);
                        if (ret)
                                goto out;
                        break;
                }
                is_first_read = _gf_false;
        }

        switch (opcode) {
        case GF_WORM_OPTION_TYPE_SET:
                if (!found) {
                        ret = glusterd_worm_conf_write_gfid (fd, gfid);
                        if (ret == -1) {
                                gf_msg (this->name, GF_LOG_ERROR, errno,
                                        GD_MSG_WORM_CONF_WRITE_FAIL,
                                        "write into worm.conf failed. ");
                                goto out;
                        }
                }
                break;

        case GF_WORM_OPTION_TYPE_CLEAR:
                if (is_file_empty) {
                        gf_asprintf (op_errstr, "Cannot clear on"
                                     " %s. The worm configuration file"
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
                        }
                }
                break;

        default:
                ret = 0;
                break;
        }

        ret = 0;
out:
        if (conf_fd != -1) {
                sys_close (conf_fd);
        }

        if (buf)
                GF_FREE(buf);

        if (ret && (fd > 0)) {
                gf_store_unlink_tmppath (volinfo->worm_conf_shandle);
        } else if (!ret) {
                ret = gf_store_rename_tmppath (volinfo->worm_conf_shandle);
        }
        return ret;
}

int32_t
glusterd_worm_set (glusterd_volinfo_t *volinfo, dict_t *dict,
                   int opcode, char **op_errstr)
{
        int32_t          ret                = -1;
        char            *path               = NULL;
        char            *start              = NULL;
        char            *dura               = NULL;
        char            *gfid_str           = NULL;
        xlator_t        *this               = NULL;

        this = THIS;
        GF_ASSERT (this);

        GF_VALIDATE_OR_GOTO (this->name, dict, out);
        GF_VALIDATE_OR_GOTO (this->name, volinfo, out);
        GF_VALIDATE_OR_GOTO (this->name, op_errstr, out);

        ret = glusterd_check_if_worm_trans_enabled (volinfo);
        if (ret == -1) {
                *op_errstr = gf_strdup ("Worm is disabled, please enable "
                                        "worm");
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

        ret = dict_get_str (dict, "start", &start);
        if (ret) {
                gf_msg (this->name, GF_LOG_ERROR, 0,
                        GD_MSG_DICT_GET_FAILED, "Unable to fetch start");
                goto out;
        }

        ret = dict_get_str (dict, "dura", &dura);
        if (ret) {
                gf_msg (this->name, GF_LOG_ERROR, 0,
                        GD_MSG_DICT_GET_FAILED, "Unable to fetch duration");
                goto out;
        }

        if (is_origin_glusterd (dict)) {
                ret = _glusterd_worm_set (volinfo->volname, path,
                                          start, dura, WORM_START_AND_DURA_KEY,
                                          op_errstr);
                if (ret)
                        goto out;
        }

        ret = dict_get_str (dict, "gfid", &gfid_str);
        if (ret) {
                gf_msg (this->name, GF_LOG_ERROR, 0,
                        GD_MSG_DICT_GET_FAILED, "Failed to get gfid of path "
                        "%s", path);
                goto out;
        }

        ret = glusterd_store_worm_config (volinfo, path, gfid_str, opcode,
                                          op_errstr);
        if (ret)
                goto out;

        ret = 0;
out:

        if (ret && op_errstr && !*op_errstr)
                gf_asprintf (op_errstr, "Failed to set worm periods on path %s "
                             "for volume %s", path, volinfo->volname);
        return ret;
}

static int
_glusterd_worm_clear (char *volname, char *path, char **op_errstr)
{
        int               ret                = -1;
        xlator_t         *this               = NULL;
        char              abspath[PATH_MAX]  = {0,};
        glusterd_conf_t  *priv               = NULL;

        this = THIS;
        GF_ASSERT (this);
        priv = this->private;
        GF_ASSERT (priv);

        GLUSTERD_GET_WORM_MOUNT_PATH (abspath, volname, path);
        ret = gf_lstat_dir (abspath, NULL);
        if (ret) {
                gf_asprintf (op_errstr, "Failed to find the directory %s. "
                             "Reason : %s", abspath, strerror (errno));
                goto out;
        }

        ret = sys_lremovexattr (abspath, WORM_START_AND_DURA_KEY);
        if (ret) {
                gf_asprintf (op_errstr, "removexattr failed on %s. "
                             "Reason : %s", abspath, strerror (errno));
                goto out;
        }

        ret = 0;

out:
        return ret;
}

int32_t
glusterd_worm_clear (glusterd_volinfo_t *volinfo, dict_t *dict,
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

        ret = glusterd_check_if_worm_trans_enabled (volinfo);
        if (ret == -1) {
                *op_errstr = gf_strdup ("Worm is disabled, please enable "
                                        "worm");
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

        if (is_origin_glusterd (dict)) {
                ret = _glusterd_worm_clear (volinfo->volname, path, op_errstr);
                if (ret)
                        goto out;
        }

        ret = dict_get_str (dict, "gfid", &gfid_str);
        if (ret) {
                gf_msg (this->name, GF_LOG_ERROR, 0,
                        GD_MSG_DICT_GET_FAILED, "Failed to get gfid of path "
                        "%s", path);
                goto out;
        }

        ret = glusterd_store_worm_config (volinfo, path, gfid_str, opcode,
                                          op_errstr);
        if (ret)
                goto out;


        ret = 0;

out:
        return ret;
}

static int
_glusterd_worm_get (char *volname, char *path, char *key,
                    char **op_errstr, dict_t *rsp_dict)
{
        int               ret                = -1;
        xlator_t         *this               = NULL;
        char              abspath[PATH_MAX]  = {0,};
        glusterd_conf_t  *priv               = NULL;
	worm_meta_t       meta               = {0,};

        this = THIS;
        GF_ASSERT (this);
        priv = this->private;
        GF_ASSERT (priv);

        GLUSTERD_GET_WORM_MOUNT_PATH (abspath, volname, path);
        ret = gf_lstat_dir (abspath, NULL);
        if (ret) {
                gf_asprintf (op_errstr, "Failed to find the directory %s. "
                             "Reason : %s", abspath, strerror (errno));
                goto out;
        }

        ret = sys_lgetxattr (abspath, key, (void *)&meta, sizeof (meta));
        if (ret < 0) {
                gf_asprintf (op_errstr, "getxattr of %s failed on %s."
                             " Reason : %s", key, abspath, strerror (errno));

                switch (errno) {
#if defined(ENODATA)
                case ENODATA:
#endif
#if defined(ENOATTR) && (ENOATTR != ENODATA)
                case ENOATTR:
#endif
                        gf_asprintf (op_errstr, "no xattr of %s found on %s."
                                     " Reason : %s", key, abspath,
                                     strerror (errno));
                        break;

                default:
                        gf_asprintf (op_errstr, "unexpected error : %s",
                                     strerror (errno));
                        break;
                }

                goto out;
        }

        meta.start = ntoh64 (meta.start);
        meta.dura  = ntoh64 (meta.dura);

        ret = dict_set_str (rsp_dict, "path", path);
        if (ret) {
                gf_asprintf (op_errstr, "failed to set path : %s",
                             strerror (errno));
                goto out;
        }

        ret = dict_set_int64 (rsp_dict, "start", meta.start);
        if (ret) {
                gf_asprintf (op_errstr, "failed to set start : %s",
                             strerror (errno));
                goto out;
        }

        ret = dict_set_int64 (rsp_dict, "dura", meta.dura);
        if (ret) {
                gf_asprintf (op_errstr, "failed to set dura : %s",
                             strerror (errno));
                goto out;
        }

        ret = 0;
out:
        return ret;
}

int32_t
glusterd_worm_get (glusterd_volinfo_t *volinfo, dict_t *dict,
                   int opcode, char **op_errstr, dict_t *rsp_dict)
{
        int32_t          ret                = -1;
        char            *path               = NULL;
        xlator_t        *this               = NULL;

        this = THIS;
        GF_ASSERT (this);

        GF_VALIDATE_OR_GOTO (this->name, dict, out);
        GF_VALIDATE_OR_GOTO (this->name, volinfo, out);
        GF_VALIDATE_OR_GOTO (this->name, op_errstr, out);
        GF_VALIDATE_OR_GOTO (this->name, rsp_dict, out);

        ret = glusterd_check_if_worm_trans_enabled (volinfo);
        if (ret == -1) {
                *op_errstr = gf_strdup ("Worm is disabled, please enable "
                                        "worm");
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

        if (is_origin_glusterd (dict)) {
                ret = _glusterd_worm_get (volinfo->volname, path,
                                          WORM_START_AND_DURA_KEY,
                                          op_errstr, rsp_dict);
                if (ret)
                        goto out;
        }

        ret = 0;
out:

        if (ret && op_errstr && !*op_errstr)
                gf_asprintf (op_errstr, "Failed to operate worm periods "
                             "on path %s for volume %s",
                             path, volinfo->volname);
        return ret;
}

int
glusterd_op_worm (dict_t *dict, char **op_errstr, dict_t *rsp_dict)
{
        glusterd_volinfo_t     *volinfo            = NULL;
        int32_t                 ret                = -1;
        char                   *volname            = NULL;
        int                     type               = -1;
//        gf_boolean_t            start_crawl        = _gf_false;
        glusterd_conf_t        *priv               = NULL;
        xlator_t               *this               = NULL;
        char                    mountdir[PATH_MAX] = {0,};

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

        switch (type) {
                case GF_WORM_OPTION_TYPE_ENABLE:
                        ret = glusterd_worm_enable (volinfo, op_errstr);
                        if (ret < 0)
                                goto out;
                        break;

                case GF_WORM_OPTION_TYPE_DISABLE:
                        ret = glusterd_worm_disable (volinfo, op_errstr);
                        if (ret < 0)
                                goto out;

                        break;

                case GF_WORM_OPTION_TYPE_SET:
                        ret = glusterd_worm_set (volinfo, dict, type,
                                                 op_errstr);
                        goto out;

                case GF_WORM_OPTION_TYPE_CLEAR:
                        ret = glusterd_worm_clear (volinfo, dict,
                                                   type, op_errstr);
                        goto out;

                case GF_WORM_OPTION_TYPE_GET:
                        ret = glusterd_worm_get (volinfo, dict, type,
                                                 op_errstr, rsp_dict);
                        goto out;

                case GF_WORM_OPTION_TYPE_LIST:
                        ret = glusterd_check_if_worm_trans_enabled (volinfo);
                        if (ret == -1) {
                                *op_errstr = gf_strdup ("Cannot list, "
                                                        "worm is disabled");
                        }
                        goto out;

                default:
                        gf_asprintf (op_errstr, "Worm command failed. Invalid "
                                     "opcode");
                        ret = -1;
                        goto out;
        }

        ret = glusterd_store_volinfo (volinfo,
                                      GLUSTERD_VOLINFO_VER_AC_INCREMENT);
        if (ret) {
                goto out;
        }

        ret = glusterd_create_volfiles_and_notify_services (volinfo);
        if (ret) {
                gf_msg (this->name, GF_LOG_ERROR, 0,
                        GD_MSG_VOLFILE_CREATE_FAIL, "Unable to re-create "
                                                  "volfiles");
                if (GF_WORM_OPTION_TYPE_ENABLE == type) {
                        /* rollback volinfo */
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

//        if (rsp_dict && start_crawl == _gf_true)
//                glusterd_worm_initiate_fs_crawl (priv, volinfo, type);

        ret = 0;
out:

        if (type == GF_WORM_OPTION_TYPE_SET ||
            type == GF_WORM_OPTION_TYPE_GET ||
            type == GF_WORM_OPTION_TYPE_CLEAR) {
                GLUSTERD_GET_WORM_MOUNT_PATH (mountdir, volname, "/");
                glusterd_remove_auxiliary_mount (volname, mountdir);
        }

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
glusterd_create_worm_auxiliary_mount (xlator_t *this, char *volname, int type)
{
        int                ret                     = -1;
        char               mountdir[PATH_MAX]      = {0,};
        char               pidfile_path[PATH_MAX]  = {0,};
        char               logfile[PATH_MAX]       = {0,};
        char               qpid[16]                = {0,};
        char              *volfileserver           = NULL;
        glusterd_conf_t   *priv                    = NULL;
        struct stat        buf                     = {0,};
        FILE              *file                    = NULL;

        GF_VALIDATE_OR_GOTO ("glusterd", this, out);
        priv = this->private;
        GF_VALIDATE_OR_GOTO (this->name, priv, out);


        GLUSTERFS_GET_WORM_MOUNT_PIDFILE (pidfile_path, volname);
        GLUSTERD_GET_WORM_MOUNT_PATH (mountdir, volname, "/");

        file = fopen (pidfile_path, "r");
        if (file) {
                /* Previous command did not clean up pid file.
                 * remove aux mount if it exists*/
                gf_umount_lazy (this->name, mountdir, 1);
                fclose(file);
        }

        ret = sys_mkdir (mountdir, 0777);
        if (ret && errno != EEXIST) {
                gf_msg (this->name, GF_LOG_ERROR, errno,
                        GD_MSG_MOUNT_REQ_FAIL, "Failed to create auxiliary "
                        "mount directory %s", mountdir);
                goto out;
        }
        snprintf (logfile, PATH_MAX-1, "%s/worm-mount-%s.log",
                  DEFAULT_LOG_FILE_DIRECTORY, volname);
        snprintf(qpid, 15, "%d", GF_CLIENT_PID_WORM_MOUNT);

        if (dict_get_str (this->options, "transport.socket.bind-address",
                          &volfileserver) != 0)
                volfileserver = "localhost";

        synclock_unlock (&priv->big_lock);
        ret = runcmd (SBIN_DIR"/glusterfs",
                      "--volfile-server", volfileserver,
                      "--volfile-id", volname,
                      "-l", logfile,
                      "-p", pidfile_path,
                      "--client-pid", qpid,
                      mountdir,
                      NULL);
        if (ret == 0) {
                /* Block here till mount process is ready to accept FOPs.
                 * Else, if glusterd acquires biglock below before
                 * mount process is ready, then glusterd and mount process
                 * can get into a deadlock situation.
                 */
                ret = sys_stat (mountdir, &buf);
                if (ret < 0)
                        ret = -errno;
        } else {
                ret = -errno;
        }

        synclock_lock (&priv->big_lock);

        if (ret) {
                gf_msg (this->name, GF_LOG_ERROR, -ret,
                        GD_MSG_MOUNT_REQ_FAIL, "Failed to mount glusterfs "
                        "client. Please check the log file %s for more details",
                        logfile);
                ret = -1;
                goto out;
        }

        ret = 0;

out:
        return ret;
}

int
glusterd_op_stage_worm (dict_t *dict, char **op_errstr, dict_t *rsp_dict)
{
        int                 ret            = 0;
        char               *volname        = NULL;
        gf_boolean_t        exists         = _gf_false;
        int                 type           = 0;
        xlator_t           *this           = NULL;
        glusterd_conf_t    *priv           = NULL;
        glusterd_volinfo_t *volinfo        = NULL;
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
                                        "before executing worm command.");
                ret = -1;
                goto out;
        }

        ret = dict_get_int32 (dict, "type", &type);
        if (ret) {
                *op_errstr = gf_strdup ("Volume worm failed, internal error, "
                                        "unable to get type of operation");
                goto out;
        }

        if ((!glusterd_is_volume_worm_enabled (volinfo)) &&
            (type != GF_WORM_OPTION_TYPE_ENABLE)) {
                *op_errstr = gf_strdup ("Worm is disabled, please enable "
                                        "worm");
                ret = -1;
                goto out;
        }

        if ((GF_WORM_OPTION_TYPE_ENABLE != type) &&
            (glusterd_check_if_worm_trans_enabled (volinfo) != 0)) {
                ret = -1;
                gf_asprintf (op_errstr, "Worm is not enabled on volume %s",
                             volname);
                goto out;
        }

        switch (type) {
        case GF_WORM_OPTION_TYPE_SET:
        case GF_WORM_OPTION_TYPE_GET:
        case GF_WORM_OPTION_TYPE_CLEAR:
                /* Worm auxiliary mount is needed by CLI
                 * for list command and need by glusterd for
                 * setting/removing limit
                 */
                if (is_origin_glusterd (dict)) {
                        ret = glusterd_create_worm_auxiliary_mount (this,
                                                            volname, type);
                        if (ret) {
                                *op_errstr = gf_strdup ("Failed to start aux "
                                                        "mount");
                                goto out;
                        }
                }
                break;
        }

        switch (type) {
        case GF_WORM_OPTION_TYPE_SET:
        case GF_WORM_OPTION_TYPE_GET:
        case GF_WORM_OPTION_TYPE_CLEAR:
                get_gfid = _gf_true;
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
                        GD_MSG_OP_STAGE_WORM_FAIL, "%s", *op_errstr);
        gf_msg_debug (this->name, 0, "Returning %d", ret);

         return ret;
}
