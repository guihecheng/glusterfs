#include "xlator.h"
#include "syncop.h"
#include "glusterfs.h"
#include "worm-common-utils.h"
#include "dir-worm-mem-types.h"
#include "dir-worm.h"
#include "dir-worm-helper.h"

void
dir_worm_serialize_meta (worm_meta_t *meta, char *val)
{
        GF_VALIDATE_OR_GOTO ("dir-worm", meta, out);
        GF_VALIDATE_OR_GOTO ("dir-worm", val, out);

        sprintf (val, "%"PRIu64"/%"PRIu64, meta->start, meta->dura);

out:
        return;
}

void
dir_worm_deserialize_meta (char *val, worm_meta_t *meta)
{
        char *token     =       NULL;

        GF_VALIDATE_OR_GOTO ("dir-worm", val, out);
        GF_VALIDATE_OR_GOTO ("dir-worm", meta, out);

        token = strtok (val, "/");
        meta->start = atoi (token);
        token = strtok (NULL, "/");
        meta->dura = atoi (token);

out:
        return;
}

void
dir_worm_serialize_state (dir_worm_reten_state_t *reten_state, char *val)
{
        uint32_t state     =       0;

        GF_VALIDATE_OR_GOTO ("dir-worm", reten_state, out);
        GF_VALIDATE_OR_GOTO ("dir-worm", val, out);

        state |= reten_state->worm << 0;
        state |= reten_state->retain << 1;
        sprintf (val, "%d/%"PRIu64"/%"PRIu64, state, reten_state->start_period,
                 reten_state->dura_period);

out:
        return;
}

void
dir_worm_deserialize_state (char *val, dir_worm_reten_state_t *reten_state)
{
        char *token     =       NULL;
        uint32_t state  =       0;

        GF_VALIDATE_OR_GOTO ("dir-worm", val, out);
        GF_VALIDATE_OR_GOTO ("dir-worm", reten_state, out);

        token = strtok (val, "/");
        state = atoi (token);
        reten_state->worm = (state >> 0) & 1;
        reten_state->retain = (state >> 1) & 1;
        token = strtok (NULL, "/");
        reten_state->start_period = atoi (token);
        token = strtok (NULL, "/");
        reten_state->dura_period = atoi (token);

out:
        return;
}

int32_t
dir_worm_init_state (xlator_t *this, gf_boolean_t fop_with_fd, void *file_ptr,
                     void *meta_ptr)
{
        int ret                 =      -1;
        uint64_t tick_start     =       0;
        dict_t *dict            =       NULL;
        char val[100]           =       "";

        GF_VALIDATE_OR_GOTO ("dir-worm", this, out);
        GF_VALIDATE_OR_GOTO (this->name, file_ptr, out);

        tick_start = time (NULL);
        dict = dict_new ();
        if (!dict) {
                gf_log (this->name, GF_LOG_ERROR, "Error creating the dict");
                goto out;
        }
        ret = dict_set_uint64 (dict, WORM_TICK_START_KEY, tick_start);
        if (ret) {
                gf_log (this->name, GF_LOG_ERROR, "Error in setting the dict");
                goto out;
        }
        if (fop_with_fd)
                ret = syncop_fsetxattr (this, (fd_t *)file_ptr, dict, 0,
                                        NULL, NULL);
        else
                ret = syncop_setxattr (this, (loc_t *)file_ptr, dict, 0, NULL,
                                       NULL);

        dict_unref (dict);

        dict = dict_new ();
        if (!dict) {
                gf_log (this->name, GF_LOG_ERROR, "Error creating the dict");
                goto out;
        }

        dir_worm_serialize_meta ((worm_meta_t *)meta_ptr, val);

        ret = dict_set_str (dict, WORM_START_AND_DURA_KEY, val);
        if (ret) {
                gf_log (this->name, GF_LOG_ERROR, "Error in setting the dict");
                goto out;
        }
        if (fop_with_fd)
                ret = syncop_fsetxattr (this, (fd_t *)file_ptr, dict, 0,
                                        NULL, NULL);
        else
                ret = syncop_setxattr (this, (loc_t *)file_ptr, dict, 0, NULL,
                                       NULL);
out:
        if (dict)
                dict_unref (dict);
        return ret;
}

int32_t
dir_worm_commit_state (xlator_t *this, dir_worm_reten_state_t *reten_state,
                       gf_boolean_t fop_with_fd, void *file_ptr)
{
        char val[100]   =        "";
        int ret         =        -1;
        dict_t *dict    =        NULL;

        GF_VALIDATE_OR_GOTO ("dir-worm", this, out);
        GF_VALIDATE_OR_GOTO (this->name, reten_state, out);
        GF_VALIDATE_OR_GOTO (this->name, file_ptr, out);

        dir_worm_serialize_state (reten_state, val);
        dict = dict_new ();
        if (!dict) {
                gf_log (this->name, GF_LOG_ERROR, "Error creating the dict");
                goto out;
        }
        ret = dict_set_str (dict, WORM_RETEN_STATE_KEY, val);
        if (ret) {
                gf_log (this->name, GF_LOG_ERROR, "Error in setting the dict");
                goto out;
        }
        if (fop_with_fd)
                ret = syncop_fsetxattr (this, (fd_t *)file_ptr, dict, 0,
                                        NULL, NULL);
        else
                ret = syncop_setxattr (this, (loc_t *)file_ptr, dict, 0, NULL,
                                       NULL);
out:
        if (dict)
                dict_unref (dict);
        return ret;
}

int32_t
dir_worm_set_state (xlator_t *this, gf_boolean_t fop_with_fd, void *file_ptr,
                    dir_worm_reten_state_t *retention_state, struct iatt *stbuf)
{
        dir_worm_priv_t *priv    =      NULL;
        struct iatt stpre        =      {0,};
        int ret                  =      -1;

        GF_VALIDATE_OR_GOTO ("dir-worm", this, out);
        GF_VALIDATE_OR_GOTO (this->name, file_ptr, out);
        GF_VALIDATE_OR_GOTO (this->name, retention_state, out);
        GF_VALIDATE_OR_GOTO (this->name, stbuf, out);

        priv = this->private;
        GF_ASSERT (priv);
        retention_state->worm = 1;
        retention_state->retain = 1;

        if (fop_with_fd)
                ret = syncop_fstat (this, (fd_t *)file_ptr, &stpre, NULL, NULL);
        else
                ret = syncop_stat (this, (loc_t *)file_ptr, &stpre, NULL, NULL);
        if (ret)
                goto out;

        stbuf->ia_mtime = stpre.ia_mtime;
        stbuf->ia_atime = time (NULL) + retention_state->dura_period;

        if (fop_with_fd)
                ret = syncop_fsetattr (this, (fd_t *)file_ptr, stbuf,
                                       GF_SET_ATTR_ATIME, NULL, NULL,
                                       NULL, NULL);
        else
                ret = syncop_setattr (this, (loc_t *)file_ptr, stbuf,
                                      GF_SET_ATTR_ATIME, NULL, NULL,
                                      NULL, NULL);
        if (ret)
                goto out;

        ret = dir_worm_commit_state (this, retention_state, fop_with_fd, file_ptr);
        if (ret) {
                gf_log (this->name, GF_LOG_ERROR, "Error setting xattr");
                goto out;
        }
        ret = 0;
out:
        return ret;
}

int32_t
dir_worm_get_state (xlator_t *this, gf_boolean_t fop_with_fd, void *file_ptr,
                    dir_worm_reten_state_t *reten_state)
{
        dict_t *dict    =       NULL;
        char *val       =       NULL;
        int ret         =       -1;

        GF_VALIDATE_OR_GOTO ("dir-worm", this, out);
        GF_VALIDATE_OR_GOTO (this->name, file_ptr, out);
        GF_VALIDATE_OR_GOTO (this->name, reten_state, out);

        if (fop_with_fd)
                ret = syncop_fgetxattr (this, (fd_t *)file_ptr, &dict,
                                        WORM_RETEN_STATE_KEY, NULL, NULL);
        else
                ret = syncop_getxattr (this, (loc_t *)file_ptr, &dict,
                                       WORM_RETEN_STATE_KEY, NULL, NULL);
        if (ret < 0 || !dict) {
                ret = -1;
                goto out;
        }
        ret = dict_get_str (dict, WORM_RETEN_STATE_KEY, &val);
        if (ret) {
                ret = -2;
                gf_log (this->name, GF_LOG_ERROR, "Empty val");
        }
        dir_worm_deserialize_state (val, reten_state);
out:
        if (dict)
                dict_unref (dict);
        return ret;
}

void
dir_worm_state_finish (xlator_t *this, gf_boolean_t fop_with_fd, void *file_ptr,
                       dir_worm_reten_state_t *reten_state, struct iatt *stbuf)
{
        int ret                                 =       -1;

        GF_VALIDATE_OR_GOTO ("dir-worm", this, out);
        GF_VALIDATE_OR_GOTO (this->name, file_ptr, out);
        GF_VALIDATE_OR_GOTO (this->name, reten_state, out);
        GF_VALIDATE_OR_GOTO (this->name, stbuf, out);

        stbuf->ia_atime -= reten_state->dura_period;
        reten_state->retain = 0;
        reten_state->start_period = 0;
        reten_state->dura_period = 0;
        ret = dir_worm_commit_state (this, reten_state, fop_with_fd, file_ptr);
        if (ret) {
                gf_log (this->name, GF_LOG_ERROR, "Error commit state");
                goto out;
        }

        if (fop_with_fd)
                ret = syncop_fsetattr (this, (fd_t *)file_ptr, stbuf,
                                       GF_SET_ATTR_ATIME, NULL, NULL,
                                       NULL, NULL);
        else
                ret = syncop_setattr (this, (loc_t *)file_ptr, stbuf,
                                      GF_SET_ATTR_ATIME, NULL, NULL,
                                      NULL, NULL);
        if (ret)
                goto out;
        gf_log (this->name, GF_LOG_INFO, "Retention state reset");
out:
        return;
}

int
dir_worm_state_transition (xlator_t *this, gf_boolean_t fop_with_fd,
                           void *file_ptr, glusterfs_fop_t op)
{
        int op_errno                        =       EROFS;
        int ret                             =       -1;
        uint64_t start_period               =       0;
        uint64_t tick_start                 =       0;
        dict_t *dict                        =       NULL;
        dir_worm_reten_state_t reten_state  =       {0,};
        dir_worm_priv_t *priv               =       NULL;
        struct iatt stbuf                   =       {0,};
        worm_meta_t meta                    =       {0,};
        char *val                           =       NULL;

        priv = this->private;
        GF_ASSERT (priv);

        if (fop_with_fd)
                ret = syncop_fgetxattr (this, (fd_t *)file_ptr, &dict,
                                        WORM_TICK_START_KEY, NULL, NULL);
        else
                ret = syncop_getxattr (this, (loc_t *)file_ptr, &dict,
                                       WORM_TICK_START_KEY, NULL, NULL);
        if (ret < 0 || !dict) {
                op_errno = ret;
                gf_msg (this->name, GF_LOG_ERROR, -ret, 0,
                        "Error getting xattr");
                goto out;
        }
        ret = dict_get_uint64 (dict, WORM_TICK_START_KEY, &tick_start);
        if (ret) {
                op_errno = ret;
                gf_msg (this->name, GF_LOG_ERROR, -ret, 0,
                        "Error getting start time");
                goto out;
        }

        dict_unref (dict);
        dict = NULL;

        if (fop_with_fd)
                ret = syncop_fstat (this, (fd_t *)file_ptr, &stbuf, NULL, NULL);
        else
                ret = syncop_stat (this, (loc_t *)file_ptr, &stbuf, NULL, NULL);
        if (ret) {
                op_errno = ret;
                gf_msg (this->name, GF_LOG_ERROR, -ret, 0,
                        "Error getting file stat");
                goto out;
        }

        if (fop_with_fd)
                ret = syncop_fgetxattr (this, (fd_t *)file_ptr, &dict,
                                        WORM_START_AND_DURA_KEY, NULL, NULL);
        else
                ret = syncop_getxattr (this, (loc_t *)file_ptr, &dict,
                                       WORM_START_AND_DURA_KEY, NULL, NULL);
        if (ret < 0 || !dict) {
                op_errno = ret;
                gf_log (this->name, GF_LOG_ERROR, "Error getting xattr");
                goto out;
        }

        ret = dict_get_str (dict, WORM_START_AND_DURA_KEY, &val);
        if (ret) {
                gf_log (this->name, GF_LOG_ERROR, "Empty val");
                goto out;
        }

        dir_worm_deserialize_meta (val, &meta);
        start_period = meta.start;

        ret = dir_worm_get_state (this, fop_with_fd, file_ptr, &reten_state);
        if (ret == -2) {
                op_errno = ret;
                gf_msg (this->name, GF_LOG_ERROR, -ret, 0,
                        "Error getting worm/retention state");
                goto out;
        }

        if (ret == -1 &&
            (time (NULL) - tick_start) >= start_period) {
                if ((time (NULL) - stbuf.ia_mtime) >= start_period) {
                        reten_state.start_period = meta.start;
                        reten_state.dura_period = meta.dura;

                        ret = dir_worm_set_state(this, fop_with_fd, file_ptr,
                                                 &reten_state, &stbuf);
                        if (ret) {
                                op_errno = ret;
                                gf_msg (this->name, GF_LOG_ERROR, -ret, 0,
                                        "Error setting worm/retention state");
                                goto out;
                        }
                        goto out;
                } else {
                        op_errno = 0;
                        goto out;
                }
        } else if (ret == -1 && (time (NULL) - tick_start)
                   < start_period) {
                op_errno = 0;
                goto out;
        } else if (reten_state.retain &&
                   ((time (NULL) >= stbuf.ia_atime))) {
                dir_worm_state_finish (this, fop_with_fd, file_ptr,
                                       &reten_state, &stbuf);
        }
        if (reten_state.worm && !reten_state.retain &&
                priv->dir_worm_files_deletable && op == GF_FOP_UNLINK) {
                op_errno = 0;
                goto out;
        }

out:
        if (dict)
                dict_unref (dict);
        return op_errno;
}

int32_t
is_wormfile (xlator_t *this, gf_boolean_t fop_with_fd, void *file_ptr)
{
        int ret         =       -1;
        dict_t *dict    =       NULL;

        if (fop_with_fd)
                ret = syncop_fgetxattr (this, (fd_t *)file_ptr, &dict,
                                        WORM_START_AND_DURA_KEY, NULL, NULL);
        else
                ret = syncop_getxattr (this, (loc_t *)file_ptr, &dict,
                                       WORM_START_AND_DURA_KEY, NULL, NULL);
        if (dict) {
                ret = 0;
                dict_unref (dict);
        }
        return ret;
}
