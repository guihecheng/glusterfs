#include <ctype.h>
#include <sys/uio.h>
#include <libgen.h>

#include "glusterfs.h"
#include "xlator.h"
#include "logging.h"
#include "compat.h"
#include "syncop.h"
#include "byte-order.h"

#include "worm-common-utils.h"
#include "dir-worm-mem-types.h"
#include "dir-worm.h"
#include "dir-worm-helper.h"

typedef struct {
        loc_t loc;
} dir_worm_local_t;

int32_t
mem_acct_init (xlator_t *this)
{
        int     ret = -1;

        ret = xlator_mem_acct_init (this, gf_dir_worm_mt_end + 1);
        if (ret)
                gf_log (this->name, GF_LOG_ERROR, "Memory accounting "
                        "initialization failed.");

        return ret;
}

static dir_worm_local_t *
dir_worm_local_get (call_frame_t *frame)
{
        dir_worm_local_t *local = NULL;

        local = frame->local;
        if (local)
                goto out;

        local = GF_CALLOC (1, sizeof (*local), gf_dir_worm_mt_local_t);
        if (!local)
                goto out;

        frame->local = local;
out:
        return local;
}

static void
dir_worm_local_wipe (dir_worm_local_t *local)
{
        if (!local)
                return;

        loc_wipe (&local->loc);
        GF_FREE (local);
}

static int
dir_worm_build_parent_loc (loc_t *parent, loc_t *child, int32_t *op_errno)
{
        int     ret = -1;
        char    *child_path = NULL;

        if (!child->parent) {
                if (op_errno)
                        *op_errno = EINVAL;
                goto out;
        }

        child_path = gf_strdup (child->path);
        if (!child_path) {
                if (op_errno)
                        *op_errno = ENOMEM;
                goto out;
        }

        parent->path = gf_strdup (dirname (child_path));
        if (!parent->path) {
                if (op_errno)
                        *op_errno = ENOMEM;
                goto out;
        }

        parent->inode = inode_ref (child->parent);
	gf_uuid_copy (parent->gfid, child->pargfid);

        ret = 0;
out:
        GF_FREE (child_path);

        return ret;
}

static int32_t
dir_worm_open (call_frame_t *frame, xlator_t *this, loc_t *loc, int32_t flags,
               fd_t *fd, dict_t *xdata)
{
        STACK_WIND_TAIL (frame, FIRST_CHILD(this),
                         FIRST_CHILD(this)->fops->open, loc, flags, fd, xdata);
        return 0;
}

static int32_t
dir_worm_writev (call_frame_t *frame, xlator_t *this, fd_t *fd,
                 struct iovec *vector, int32_t count, off_t offset,
                 uint32_t flags, struct iobref *iobref, dict_t *xdata)
{
        dir_worm_priv_t *priv            =       NULL;
        int op_errno                     =       EROFS;

        priv = this->private;
        GF_ASSERT (priv);
        if (!priv->dir_worm_on || (frame->root->pid < 0)) {
                op_errno = 0;
                goto out;
        }
        if (is_wormfile (this, _gf_true, fd)) {
                op_errno = 0;
                goto out;
        }
        op_errno = dir_worm_state_transition (this, _gf_true, fd, GF_FOP_WRITE);

out:
        if (op_errno) {
                if (op_errno < 0)
                        op_errno = EROFS;
                STACK_UNWIND_STRICT (writev, frame, -1, op_errno, NULL, NULL,
                                     NULL);
        }
        else
                STACK_WIND_TAIL (frame, FIRST_CHILD (this),
                                 FIRST_CHILD (this)->fops->writev,
                                 fd, vector, count, offset, flags, iobref,
                                 xdata);
        return 0;
}

static int32_t
dir_worm_setattr (call_frame_t *frame, xlator_t *this, loc_t *loc,
                  struct iatt *stbuf, int32_t valid, dict_t *xdata)
{
        dir_worm_reten_state_t reten_state  =       {0,};
        struct iatt stpre                   =       {0,};
        dir_worm_priv_t *priv               =       NULL;
        int op_errno                        =       EROFS;
        int ret                             =       -1;

        priv = this->private;
        GF_ASSERT (priv);
        if (!priv->dir_worm_on) {
                op_errno = 0;
                goto out;
        }

        if (is_wormfile (this, _gf_false, loc)) {
                op_errno = 0;
                goto out;
        }

        if (valid & GF_SET_ATTR_ATIME) {
                ret = dir_worm_get_state (this, _gf_false, loc, &reten_state);
                if (ret) {
                        op_errno = 0;
                        goto out;
                }
                if (reten_state.retain) {
                        ret = syncop_stat (this, loc, &stpre, NULL, NULL);
                        if (ret)
                                goto out;
                        if (stbuf->ia_atime < stpre.ia_atime) {
                                gf_log (this->name, GF_LOG_ERROR,
                                        "Cannot decrease the atime of a"
                                        " WORM-Retained file");
                                goto out;
                        }
                        stbuf->ia_mtime = stpre.ia_mtime;
                }
        }
        op_errno = 0;

out:
        if (op_errno)
                STACK_UNWIND_STRICT (setattr, frame, -1, EROFS, NULL, NULL,
                                     NULL);
        else
                STACK_WIND_TAIL (frame, FIRST_CHILD (this),
                                 FIRST_CHILD (this)->fops->setattr,
                                 loc, stbuf, valid, xdata);
        return 0;
}

static int32_t
dir_worm_fsetattr (call_frame_t *frame, xlator_t *this, fd_t *fd,
                   struct iatt *stbuf, int32_t valid, dict_t *xdata)
{
        dir_worm_reten_state_t reten_state  =       {0,};
        struct iatt stpre                   =       {0,};
        dir_worm_priv_t *priv               =       NULL;
        int op_errno                        =       EROFS;
        int ret                             =       -1;

        priv = this->private;
        GF_ASSERT (priv);
        if (!priv->dir_worm_on) {
                op_errno = 0;
                goto out;
        }

        if (is_wormfile (this, _gf_true, fd)) {
                op_errno = 0;
                goto out;
        }

        if (valid & GF_SET_ATTR_ATIME) {
                ret = dir_worm_get_state (this, _gf_true, fd, &reten_state);
                if (ret) {
                        op_errno = 0;
                        goto out;
                }
                if (reten_state.retain) {
                        ret = syncop_fstat (this, fd, &stpre, NULL, NULL);
                        if (ret)
                                goto out;
                        if (stbuf->ia_atime < stpre.ia_atime) {
                                gf_log (this->name, GF_LOG_ERROR,
                                        "Cannot decrease the atime of a"
                                        " WORM-Retained file");
                                goto out;
                        }
                        stbuf->ia_mtime = stpre.ia_mtime;
                }
        }
        op_errno = 0;

out:
        if (op_errno)
                STACK_UNWIND_STRICT (fsetattr, frame, -1, EROFS, NULL, NULL,
                                     NULL);
        else
                STACK_WIND_TAIL (frame, FIRST_CHILD (this),
                                 FIRST_CHILD (this)->fops->fsetattr,
                                 fd, stbuf, valid, xdata);
        return 0;
}

static int32_t
dir_worm_rename (call_frame_t *frame, xlator_t *this,
                 loc_t *oldloc, loc_t *newloc, dict_t *xdata)
{
        int op_errno                =       EROFS;
        dir_worm_priv_t *priv       =       NULL;

        priv = this->private;
        GF_ASSERT (priv);
        if (!priv->dir_worm_on || (frame->root->pid < 0)) {
                op_errno = 0;
                goto out;
        }

        gf_uuid_copy (oldloc->gfid, oldloc->inode->gfid);
        if (is_wormfile (this, _gf_false, oldloc)) {
                op_errno = 0;
                goto check_newloc;
        }
        op_errno = dir_worm_state_transition (this, _gf_false, oldloc,
                                              GF_FOP_RENAME);

        if (op_errno == 0) {
check_newloc:
                if (newloc->inode != NULL) {
                        gf_uuid_copy (newloc->gfid, newloc->inode->gfid);
                        if (is_wormfile (this, _gf_false, newloc)) {
                                op_errno = 0;
                                goto out;
                        }
                        op_errno = dir_worm_state_transition (this, _gf_false,
                                                              newloc,
                                                              GF_FOP_RENAME);
                }
        }

out:
        if (op_errno) {
                if (op_errno < 0)
                        op_errno = EROFS;
                STACK_UNWIND_STRICT (rename, frame, -1, op_errno, NULL,
                                     NULL, NULL, NULL, NULL, NULL);
        }
        else
                STACK_WIND_TAIL (frame, FIRST_CHILD (this),
                                 FIRST_CHILD (this)->fops->rename,
                                 oldloc, newloc, xdata);
        return 0;
}

static int32_t
dir_worm_link (call_frame_t *frame, xlator_t *this, loc_t *oldloc,
               loc_t *newloc, dict_t *xdata)
{
        int op_errno                =       EROFS;
        dir_worm_priv_t *priv       =       NULL;

        priv = this->private;
        GF_ASSERT (priv);
        if (!priv->dir_worm_on || (frame->root->pid < 0)) {
                op_errno = 0;
                goto out;
        }

        gf_uuid_copy (oldloc->gfid, oldloc->inode->gfid);
        if (is_wormfile (this, _gf_false, oldloc)) {
                op_errno = 0;
                goto out;
        }
        op_errno = dir_worm_state_transition (this, _gf_false, oldloc,
                                              GF_FOP_LINK);

out:
        if (op_errno) {
                if (op_errno < 0)
                        op_errno = EROFS;
                STACK_UNWIND_STRICT (link, frame, -1, op_errno, NULL, NULL,
                                     NULL, NULL, NULL);
        }
        else
                STACK_WIND_TAIL (frame, FIRST_CHILD(this),
                                 FIRST_CHILD(this)->fops->link,
                                 oldloc, newloc, xdata);
        return 0;
}

static int32_t
dir_worm_unlink (call_frame_t *frame, xlator_t *this, loc_t *loc,
                int32_t flags, dict_t *xdata)
{
        int op_errno                =       EROFS;
        dir_worm_priv_t *priv       =       NULL;

        priv = this->private;
        GF_ASSERT (priv);
        if (!priv->dir_worm_on || (frame->root->pid < 0)) {
                op_errno = 0;
                goto out;
        }

        gf_uuid_copy (loc->gfid, loc->inode->gfid);
        if (is_wormfile (this, _gf_false, loc)) {
                op_errno = 0;
                goto out;
        }
        op_errno = dir_worm_state_transition (this, _gf_false, loc,
                                              GF_FOP_UNLINK);
out:
        if (op_errno) {
                if (op_errno < 0)
                        op_errno = EROFS;
                STACK_UNWIND_STRICT (unlink, frame, -1, op_errno, NULL, NULL,
                                     NULL);
        }
        else
                STACK_WIND_TAIL (frame, FIRST_CHILD(this),
                                 FIRST_CHILD(this)->fops->unlink,
                                 loc, flags, xdata);
        return 0;
}

static int32_t
dir_worm_truncate (call_frame_t *frame, xlator_t *this, loc_t *loc,
                   off_t offset, dict_t *xdata)
{
        int op_errno                =       EROFS;
        dir_worm_priv_t *priv       =       NULL;

        priv = this->private;
        GF_ASSERT (priv);
        if (!priv->dir_worm_on || (frame->root->pid < 0)) {
                op_errno = 0;
                goto out;
        }

        if (is_wormfile (this, _gf_false, loc)) {
                op_errno = 0;
                goto out;
        }
        op_errno = dir_worm_state_transition (this, _gf_false, loc,
                                              GF_FOP_TRUNCATE);

out:
        if (op_errno) {
                if (op_errno < 0)
                        op_errno = EROFS;
                STACK_UNWIND_STRICT (truncate, frame, -1, op_errno, NULL, NULL,
                                     NULL);
        }
        else
                STACK_WIND_TAIL (frame, FIRST_CHILD (this),
                                 FIRST_CHILD (this)->fops->truncate,
                                 loc, offset, xdata);
        return 0;
}


static int32_t
dir_worm_ftruncate (call_frame_t *frame, xlator_t *this, fd_t *fd,
                    off_t offset, dict_t *xdata)
{
        int op_errno                =       EROFS;
        dir_worm_priv_t *priv       =       NULL;

        priv = this->private;
        GF_ASSERT (priv);
        if (!priv->dir_worm_on || (frame->root->pid < 0)) {
                op_errno = 0;
                goto out;
        }

        if (is_wormfile (this, _gf_true, fd)) {
                op_errno = 0;
                goto out;
        }
        op_errno = dir_worm_state_transition (this, _gf_true, fd,
                                              GF_FOP_FTRUNCATE);

out:
        if (op_errno) {
                if (op_errno < 0)
                        op_errno = EROFS;
                STACK_UNWIND_STRICT (ftruncate, frame, -1, op_errno, NULL, NULL,
                                     NULL);
        }
        else
                STACK_WIND_TAIL (frame, FIRST_CHILD (this),
                                 FIRST_CHILD (this)->fops->ftruncate,
                                 fd, offset, xdata);
        return 0;
}

static int32_t
dir_worm_create_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                     int32_t op_ret, int32_t op_errno, fd_t *fd,
                     inode_t *inode, struct iatt *buf,
                     struct iatt *preparent, struct iatt *postparent,
                     dict_t *xdata)
{
        int ret                       = 0;
        dir_worm_priv_t  *priv        = NULL;
        dir_worm_local_t *local       = NULL;
        dict_t           *dict        = NULL;
        loc_t             parent_loc  = {0,};
        char             *val         = NULL;
        worm_meta_t      *meta        = NULL;

        local = frame->local;
        frame->local = NULL;

        parent_loc.inode = NULL;

        if (op_ret) {
                goto out;
        }

        if (!local) {
                goto out;
        }

        priv = this->private;
        GF_ASSERT (priv);
        if (!priv->dir_worm_on) {
                goto out;
        }

        ret = dir_worm_build_parent_loc (&parent_loc, &local->loc, NULL);
        if (ret) {
                gf_log (this->name, GF_LOG_ERROR, "Error build parent loc");
                goto out;
        }

        ret = syncop_getxattr (this, (loc_t *)&parent_loc, &dict,
                               WORM_START_AND_DURA_KEY, NULL, NULL);
        if (ret < 0 || !dict) {
                /* start & dura not set, fine */
                ret = 0;
                goto out;
        }

        ret = dict_get_str (dict, WORM_START_AND_DURA_KEY, &val);
        if (ret) {
                gf_log (this->name, GF_LOG_ERROR, "Error get key : %s",
                        WORM_START_AND_DURA_KEY);
                goto out;
        }

        meta = (worm_meta_t *)val;
        meta->start = ntoh64 (meta->start);
        meta->dura  = ntoh64 (meta->dura);

        ret = dir_worm_init_state (this, _gf_true, fd, (void *)meta);
        if (ret) {
                gf_log (this->name, GF_LOG_ERROR, "Error init worm state");
                goto out;
        }

out:
        if (parent_loc.inode)
                inode_unref (parent_loc.inode);

        if (dict)
                dict_unref (dict);

        if (local)
                dir_worm_local_wipe (local);

        STACK_UNWIND_STRICT (create, frame, op_ret, op_errno, fd, inode, buf,
                             preparent, postparent, xdata);
        return ret;
}


static int32_t
dir_worm_create (call_frame_t *frame, xlator_t *this, loc_t *loc, int32_t flags,
                 mode_t mode, mode_t umask, fd_t *fd, dict_t *xdata)
{
        dir_worm_local_t *local = NULL;

        local = dir_worm_local_get (frame);

        loc_copy (&local->loc, loc);

        STACK_WIND (frame, dir_worm_create_cbk,  FIRST_CHILD (this),
                    FIRST_CHILD(this)->fops->create, loc, flags,
                    mode, umask, fd, xdata);
        return 0;
}
int32_t
init (xlator_t *this)
{
        int                    ret      = -1;
        dir_worm_priv_t       *priv    = NULL;

        if (!this->children || this->children->next) {
                gf_log (this->name, GF_LOG_ERROR,
                        "translator not configured with exactly one child");
                return -1;
        }

        if (!this->parents) {
                gf_log (this->name, GF_LOG_WARNING,
                        "dangling volume. check volfile ");
        }

        priv = GF_CALLOC (1, sizeof(*priv), gf_dir_worm_mt_priv_t);
        if (!priv) {
                gf_log (this->name, GF_LOG_ERROR, "Error allocating priv");
                goto out;
        }

        this->private = priv;

        GF_OPTION_INIT ("dir-worm", priv->dir_worm_on,
                        bool, out);
        GF_OPTION_INIT ("dir-worm-files-deletable", priv->dir_worm_files_deletable,
                        bool, out);
        GF_OPTION_INIT ("dir-worm-files-editable", priv->dir_worm_files_editable,
                        bool, out);

        ret = 0;
out:
        return ret;
}

int
reconfigure (xlator_t *this, dict_t *options)
{
        dir_worm_priv_t   *priv                    = NULL;
        int                ret                     = -1;

        priv = this->private;
        GF_ASSERT (priv);

        GF_OPTION_RECONF ("dir-worm", priv->dir_worm_on,
                          options, bool, out);
        GF_OPTION_RECONF ("dir-worm-files-deletable", priv->dir_worm_files_deletable,
                          options, bool, out);
        GF_OPTION_RECONF ("dir-worm-files-editable", priv->dir_worm_files_editable,
                          options, bool, out);
        ret = 0;
out:
        gf_log (this->name, GF_LOG_DEBUG, "returning %d", ret);
        return ret;
}

void
fini (xlator_t *this)
{
	dir_worm_priv_t *priv = this->private;

        if (!priv)
                return;
        this->private = NULL;
        GF_FREE (priv);

	return;
}

struct xlator_fops fops = {
        .open        = dir_worm_open,
        .writev      = dir_worm_writev,
        .setattr     = dir_worm_setattr,
        .fsetattr    = dir_worm_fsetattr,
        .rename      = dir_worm_rename,
        .link        = dir_worm_link,
        .unlink      = dir_worm_unlink,
        .truncate    = dir_worm_truncate,
        .ftruncate   = dir_worm_ftruncate,
        .create      = dir_worm_create,
};

struct xlator_cbks cbks;

struct volume_options options[] = {
        { .key = {"dir-worm"},
          .type = GF_OPTION_TYPE_BOOL,
          .default_value = "off",
          /*.validate_fn = validate_boolean,*/
          .op_version = {GD_OP_VERSION_3_8_4},
          .flags = OPT_FLAG_SETTABLE,
          .description = "When \"on\", makes a volume get write once read many"
                         " feature for directories."
                         "It is turned \"off\" by default."
        },
        { .key = {"dir-worm-files-deletable"},
          .type = GF_OPTION_TYPE_BOOL,
          .default_value = "on",
          /*.validate_fn = validate_boolean,*/
          .op_version = {GD_OP_VERSION_3_8_4},
          .flags = OPT_FLAG_SETTABLE,
          .description = "When \"off\", doesn't allow the Worm files"
                         "to be deleted. It is turned \"on\" by default."
        },
        { .key = {"dir-worm-files-editable"},
          .type = GF_OPTION_TYPE_BOOL,
          .default_value = "on",
          /*.validate_fn = validate_boolean,*/
          .description = "When \"off\", doesn't allow the Worm files"
                         "to be modified. It is turned \"off\" by default."
        },
	{ .key  = {NULL} },
};
