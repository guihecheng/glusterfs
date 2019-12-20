#include "xquota.h"
#include "common-utils.h"
#include "defaults.h"
#include "statedump.h"
#include "xquota-common-utils.h"
#include "xquota-messages.h"
#include "events.h"

struct volume_options options[];

static int32_t
__xquota_init_inode_ctx (inode_t *inode, xlator_t *this,
                         xquota_inode_ctx_t **context)
{
        int32_t             ret  = -1;
        xquota_inode_ctx_t *ctx  = NULL;

        if (inode == NULL) {
                goto out;
        }

        XQUOTA_ALLOC_OR_GOTO (ctx, xquota_inode_ctx_t, out);

        LOCK_INIT(&ctx->lock);

        if (context != NULL) {
                *context = ctx;
        }

        ret = __inode_ctx_put (inode, this, (uint64_t )(long)ctx);
        if (ret) {
                gf_msg (this->name, GF_LOG_WARNING, 0,
                        XQ_MSG_INODE_CTX_SET_FAILED, "cannot set xquota context "
                        "in inode (gfid:%s)", uuid_utoa (inode->gfid));
                GF_FREE (ctx);
        }
out:
        return ret;
}


static int32_t
xquota_inode_ctx_get (inode_t *inode, xlator_t *this,
                      xquota_inode_ctx_t **ctx, char create_if_absent)
{
        int32_t  ret = 0;
        uint64_t ctx_int;

        LOCK (&inode->lock);
        {
                ret = __inode_ctx_get (inode, this, &ctx_int);

                if ((ret == 0) && (ctx != NULL)) {
                        *ctx = (xquota_inode_ctx_t *) (unsigned long)ctx_int;
                } else if (create_if_absent) {
                        ret = __xquota_init_inode_ctx (inode, this, ctx);
                }
        }
        UNLOCK (&inode->lock);

        return ret;
}

int
xquota_loc_fill (loc_t *loc, inode_t *inode, inode_t *parent, char *path)
{
        int ret = -1;

        if (!loc || (inode == NULL))
                return ret;

        if (inode) {
                loc->inode = inode_ref (inode);
                gf_uuid_copy (loc->gfid, inode->gfid);
        }

        if (parent) {
                loc->parent = inode_ref (parent);
        }

        if (path != NULL) {
                loc->path = gf_strdup (path);

                loc->name = strrchr (loc->path, '/');
                if (loc->name) {
                        loc->name++;
                }
        }

        ret = 0;

        return ret;
}


int
xquota_inode_loc_fill (inode_t *inode, loc_t *loc)
{
        char            *resolvedpath = NULL;
        inode_t         *parent       = NULL;
        int              ret          = -1;
        xlator_t        *this         = NULL;

        if ((!inode) || (!loc)) {
                return ret;
        }

        this = THIS;

        if ((inode) && __is_root_gfid (inode->gfid)) {
                loc->parent = NULL;
                goto ignore_parent;
        }

        parent = inode_parent (inode, 0, NULL);
        if (!parent) {
                gf_msg_debug (this->name, 0, "cannot find parent for "
                              "inode (gfid:%s)", uuid_utoa (inode->gfid));
        }

ignore_parent:
        ret = inode_path (inode, NULL, &resolvedpath);
        if (ret < 0) {
                gf_msg_debug (this->name, 0, "cannot construct path for "
                              "inode (gfid:%s)",  uuid_utoa (inode->gfid));
        }

        ret = xquota_loc_fill (loc, inode, parent, resolvedpath);
        if (ret < 0) {
                gf_msg (this->name, GF_LOG_WARNING, ENOMEM, XQ_MSG_ENOMEM,
                        "cannot fill loc");
                goto err;
        }

err:
        if (parent) {
                inode_unref (parent);
        }

        GF_FREE (resolvedpath);

        return ret;
}


int32_t
xquota_local_cleanup (xquota_local_t *local)
{
        if (local == NULL) {
                goto out;
        }

        loc_wipe (&local->loc);
        loc_wipe (&local->newloc);
        loc_wipe (&local->oldloc);
        loc_wipe (&local->validate_loc);

        inode_unref (local->inode);

        if (local->xdata)
                dict_unref (local->xdata);

        if (local->validate_xdata)
                dict_unref (local->validate_xdata);

        if (local->stub)
                call_stub_destroy (local->stub);

        LOCK_DESTROY (&local->lock);

        mem_put (local);
out:
        return 0;
}


static xquota_local_t *
xquota_local_new ()
{
        xquota_local_t *local = NULL;
        local = mem_get0 (THIS->local_pool);
        if (local == NULL)
                goto out;

        LOCK_INIT (&local->lock);
        local->space_available = -1;

out:
        return local;
}

static int
xquota_get_meta (xlator_t *this, dict_t *dict, uint64_t *hard_lim,
                 uint64_t *soft_lim)
{
        xquota_meta_t   *meta               = NULL;
        xquota_priv_t   *priv               = NULL;
        int64_t          soft_lim_percent   = 0;
        int64_t         *ptr                = NULL;

        if ((this == NULL) || (dict == NULL) || (hard_lim == NULL)
            || (soft_lim == NULL))
                goto out;

        priv = this->private;

        (void) dict_get_bin (dict, VIRTUAL_XQUOTA_USAGE_META_KEY, (void **) &ptr);
        meta = (xquota_meta_t *)ptr;

        if (meta) {
                *hard_lim = ntoh64 (meta->hl);
                soft_lim_percent = ntoh64 (meta->sl);
        }

        if (soft_lim_percent <= 0) {
                soft_lim_percent = priv->default_soft_lim;
        }

        if ((*hard_lim > 0) && (soft_lim_percent > 0)) {
                *soft_lim = (soft_lim_percent * (*hard_lim))/100;
        }

out:
        return 0;
}

int
xquota_fill_inodectx (xlator_t *this, inode_t *inode, dict_t *dict,
                      loc_t *loc, struct iatt *buf, int32_t *op_errno)
{
        int32_t              ret                  = -1;
        xquota_inode_ctx_t  *ctx                  = NULL;
        uint64_t             value                = 0;
        uint64_t             hard_lim             = 0;
        uint64_t             soft_lim             = 0;

        xquota_get_meta (this, dict, &hard_lim, &soft_lim);

        inode_ctx_get (inode, this, &value);
        ctx = (xquota_inode_ctx_t *)(unsigned long)value;

        if ((((ctx == NULL) || (ctx->hard_lim == hard_lim))
             && (hard_lim < 0) && !XQUOTA_REG_OR_LNK_FILE (buf->ia_type))) {
                ret = 0;
                goto out;
        }

        ret = xquota_inode_ctx_get (inode, this, &ctx, 1);
        if ((ret == -1) || (ctx == NULL)) {
                gf_msg (this->name, GF_LOG_WARNING, ENOMEM,
                        XQ_MSG_INODE_CTX_GET_FAILED, "cannot create xquota "
                        "context in inode(gfid:%s)", uuid_utoa (inode->gfid));
                ret = -1;
                *op_errno = ENOMEM;
                goto out;
        }

        LOCK (&ctx->lock);
        {
                ctx->hard_lim = hard_lim;
                ctx->soft_lim = soft_lim;

                ctx->buf = *buf;
        }
        UNLOCK (&ctx->lock);

out:
        return ret;
}

static void
xquota_link_count_decrement (call_frame_t *frame)
{
        call_frame_t    *tmpframe   = NULL;
        xquota_local_t  *local      = NULL;
        call_stub_t     *stub       = NULL;
        int              link_count = -1;

        local = frame->local;
        if (local && local->par_frame) {
                local = local->par_frame->local;
                tmpframe = frame;
        }

        if (local == NULL)
                goto out;

        LOCK (&local->lock);
        {
                link_count = --local->link_count;
                if (link_count == 0) {
                        stub = local->stub;
                        local->stub = NULL;
                }
        }
        UNLOCK (&local->lock);

        if (stub != NULL) {
                call_resume (stub);
        }

out:
        if (tmpframe) {
                local = tmpframe->local;
                tmpframe->local = NULL;

                STACK_DESTROY (frame->root);
                if (local)
                        xquota_local_cleanup (local);
        }

        return;
}

static void
xquota_handle_validate_error (call_frame_t *frame, int32_t op_ret,
                              int32_t op_errno)
{
        xquota_local_t  *local;

        local = frame->local;
        if (local && local->par_frame)
                local = local->par_frame->local;

        if (local == NULL)
                goto out;

        LOCK (&local->lock);
        {
                if (op_ret < 0) {
                        local->op_ret = op_ret;
                        local->op_errno = op_errno;
                }
        }
        UNLOCK (&local->lock);

        xquota_link_count_decrement (frame);
out:
        return;
}

static uint64_t
xquota_time_elapsed (struct timeval *now, struct timeval *then)
{
        return (now->tv_sec - then->tv_sec);
}

int32_t
xquota_timeout (struct timeval *tv, int32_t timeout)
{
        struct timeval now       = {0,};
        int32_t        timed_out = 0;

        gettimeofday (&now, NULL);

        if (xquota_time_elapsed (&now, tv) >= timeout) {
                timed_out = 1;
        }

        return timed_out;
}

void
xquota_log_helper (char **usage_str, int64_t cur_size, inode_t *inode,
                   char **path, struct timeval *cur_time)
{
        xlator_t        *this   = THIS;

        if (!usage_str || !inode || !path || !cur_time) {
                gf_log (this->name, GF_LOG_ERROR, "Received null argument");
                return;
        }

        *usage_str = gf_uint64_2human_readable (cur_size);
        if (!(*usage_str))
                gf_msg (this->name, GF_LOG_ERROR, ENOMEM, XQ_MSG_ENOMEM,
                        "integer to string conversion failed Reason"
                        ":\"Cannot allocate memory\"");

        inode_path (inode, NULL, path);
        if (!(*path))
                *path = uuid_utoa (inode->gfid);

        gettimeofday (cur_time, NULL);
}

/* Logs if
*  i.   Usage crossed soft limit
*  ii.  Usage above soft limit and alert-time elapsed
*/
void
xquota_log_usage (xlator_t *this, xquota_inode_ctx_t *ctx, inode_t *inode,
                  int64_t delta)
{
        struct timeval            cur_time       = {0,};
        char                     *usage_str      = NULL;
        char                     *path           = NULL;
        int64_t                   cur_size       = 0;
        xquota_priv_t            *priv           = NULL;

        priv = this->private;
        cur_size = ctx->usage + delta;

        if ((ctx->soft_lim <= 0) || cur_size < ctx->soft_lim)
                return;

        /* Usage crossed/reached soft limit */
        if (DID_REACH_LIMIT (ctx->soft_lim, ctx->usage, cur_size)) {

                xquota_log_helper (&usage_str, cur_size, inode,
                                   &path, &cur_time);

                gf_msg (this->name, GF_LOG_ALERT, 0,
                        XQ_MSG_CROSSED_SOFT_LIMIT, "Usage crossed soft limit: "
                        "%s used by %s", usage_str, path);

                gf_event (EVENT_XQUOTA_CROSSED_SOFT_LIMIT, "Usage=%s;volume=%s;"
                          "path=%s", usage_str, priv->volume_uuid, path);

                ctx->prev_log = cur_time;

        }
        /* Usage is above soft limit */
        else if (cur_size > ctx->soft_lim &&
                           xquota_timeout (&ctx->prev_log, priv->log_timeout)) {

                xquota_log_helper (&usage_str, cur_size, inode,
                                   &path, &cur_time);

                gf_msg (this->name, GF_LOG_ALERT, 0, XQ_MSG_CROSSED_SOFT_LIMIT,
                        "Usage is above soft limit: %s used by %s",
                        usage_str, path);

                gf_event (EVENT_XQUOTA_CROSSED_SOFT_LIMIT, "Usage=%s;volume=%s;"
                          "path=%s", usage_str, priv->volume_uuid, path);

                ctx->prev_log = cur_time;
        }

        if (usage_str)
                GF_FREE (usage_str);
}

int32_t
xquota_validate_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                     int32_t op_ret, int32_t op_errno, inode_t *inode,
                     struct iatt *buf, dict_t *xdata, struct iatt *postparent)
{
        xquota_local_t     *local      = NULL;
        int32_t             ret        = 0;
        xquota_inode_ctx_t *ctx        = NULL;
        uint64_t            value      = 0;
        xquota_meta_t      *meta       = NULL;

        local = frame->local;

        if (op_ret < 0) {
                goto unwind;
        }

        GF_ASSERT (local);
        GF_ASSERT (frame);
        GF_VALIDATE_OR_GOTO_WITH_ERROR ("xquota", this, unwind, op_errno,
                                        EINVAL);
        GF_VALIDATE_OR_GOTO_WITH_ERROR (this->name, xdata, unwind, op_errno,
                                        EINVAL);

        ret = inode_ctx_get (local->validate_loc.inode, this, &value);

        ctx = (xquota_inode_ctx_t *)(unsigned long)value;
        if ((ret == -1) || (ctx == NULL)) {
                gf_msg (this->name, GF_LOG_WARNING, EINVAL,
			XQ_MSG_INODE_CTX_GET_FAILED, "xquota context is"
			" not present in  inode (gfid:%s)",
                        uuid_utoa (local->validate_loc.inode->gfid));
                op_errno = EINVAL;
                goto unwind;
        }

        ret = dict_get_bin (xdata, VIRTUAL_XQUOTA_USAGE_META_KEY, (void**)&meta);
        if (ret == -1) {
                gf_msg (this->name, GF_LOG_WARNING, EINVAL,
			XQ_MSG_SIZE_KEY_MISSING, "xquota usage meta key not present "
                        "in dict");
                op_errno = EINVAL;
        }

        local->just_validated = 1; /* so that we don't go into infinite
                                    * loop of validation and checking
                                    * limit when timeout is zero.
                                    */
        LOCK (&ctx->lock);
        {
                ctx->usage = ntoh64 (meta->usage);
                gettimeofday (&ctx->tv, NULL);
        }
        UNLOCK (&ctx->lock);

        xquota_check_limit (frame, local->validate_loc.inode, this);
        return 0;

unwind:
        xquota_handle_validate_error (frame, op_ret, op_errno);
        return 0;
}


int
xquota_validate (call_frame_t *frame, inode_t *inode, xlator_t *this,
                 fop_lookup_cbk_t cbk_fn)
{
        xquota_local_t     *local = NULL;
        int                 ret   = 0;
        dict_t             *xdata = NULL;
        xquota_priv_t      *priv  = NULL;

        local = frame->local;
        priv = this->private;

        LOCK (&local->lock);
        {
                loc_wipe (&local->validate_loc);

                ret = xquota_inode_loc_fill (inode, &local->validate_loc);
                if (ret < 0) {
                        gf_msg (this->name, GF_LOG_WARNING, ENOMEM,
                                XQ_MSG_ENFORCEMENT_FAILED,
				"cannot fill loc for inode (gfid:%s), hence "
                                "aborting xquota-checks and continuing with fop",
                                uuid_utoa (inode->gfid));
                }
        }
        UNLOCK (&local->lock);

        if (ret < 0) {
                ret = -ENOMEM;
                goto err;
        }

        xdata = dict_new ();
        if (xdata == NULL) {
                ret = -ENOMEM;
                goto err;
        }

        ret = dict_set_int8 (xdata, VIRTUAL_XQUOTA_USAGE_META_KEY, 1);
        if (ret < 0) {
                gf_msg (this->name, GF_LOG_WARNING, ENOMEM,
			XQ_MSG_ENOMEM, "dict set failed");
                ret = -ENOMEM;
                goto err;
        }

        ret = dict_set_str (xdata, "volume-uuid", priv->volume_uuid);
        if (ret < 0) {
                gf_msg (this->name, GF_LOG_WARNING, ENOMEM,
			XQ_MSG_ENOMEM, "dict set failed");
                ret = -ENOMEM;
                goto err;
        }

        ret = xquota_enforcer_lookup (frame, this, xdata, cbk_fn);
        if (ret < 0) {
                ret = -ENOTCONN;
                goto err;
        }

        ret = 0;
err:
        if (xdata)
                dict_unref (xdata);

        return ret;
}

int32_t
xquota_readv_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                  int32_t op_ret, int32_t op_errno, struct iovec *vector,
                  int32_t count, struct iatt *stbuf, struct iobref *iobref,
                  dict_t *xdata)
{
        xquota_local_t     *local = NULL;
        xquota_inode_ctx_t *ctx   = NULL;

        if (op_ret < 0) {
                goto out;
        }

        local = frame->local;

        GF_VALIDATE_OR_GOTO ("xquota", local, out);

        (void) xquota_inode_ctx_get (local->loc.inode, this, &ctx, 0);
        if (ctx == NULL) {
                gf_msg_debug (this->name, 0, "xquota context is NULL on inode"
                              " (%s). If xquota is not enabled recently and "
                              "crawler has finished crawling, its an error",
                              uuid_utoa (local->loc.inode->gfid));
                goto out;
        }

        LOCK (&ctx->lock);
        {
                ctx->buf = *stbuf;
        }
        UNLOCK (&ctx->lock);

out:
        XQUOTA_STACK_UNWIND (readv, frame, op_ret, op_errno, vector, count,
                             stbuf, iobref, xdata);
        return 0;
}


int32_t
xquota_readv (call_frame_t *frame, xlator_t *this,
              fd_t *fd, size_t size, off_t offset,
              uint32_t flags, dict_t *xdata)
{
        xquota_priv_t  *priv  = NULL;
        xquota_local_t *local = NULL;

        priv = this->private;

        WIND_IF_XQUOTAOFF (priv->is_xquota_on, off);

        local = xquota_local_new ();
        if (local == NULL) {
                goto unwind;
        }

        frame->local = local;

        local->loc.inode = inode_ref (fd->inode);

        STACK_WIND (frame, xquota_readv_cbk,
                    FIRST_CHILD(this), FIRST_CHILD(this)->fops->readv, fd,
                    size, offset, flags, xdata);
        return 0;

unwind:
        XQUOTA_STACK_UNWIND (readv, frame, -1, ENOMEM, NULL, -1, NULL, NULL,
                             NULL);
        return 0;

off:
        STACK_WIND_TAIL (frame, FIRST_CHILD(this),
                         FIRST_CHILD(this)->fops->readv, fd,
                         size, offset, flags, xdata);
        return 0;
}

int32_t
xquota_writev_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, struct iatt *prebuf,
                   struct iatt *postbuf, dict_t *xdata)
{
        int32_t                   ret            = 0;
        uint64_t                  ctx_int        = 0;
        xquota_inode_ctx_t       *ctx            = NULL;
        xquota_local_t           *local          = NULL;

        local = frame->local;

        if ((op_ret < 0) || (local == NULL) || (postbuf == NULL)) {
                goto out;
        }

        ret = inode_ctx_get (local->loc.inode, this, &ctx_int);
        if (ret) {
                gf_msg (this->name, GF_LOG_WARNING, 0,
                        XQ_MSG_INODE_CTX_GET_FAILED, "%s: failed to get the "
			"context", local->loc.path);
                goto out;
        }

        ctx = (xquota_inode_ctx_t *)(unsigned long) ctx_int;

        if (ctx == NULL) {
                gf_msg (this->name, GF_LOG_WARNING, 0,
			XQ_MSG_INODE_CTX_GET_FAILED,
                        "xquota context not set in %s (gfid:%s)",
                        local->loc.path, uuid_utoa (local->loc.inode->gfid));
                goto out;
        }

        LOCK (&ctx->lock);
        {
                ctx->buf = *postbuf;
        }
        UNLOCK (&ctx->lock);

out:
        XQUOTA_STACK_UNWIND (writev, frame, op_ret, op_errno, prebuf, postbuf,
                             xdata);

        return 0;
}

int32_t
xquota_writev_helper (call_frame_t *frame, xlator_t *this, fd_t *fd,
                      struct iovec *vector, int32_t count, off_t off,
                      uint32_t flags, struct iobref *iobref, dict_t *xdata)
{
        xquota_local_t *local      = NULL;
        int32_t         op_errno   = EINVAL;
        struct iovec   *new_vector = NULL;
        int32_t         new_count  = 0;

        local = frame->local;

        GF_VALIDATE_OR_GOTO ("xquota", local, unwind);

        if (local->op_ret == -1) {
                op_errno = local->op_errno;

                if ((op_errno == EDQUOT) && (local->space_available > 0)) {
                        new_count = iov_subset (vector, count, 0,
                                                local->space_available, NULL);

                        new_vector = GF_CALLOC (new_count,
                                                sizeof (struct iovec),
                                                gf_common_mt_iovec);
                        if (new_vector == NULL) {
                                local->op_ret = -1;
                                local->op_errno = ENOMEM;
                                goto unwind;
                        }

                        new_count = iov_subset (vector, count, 0,
                                                local->space_available,
                                                new_vector);

                        vector = new_vector;
                        count = new_count;
                } else if (op_errno == ENOENT || op_errno == ESTALE) {
                        /* We may get ENOENT/ESTALE in case of below scenario
                         *     fd = open file.txt
                         *     unlink file.txt
                         *     write on fd
                         * Here build_ancestry can fail as the file is removed.
                         * For now ignore ENOENT/ESTALE with writes on active fd
                         * We need to re-visit this code once we understand
                         * how other file-system behave in this scenario
                         */
                        gf_msg_debug (this->name, 0, "xquota enforcer failed "
                                      "with ENOENT/ESTALE on %s, cannot check "
                                      "xquota limits and allowing writes",
                                      uuid_utoa (fd->inode->gfid));
                } else {
                        goto unwind;
                }
        }

        STACK_WIND (frame, xquota_writev_cbk,
                    FIRST_CHILD(this), FIRST_CHILD(this)->fops->writev, fd,
                    vector, count, off, flags, iobref, xdata);

        if (new_vector != NULL)
                GF_FREE (new_vector);

        return 0;

unwind:
        XQUOTA_STACK_UNWIND (writev, frame, -1, op_errno, NULL, NULL, NULL);
        return 0;
}

int32_t
xquota_check_size_limit (call_frame_t *frame, xquota_inode_ctx_t *ctx,
                         xquota_priv_t *priv, inode_t *_inode, xlator_t *this,
                         int32_t *op_errno, int just_validated, int64_t delta,
                         xquota_local_t *local, gf_boolean_t *skip_check)
{
        int32_t         ret                     = -1;
        uint32_t        timeout                 =  0;
        char            need_validate           =  0;
        gf_boolean_t    hard_limit_exceeded     =  0;
        int64_t         space_available         =  0;
        int64_t         wouldbe_size            =  0;

        GF_ASSERT (frame);
        GF_ASSERT (priv);
        GF_ASSERT (_inode);
        GF_ASSERT (this);
        GF_ASSERT (local);

        if (ctx != NULL && (ctx->hard_lim > 0 || ctx->soft_lim > 0)) {
                wouldbe_size = ctx->usage + delta;

                LOCK (&ctx->lock);
                {
                        timeout = priv->soft_timeout;

                        if ((ctx->soft_lim >= 0)
                            && (wouldbe_size > ctx->soft_lim)) {
                                timeout = priv->hard_timeout;
                        }

                        if (!just_validated
                            && xquota_timeout (&ctx->tv, timeout)) {
                                need_validate = 1;
                        } else if (wouldbe_size >= ctx->hard_lim) {
                                hard_limit_exceeded = 1;
                        }
                }
                UNLOCK (&ctx->lock);

                if (need_validate && *skip_check != _gf_true) {
                        *skip_check = _gf_true;
                        ret = xquota_validate (frame, _inode, this,
                                               xquota_validate_cbk);
                        if (ret < 0) {
                                *op_errno = -ret;
                                *skip_check = _gf_false;
                        }
                        goto out;
                }

                if (hard_limit_exceeded) {
                        local->op_ret = -1;
                        local->op_errno = EDQUOT;

                        space_available = ctx->hard_lim - ctx->usage;

                        if (space_available < 0)
                                space_available = 0;

                        if ((local->space_available < 0)
                            || (local->space_available
                                > space_available)){
                                local->space_available
                                        = space_available;

                        }

                        if (space_available == 0) {
                                *op_errno = EDQUOT;
                                goto out;
                        }
                }

                /* We log usage only if xquota limit is configured on
                   that inode. */
                xquota_log_usage (this, ctx, _inode, delta);
        }

        ret = 0;
out:
        return ret;
}

int32_t
xquota_check_limit (call_frame_t *frame, inode_t *inode, xlator_t *this)
{
        int32_t            ret                 = -1, op_errno = EINVAL;
        inode_t           *_inode              = NULL;
        xquota_inode_ctx_t *ctx                = NULL;
        xquota_priv_t      *priv               = NULL;
        xquota_local_t     *local              = NULL;
        xquota_local_t     *par_local          = NULL;
        char               just_validated      = 0;
        int64_t            delta               = 0;
        uint64_t           value               = 0;
        gf_boolean_t       skip_check          = _gf_false;

        GF_VALIDATE_OR_GOTO ("xquota", this, err);
        GF_VALIDATE_OR_GOTO (this->name, frame, err);
        GF_VALIDATE_OR_GOTO (this->name, inode, err);

        local  = frame->local;
        GF_VALIDATE_OR_GOTO (this->name, local, err);

        if (local->par_frame) {
                par_local = local->par_frame->local;
                GF_VALIDATE_OR_GOTO (this->name, par_local, err);
        } else {
                par_local = local;
        }

        delta = par_local->delta;

        GF_VALIDATE_OR_GOTO (this->name, par_local->stub, err);
        /* Allow all the trusted clients
         * Don't block the gluster internal processes like rebalance, gsyncd,
         * self heal etc from the disk quotas.
         *
         * Method: Allow all the clients with PID negative. This is by the
         * assumption that any kernel assigned pid doesn't have the negative
         * number.
         */
        if (0 > frame->root->pid) {
                ret = 0;
                xquota_link_count_decrement (frame);
                goto done;
        }

        priv = this->private;

        inode_ctx_get (inode, this, &value);
        ctx = (xquota_inode_ctx_t *)(unsigned long)value;

        _inode = inode_ref (inode);

        LOCK (&local->lock);
        {
                just_validated = local->just_validated;
                local->just_validated = 0;
        }
        UNLOCK (&local->lock);

        ret = xquota_check_size_limit (frame, ctx, priv, _inode, this,
                                       &op_errno, just_validated, delta,
                                       par_local, &skip_check);
        if (skip_check == _gf_true)
                goto done;

        if (ret) {
                if (op_errno != EDQUOT)
                        gf_msg (this->name, GF_LOG_ERROR, 0,
                                XQ_MSG_ENFORCEMENT_FAILED, "Failed to "
                                "check xquota size limit");
                goto err;
        }

        xquota_link_count_decrement (frame);
done:
        inode_unref (_inode);
        return 0;

err:
        xquota_handle_validate_error (frame, -1, op_errno);
        inode_unref (_inode);
        return 0;
}

int32_t
xquota_writev (call_frame_t *frame, xlator_t *this,
               fd_t *fd, struct iovec * vector,
               int32_t count, off_t off, uint32_t flags,
               struct iobref *iobref, dict_t *xdata)
{
        xquota_priv_t      *priv       = NULL;
        int32_t             op_errno   = EINVAL;
        uint64_t            size       = 0;
        xquota_local_t     *local      = NULL;
        xquota_inode_ctx_t *ctx        = NULL;
        call_stub_t        *stub       = NULL;

        priv = this->private;

        WIND_IF_XQUOTAOFF (priv->is_xquota_on, off);

        GF_ASSERT (frame);
        GF_VALIDATE_OR_GOTO ("xquota", this, unwind);
        GF_VALIDATE_OR_GOTO (this->name, fd, unwind);

        local = xquota_local_new ();
        if (local == NULL) {
                goto unwind;
        }

        frame->local = local;
        local->loc.inode = inode_ref (fd->inode);

        (void) xquota_inode_ctx_get (fd->inode, this, &ctx, 0);
        if (ctx == NULL) {
                gf_msg_debug (this->name, 0, "xquota context is NULL on inode"
                              " (%s). If xquota is not enabled recently and "
                              "crawler has finished crawling, its an error",
                              uuid_utoa (fd->inode->gfid));
        }

        stub = fop_writev_stub (frame, xquota_writev_helper, fd, vector, count,
                                off, flags, iobref, xdata);
        if (stub == NULL) {
                op_errno = ENOMEM;
                goto unwind;
        }

        priv = this->private;
        GF_VALIDATE_OR_GOTO (this->name, priv, unwind);

        size = iov_length (vector, count);

        LOCK (&local->lock);
        {
                local->delta = size;
                local->link_count = 1;
                local->stub = stub;
        }
        UNLOCK (&local->lock);

        xquota_check_limit (frame, fd->inode, this);
        return 0;

unwind:
        XQUOTA_STACK_UNWIND (writev, frame, -1, op_errno, NULL, NULL, NULL);
        return 0;

off:
        STACK_WIND_TAIL (frame, FIRST_CHILD(this),
                         FIRST_CHILD(this)->fops->writev, fd,
                         vector, count, off, flags, iobref, xdata);
        return 0;
}

int32_t
xquota_lookup_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, inode_t *inode,
                   struct iatt *buf, dict_t *xdata, struct iatt *postparent)
{
        xquota_local_t      *local        = NULL;
        inode_t             *this_inode   = NULL;

        local = frame->local;
        frame->local = NULL;

        if (op_ret >= 0 && inode) {
                this_inode = inode_ref (inode);

                op_ret = xquota_fill_inodectx (this, inode, xdata, &local->loc,
                                               buf, &op_errno);
                if (op_ret < 0)
                        op_errno = ENOMEM;
        }

        XQUOTA_STACK_UNWIND (lookup, frame, op_ret, op_errno, inode, buf,
                             xdata, postparent);

        if (op_ret < 0 || this_inode == NULL || gf_uuid_is_null(this_inode->gfid))
                goto out;

out:
        if (this_inode)
                inode_unref (this_inode);

        xquota_local_cleanup (local);

        return 0;
}


int32_t
xquota_lookup (call_frame_t *frame, xlator_t *this,
               loc_t *loc, dict_t *xattr_req)
{
        xquota_priv_t  *priv             = NULL;
        int32_t         ret              = -1;
        xquota_local_t *local            = NULL;

        priv = this->private;

        WIND_IF_XQUOTAOFF (priv->is_xquota_on, off);

        xattr_req = xattr_req ? dict_ref(xattr_req) : dict_new();
        if (!xattr_req)
                goto err;

        local = xquota_local_new ();
        if (local == NULL) {
                goto err;
        }

        frame->local = local;
        loc_copy (&local->loc, loc);

        ret = dict_set_int8 (xattr_req, VIRTUAL_XQUOTA_USAGE_META_KEY, 1);
        if (ret < 0) {
                gf_msg (this->name, GF_LOG_WARNING, ENOMEM,
			XQ_MSG_ENOMEM, "dict set of key for "
                        "hard-limit failed");
                goto err;
        }

        STACK_WIND (frame, xquota_lookup_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->lookup, loc, xattr_req);

        ret = 0;

err:
        if (xattr_req)
                dict_unref (xattr_req);

        if (ret < 0) {
                XQUOTA_STACK_UNWIND (lookup, frame, -1, ENOMEM,
                                     NULL, NULL, NULL, NULL);
        }

        return 0;

off:
        STACK_WIND_TAIL (frame, FIRST_CHILD(this),
                         FIRST_CHILD(this)->fops->lookup, loc, xattr_req);
        return 0;
}

int32_t
xquota_readdirp_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                     int32_t op_ret, int32_t op_errno, gf_dirent_t *entries,
                     dict_t *xdata)
{
        gf_dirent_t    *entry = NULL;
        xquota_local_t *local = NULL;
        loc_t           loc   = {0, };

        if (op_ret <= 0)
                goto unwind;

        local = frame->local;

        list_for_each_entry (entry, &entries->list, list) {
                if ((strcmp (entry->d_name, ".") == 0)  ||
                    (strcmp (entry->d_name, "..") == 0) ||
                    entry->inode == NULL)
                        continue;

                gf_uuid_copy (loc.gfid, entry->d_stat.ia_gfid);
                loc.inode = inode_ref (entry->inode);
                loc.parent = inode_ref (local->loc.inode);
                gf_uuid_copy (loc.pargfid, loc.parent->gfid);
                loc.name = entry->d_name;

                xquota_fill_inodectx (this, entry->inode, entry->dict,
                                      &loc, &entry->d_stat, &op_errno);

                loc_wipe (&loc);
        }

unwind:
        XQUOTA_STACK_UNWIND (readdirp, frame, op_ret, op_errno, entries, xdata);
        return 0;
}


int32_t
xquota_readdirp (call_frame_t *frame, xlator_t *this,
                 fd_t *fd, size_t size, off_t off,
                 dict_t *dict)
{
        xquota_priv_t  *priv     = NULL;
        int             ret      = 0;
        gf_boolean_t    new_dict = _gf_false;
        xquota_local_t *local    = NULL;

        priv = this->private;

        WIND_IF_XQUOTAOFF (priv->is_xquota_on, off);

        local = xquota_local_new ();

        if (local == NULL) {
                goto err;
        }

        frame->local = local;

        local->loc.inode = inode_ref (fd->inode);

        if (dict == NULL) {
                dict = dict_new ();
                new_dict = _gf_true;
        }

        if (dict) {
                ret = dict_set_int8 (dict, VIRTUAL_XQUOTA_USAGE_META_KEY, 1);
                if (ret < 0) {
                        gf_msg (this->name, GF_LOG_WARNING, ENOMEM,
				XQ_MSG_ENOMEM,
				"dict set of key for hard-limit");
                        goto err;
                }
        }

        STACK_WIND (frame, xquota_readdirp_cbk,
                    FIRST_CHILD(this), FIRST_CHILD(this)->fops->readdirp, fd,
                    size, off, dict);

        if (new_dict) {
                dict_unref (dict);
        }

        return 0;
err:
        STACK_UNWIND_STRICT (readdirp, frame, -1, EINVAL, NULL, NULL);

        if (new_dict) {
                dict_unref (dict);
        }

        return 0;

off:
        STACK_WIND_TAIL (frame, FIRST_CHILD(this),
                         FIRST_CHILD(this)->fops->readdirp, fd,
                         size, off, dict);
        return 0;
}

int32_t
xquota_create_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, fd_t *fd, inode_t *inode,
                   struct iatt *buf, struct iatt *preparent,
                   struct iatt *postparent, dict_t *xdata)
{
        int32_t             ret    = -1;
        xquota_inode_ctx_t *ctx    = NULL;

        if (op_ret < 0) {
                goto unwind;
        }

        ret = xquota_inode_ctx_get (inode, this, &ctx, 1);
        if ((ret == -1) || (ctx == NULL)) {
                gf_msg (this->name, GF_LOG_WARNING, ENOMEM,
                        XQ_MSG_INODE_CTX_GET_FAILED, "cannot create xquota "
                        "context in inode(gfid:%s)", uuid_utoa (inode->gfid));
                op_ret = -1;
                op_errno = ENOMEM;
                goto unwind;
        }

        LOCK (&ctx->lock);
        {
                ctx->buf = *buf;
        }
        UNLOCK (&ctx->lock);

unwind:
        XQUOTA_STACK_UNWIND (create, frame, op_ret, op_errno, fd, inode, buf,
                             preparent, postparent, xdata);
        return 0;
}


int32_t
xquota_create_helper (call_frame_t *frame, xlator_t *this, loc_t *loc,
                      int32_t flags, mode_t mode, mode_t umask, fd_t *fd,
                      dict_t *xdata)
{
        xquota_local_t *local    = NULL;
        int32_t        op_errno  = EINVAL;

        local = frame->local;

        GF_VALIDATE_OR_GOTO ("xquota", local, unwind);

        if (local->op_ret == -1) {
                op_errno = local->op_errno;
                goto unwind;
        }


        STACK_WIND (frame, xquota_create_cbk,
                    FIRST_CHILD (this), FIRST_CHILD (this)->fops->create, loc,
                    flags, mode, umask, fd, xdata);
        return 0;

unwind:
        XQUOTA_STACK_UNWIND (create, frame, -1, op_errno, NULL, NULL,
                             NULL, NULL, NULL, NULL);
        return 0;
}


int32_t
xquota_create (call_frame_t *frame, xlator_t *this, loc_t *loc, int32_t flags,
               mode_t mode, mode_t umask, fd_t *fd, dict_t *xdata)
{
        xquota_priv_t  *priv     = NULL;
        int32_t        ret       = -1;
        xquota_local_t *local    = NULL;
        int32_t        op_errno  = 0;
        call_stub_t   *stub      = NULL;

        priv = this->private;

        WIND_IF_XQUOTAOFF (priv->is_xquota_on, off);
        XQUOTA_WIND_FOR_INTERNAL_FOP (xdata, off);

        local = xquota_local_new ();
        if (local == NULL) {
                op_errno = ENOMEM;
                goto err;
        }

        frame->local = local;

        ret = loc_copy (&local->loc, loc);
        if (ret) {
                gf_msg (this->name, GF_LOG_WARNING, ENOMEM,
			XQ_MSG_ENOMEM, "loc_copy failed");
                op_errno = ENOMEM;
                goto err;
        }

        stub = fop_create_stub (frame, xquota_create_helper, loc, flags, mode,
                                umask, fd, xdata);
        if (stub == NULL) {
                goto err;
        }

        LOCK (&local->lock);
        {
                local->link_count = 1;
                local->stub = stub;
                local->delta = 0;
        }
        UNLOCK (&local->lock);

        xquota_check_limit (frame, loc->parent, this);
        return 0;
err:
        XQUOTA_STACK_UNWIND (create, frame, -1, op_errno, NULL, NULL, NULL,
                             NULL, NULL, NULL);

        return 0;

off:
        STACK_WIND_TAIL (frame, FIRST_CHILD (this),
                         FIRST_CHILD (this)->fops->create, loc,
                         flags, mode, umask, fd, xdata);
        return 0;
}

int32_t
xquota_forget (xlator_t *this,
	inode_t *inode)
{
        return 0;
}

int32_t
xquota_priv (xlator_t *this)
{
        xquota_priv_t *priv = NULL;
        int32_t        ret  = -1;


        GF_ASSERT (this);

        priv = this->private;

        gf_proc_dump_add_section ("xlators.features.xquota.priv", this->name);

        ret = TRY_LOCK (&priv->lock);
        if (ret)
             goto out;
        else {
                gf_proc_dump_write("soft-timeout", "%d", priv->soft_timeout);
                gf_proc_dump_write("hard-timeout", "%d", priv->hard_timeout);
                gf_proc_dump_write("alert-time", "%d", priv->log_timeout);
                gf_proc_dump_write("xquota-on", "%d", priv->is_xquota_on);
                gf_proc_dump_write("statfs", "%d", priv->consider_statfs);
                gf_proc_dump_write("volume-uuid", "%s", priv->volume_uuid);
                gf_proc_dump_write("validation-count", "%ld",
                                    priv->validation_count);
        }
        UNLOCK (&priv->lock);

out:
        return 0;
}

int32_t
mem_acct_init (xlator_t *this)
{
        int     ret = -1;

        if (!this)
                return ret;

        ret = xlator_mem_acct_init (this, gf_xquota_mt_end + 1);

        if (ret != 0) {
                gf_msg (this->name, GF_LOG_WARNING, ENOMEM, XQ_MSG_ENOMEM,
                        "Memory accounting init failed");
                return ret;
        }

        return ret;
}

int32_t
init (xlator_t *this)
{
        int32_t        ret  = -1;
        xquota_priv_t *priv = NULL;
        rpc_clnt_t    *rpc  = NULL;

        if ((this->children == NULL)
            || this->children->next) {
                gf_msg (this->name, GF_LOG_ERROR, 0,
                        XQ_MSG_INVALID_VOLFILE,
                        "FATAL: xquota (%s) not configured with "
                        "exactly one child", this->name);
                return -1;
        }

        if (this->parents == NULL) {
                gf_msg (this->name, GF_LOG_WARNING, 0,
                        XQ_MSG_INVALID_VOLFILE,
                        "dangling volume. check volfile");
        }

        XQUOTA_ALLOC_OR_GOTO (priv, xquota_priv_t, err);

        LOCK_INIT (&priv->lock);

        this->private = priv;

        GF_OPTION_INIT ("deem-statfs", priv->consider_statfs, bool, err);
        GF_OPTION_INIT ("server-xquota", priv->is_xquota_on, bool, err);
        GF_OPTION_INIT ("default-soft-limit", priv->default_soft_lim, percent,
                        err);
        GF_OPTION_INIT ("soft-timeout", priv->soft_timeout, time, err);
        GF_OPTION_INIT ("hard-timeout", priv->hard_timeout, time, err);
        GF_OPTION_INIT ("alert-time", priv->log_timeout, time, err);
        GF_OPTION_INIT ("volume-uuid", priv->volume_uuid, str, err);

        this->local_pool = mem_pool_new (xquota_local_t, 64);
        if (!this->local_pool) {
                ret = -1;
                gf_msg (this->name, GF_LOG_ERROR, ENOMEM,
			XQ_MSG_ENOMEM, "failed to create local_t's memory pool");
                goto err;
        }

        if (priv->is_xquota_on) {
                rpc = xquota_enforcer_init (this, this->options);
                if (rpc == NULL) {
                        ret = -1;
                        gf_msg (this->name, GF_LOG_WARNING, 0,
				XQ_MSG_XQUOTA_ENFORCER_RPC_INIT_FAILED,
				"xquota enforcer rpc init failed");
                        goto err;
                }

                LOCK (&priv->lock);
                {
                        priv->rpc_clnt = rpc;
                }
                UNLOCK (&priv->lock);
        }

        ret = 0;
err:
        return ret;
}

void
fini (xlator_t *this)
{
        return;
}

int32_t
reconfigure (xlator_t *this, dict_t *options)
{
        int32_t        ret       = -1;
        xquota_priv_t *priv      = NULL;
        gf_boolean_t   xquota_on = _gf_false;
        rpc_clnt_t    *rpc       = NULL;

        priv = this->private;

        GF_OPTION_RECONF ("deem-statfs", priv->consider_statfs, options, bool,
                          out);
        GF_OPTION_RECONF ("server-xquota", xquota_on, options, bool,
                          out);
        GF_OPTION_RECONF ("default-soft-limit", priv->default_soft_lim,
                          options, percent, out);
        GF_OPTION_RECONF ("alert-time", priv->log_timeout, options,
                          time, out);
        GF_OPTION_RECONF ("soft-timeout", priv->soft_timeout, options,
                          time, out);
        GF_OPTION_RECONF ("hard-timeout", priv->hard_timeout, options,
                          time, out);

        if (xquota_on) {
                priv->rpc_clnt = xquota_enforcer_init (this,
                                                       this->options);
                if (priv->rpc_clnt == NULL) {
                        ret = -1;
                        gf_msg (this->name, GF_LOG_WARNING, 0,
				XQ_MSG_XQUOTA_ENFORCER_RPC_INIT_FAILED,
				"xquota enforcer rpc init failed");
                        goto out;
                }

        } else {
                LOCK (&priv->lock);
                {
                        rpc = priv->rpc_clnt;
                        priv->rpc_clnt = NULL;
                }
                UNLOCK (&priv->lock);

                if (rpc != NULL) {
                        // XQuotad is shutdown when there is no started volume
                        // which has xquota enabled. So, we should disable the
                        // enforcer client when xquota is disabled on a volume,
                        // to avoid spurious reconnect attempts to a service
                        // (xquotad), that is known to be down.
                        rpc_clnt_unref (rpc);
                }
        }

        priv->is_xquota_on = xquota_on;

        ret = 0;
out:
        return ret;
}

int
notify (xlator_t *this, int event, void *data, ...)
{
        return default_notify (this, event, data);
}


struct xlator_fops fops = {
        .create               = xquota_create,
        .lookup               = xquota_lookup,
        .writev               = xquota_writev,
        .readv                = xquota_readv,
        .readdirp             = xquota_readdirp,
};
struct xlator_cbks cbks = {
        .forget               = xquota_forget,
};
struct xlator_dumpops dumpops = {
        .priv                 = xquota_priv,
};

struct volume_options options[] = {
        {.key = {"limit-usage-project"}},
        {.key = {"deem-statfs"},
         .type = GF_OPTION_TYPE_BOOL,
         .default_value = "on",
         .description = "If set to on, it takes xquota limits into"
                        " consideration while estimating fs size. (df command)"
                        " (Default is on)."
        },
        {.key = {"server-xquota"},
         .type = GF_OPTION_TYPE_BOOL,
         .default_value = "off",
         .description = "Skip the xquota enforcement if the feature is"
                        " not turned on. This is not a user exposed option."
        },
        {.key = {"default-soft-limit"},
         .type = GF_OPTION_TYPE_PERCENT,
         .default_value = "80%",
        },
        {.key = {"soft-timeout"},
         .type = GF_OPTION_TYPE_TIME,
         .min = 0,
         .max = 1800,
         .default_value = "60",
         .description = "xquota caches the directory sizes on client. "
                        "soft-timeout indicates the timeout for the validity of"
                        " cache before soft-limit has been crossed."
        },
        {.key = {"hard-timeout"},
         .type = GF_OPTION_TYPE_TIME,
         .min = 0,
         .max = 60,
         .default_value = "5",
         .description = "xquota caches the directory sizes on client. "
                        "hard-timeout indicates the timeout for the validity of"
                        " cache after soft-limit has been crossed."
        },
        { .key   = {"username"},
          .type  = GF_OPTION_TYPE_ANY,
        },
        { .key   = {"password"},
          .type  = GF_OPTION_TYPE_ANY,
        },
        { .key   = {"transport-type"},
          .value = {"tcp", "socket", "ib-verbs", "unix", "ib-sdp",
                    "tcp/client", "ib-verbs/client", "rdma"},
          .type  = GF_OPTION_TYPE_STR,
        },
        { .key   = {"remote-host"},
          .type  = GF_OPTION_TYPE_INTERNET_ADDRESS,
        },
        { .key   = {"remote-port"},
          .type  = GF_OPTION_TYPE_INT,
        },
        { .key  = {"volume-uuid"},
          .type = GF_OPTION_TYPE_STR,
          .description = "uuid of the volume this brick is part of."
        },
        { .key  = {"alert-time"},
          .type = GF_OPTION_TYPE_TIME,
          .min = 0,
          .max = 7*86400,
          .default_value = "86400",
        },
        {.key = {NULL}}
};
