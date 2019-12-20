#include "xquotad-helpers.h"

xquotad_aggregator_state_t *
get_xquotad_aggregator_state (xlator_t *this, rpcsvc_request_t *req)
{
        xquotad_aggregator_state_t *state         = NULL;
        xlator_t                   *active_subvol = NULL;
        xquota_priv_t              *priv          = NULL;

        state = (void *)GF_CALLOC (1, sizeof (*state),
                                   gf_xquota_mt_aggregator_state_t);
        if (!state)
                return NULL;

        state->this = THIS;
        priv = this->private;

        LOCK (&priv->lock);
        {
                active_subvol = state->active_subvol = FIRST_CHILD (this);
        }
        UNLOCK (&priv->lock);

        if (active_subvol->itable == NULL)
                active_subvol->itable = inode_table_new (4096, active_subvol);

        state->itable = active_subvol->itable;

        state->pool = this->ctx->pool;

        return state;
}

void
xquotad_aggregator_free_state (xquotad_aggregator_state_t *state)
{
        if (state->xdata)
                dict_unref (state->xdata);

        GF_FREE (state);
}

call_frame_t *
xquotad_aggregator_alloc_frame (rpcsvc_request_t *req)
{
        call_frame_t               *frame = NULL;
        xquotad_aggregator_state_t *state = NULL;
        xlator_t                   *this  = NULL;

        GF_VALIDATE_OR_GOTO ("server", req, out);
        GF_VALIDATE_OR_GOTO ("server", req->trans, out);
        GF_VALIDATE_OR_GOTO ("server", req->svc, out);
        GF_VALIDATE_OR_GOTO ("server", req->svc->ctx, out);

        this = req->svc->xl;

        frame = create_frame (this, req->svc->ctx->pool);
        if (!frame)
                goto out;

        state = get_xquotad_aggregator_state (this, req);
        if (!state)
                goto out;

        frame->root->state = state;
        frame->root->unique = 0;

        frame->this = this;
out:
        return frame;
}

call_frame_t *
xquotad_aggregator_get_frame_from_req (rpcsvc_request_t *req)
{
        call_frame_t *frame  = NULL;

        GF_VALIDATE_OR_GOTO ("server", req, out);

        frame = xquotad_aggregator_alloc_frame (req);
        if (!frame)
                goto out;

        frame->root->op       = req->procnum;

        frame->root->unique   = req->xid;

        frame->root->uid      = req->uid;
        frame->root->gid      = req->gid;
        frame->root->pid      = req->pid;

        frame->root->lk_owner = req->lk_owner;

        frame->local = req;
out:
        return frame;
}
