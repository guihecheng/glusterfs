#include "cli-xquotad-client.h"

extern struct rpc_clnt global_xquotad_rpc;
extern struct rpc_clnt_program cli_xquotad_clnt;

int
cli_xquotad_submit_request (void *req, call_frame_t *frame,
                            rpc_clnt_prog_t *prog,
                            int procnum, struct iobref *iobref,
                            xlator_t *this, fop_cbk_fn_t cbkfn,
                            xdrproc_t xdrproc)
{
        int           ret        = -1;
        int           count      = 0;
        struct iovec  iov        = {0, };
        struct iobuf *iobuf      = NULL;
        char          new_iobref = 0;
        ssize_t       xdr_size   = 0;

        GF_ASSERT (this);

        if (req) {
                xdr_size = xdr_sizeof (xdrproc, req);
                iobuf = iobuf_get2 (this->ctx->iobuf_pool, xdr_size);
                if (!iobuf) {
                        goto out;
                };

                if (!iobref) {
                        iobref = iobref_new ();
                        if (!iobref) {
                                goto out;
                        }

                        new_iobref = 1;
                }

                iobref_add (iobref, iobuf);

                iov.iov_base = iobuf->ptr;
                iov.iov_len  = iobuf_size (iobuf);

                /* Create the xdr payload */
                ret = xdr_serialize_generic (iov, req, xdrproc);
                if (ret == -1) {
                        goto out;
                }
                iov.iov_len = ret;
                count = 1;
        }

        /* Send the msg */
        ret = rpc_clnt_submit (&global_xquotad_rpc, prog, procnum, cbkfn,
                               &iov, count,
                               NULL, 0, iobref, frame, NULL, 0, NULL, 0, NULL);
        ret = 0;

out:
        if (new_iobref)
                iobref_unref (iobref);
        if (iobuf)
                iobuf_unref (iobuf);

        return ret;
}

int
cli_xquotad_notify (struct rpc_clnt *rpc, void *mydata,
                    rpc_clnt_event_t event, void *data)
{
        xlator_t                *this = NULL;
        int                     ret = 0;

        this = mydata;

        switch (event) {
        case RPC_CLNT_CONNECT:
        {
                gf_log (this->name, GF_LOG_TRACE, "got RPC_CLNT_CONNECT");
                break;
        }

        case RPC_CLNT_DISCONNECT:
        {
                gf_log (this->name, GF_LOG_TRACE, "got RPC_CLNT_DISCONNECT");
                break;
        }

        default:
                gf_log (this->name, GF_LOG_TRACE,
                        "got some other RPC event %d", event);
                ret = 0;
                break;
        }

        return ret;
}

struct rpc_clnt *
cli_xquotad_clnt_init (xlator_t *this, dict_t *options)
{
        struct rpc_clnt *rpc  = NULL;
        int              ret  = -1;


        ret = dict_set_str (options, "transport.address-family", "unix");
        if (ret)
                goto out;

        ret = dict_set_str (options, "transport-type", "socket");
        if (ret)
                goto out;

        ret = dict_set_str (options, "transport.socket.connect-path",
                            "/var/run/gluster/xquotad.socket");
        if (ret)
                goto out;

        rpc = rpc_clnt_new (options, this, this->name, 16);
        if (!rpc)
                goto out;

        ret = rpc_clnt_register_notify (rpc, cli_xquotad_notify, this);
        if (ret) {
                gf_log ("cli", GF_LOG_ERROR, "failed to register notify");
                goto out;
        }

        rpc_clnt_start (rpc);
out:
        if (ret) {
                if (rpc)
                        rpc_clnt_unref (rpc);
                rpc = NULL;
        }

        return rpc;
}
