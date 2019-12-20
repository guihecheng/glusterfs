#include "cli.h"
#include "compat-errno.h"
#include "compat.h"
#include "cli-cmd.h"
#include "cli1-xdr.h"
#include "xdr-generic.h"
#include "protocol-common.h"
#include "cli-mem-types.h"


int
cli_xquotad_submit_request (void *req, call_frame_t *frame,
                            rpc_clnt_prog_t *prog,
                            int procnum, struct iobref *iobref,
                            xlator_t *this, fop_cbk_fn_t cbkfn,
                            xdrproc_t xdrproc);

struct rpc_clnt *
cli_xquotad_clnt_init (xlator_t *this, dict_t *options);

int
cli_xquotad_notify (struct rpc_clnt *rpc, void *mydata,
                    rpc_clnt_event_t event, void *data);
