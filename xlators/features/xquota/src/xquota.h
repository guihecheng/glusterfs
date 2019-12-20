#ifndef __XQUOTA_H__
#define __XQUOTA_H__

#include "xlator.h"
#include "call-stub.h"
#include "defaults.h"
#include "common-utils.h"
#include "xquota-mem-types.h"
#include "glusterfs.h"
#include "compat.h"
#include "logging.h"
#include "dict.h"
#include "stack.h"
#include "event.h"
#include "globals.h"
#include "rpcsvc.h"
#include "rpc-clnt.h"
#include "byte-order.h"
#include "glusterfs3-xdr.h"
#include "glusterfs3.h"
#include "xdr-generic.h"
#include "compat-errno.h"
#include "protocol-common.h"
#include "xquota-common-utils.h"
#include "xquota-messages.h"

struct xquota_local {
        gf_lock_t               lock;
        uint32_t                link_count;
        loc_t                   loc;
        loc_t                   oldloc;
        loc_t                   newloc;
        loc_t                   validate_loc;
        int64_t                 delta;
        int32_t                 op_ret;
        int32_t                 op_errno;
        int64_t                 size;
        char                    just_validated;
        fop_lookup_cbk_t        validate_cbk;
        inode_t                *inode;
        call_stub_t            *stub;
        struct iobref          *iobref;
        int64_t                 space_available;
        dict_t                 *xdata;
        dict_t                 *validate_xdata;
        int32_t                 xquotad_conn_retry;
        xlator_t               *this;
        call_frame_t           *par_frame;
};
typedef struct xquota_local     xquota_local_t;

struct xquota_priv {
        uint32_t               soft_timeout;
        uint32_t               hard_timeout;
        uint32_t               log_timeout;
        double                 default_soft_lim;
        gf_boolean_t           is_xquota_on;
        gf_boolean_t           consider_statfs;
        gf_lock_t              lock;
        rpc_clnt_prog_t       *xquota_enforcer;
        struct rpcsvc_program *xquotad_aggregator;
        struct rpc_clnt       *rpc_clnt;
        rpcsvc_t              *rpcsvc;
        inode_table_t         *itable;
        char                  *volume_uuid;
        uint64_t               validation_count;
        int32_t                xquotad_conn_status;
};
typedef struct xquota_priv     xquota_priv_t;

struct xquota_inode_ctx {
        uint64_t         usage;
        uint64_t         hard_lim;
        uint64_t         soft_lim;
        struct iatt      buf;
        struct timeval   tv;
        struct timeval   prev_log;
        gf_lock_t        lock;
};
typedef struct xquota_inode_ctx xquota_inode_ctx_t;

#define XQUOTA_ALLOC_OR_GOTO(var, type, label)          \
        do {                                            \
                var = GF_CALLOC (sizeof (type), 1,      \
                                 gf_xquota_mt_##type);  \
                if (!var) {                             \
                        gf_msg ("", GF_LOG_ERROR,       \
                                ENOMEM, XQ_MSG_ENOMEM,  \
                "out of memory");                       \
                        ret = -1;                       \
                        goto label;                     \
                }                                       \
        } while (0);

#define WIND_IF_XQUOTAOFF(is_xquota_on, label)          \
        if (!is_xquota_on)                              \
                goto label;

#define XQUOTA_WIND_FOR_INTERNAL_FOP(xdata, label)                          \
        do {                                                               \
                if (xdata && dict_get (xdata, GLUSTERFS_INTERNAL_FOP_KEY)) \
                goto label;                                                \
        } while (0)

#define XQUOTA_REG_OR_LNK_FILE(ia_type)                 \
        (IA_ISREG (ia_type) || IA_ISLNK (ia_type))

#define XQUOTA_STACK_UNWIND(fop, frame, params...)                      \
        do {                                                            \
                xquota_local_t *_local = NULL;                          \
                if (frame) {                                            \
                        _local = frame->local;                          \
                        frame->local = NULL;                            \
                }                                                       \
                STACK_UNWIND_STRICT (fop, frame, params);               \
                xquota_local_cleanup (_local);                          \
        } while (0)

#define DID_REACH_LIMIT(lim, prev_size, cur_size)        \
        ((cur_size) >= (lim) && (prev_size) < (lim))

int
xquota_enforcer_lookup (call_frame_t *frame, xlator_t *this, dict_t *xdata,
                        fop_lookup_cbk_t cbk);

void
_xquota_enforcer_lookup (void *data);

struct rpc_clnt *
xquota_enforcer_init (xlator_t *this, dict_t *options);

void
xquota_log_usage (xlator_t *this, xquota_inode_ctx_t *ctx, inode_t *inode,
                  int64_t delta);

int32_t
xquota_check_limit (call_frame_t *frame, inode_t *inode, xlator_t *this);

int
xquota_fill_inodectx (xlator_t *this, inode_t *inode, dict_t *dict,
                      loc_t *loc, struct iatt *buf, int32_t *op_errno);

int32_t
xquota_check_size_limit (call_frame_t *frame, xquota_inode_ctx_t *ctx,
                         xquota_priv_t *priv, inode_t *_inode, xlator_t *this,
                         int32_t *op_errno, int just_validated, int64_t delta,
                         xquota_local_t *local, gf_boolean_t *skip_check);

#endif /* __XQUOTA_H__ */
