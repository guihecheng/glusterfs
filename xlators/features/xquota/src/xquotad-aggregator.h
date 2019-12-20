#ifndef _XQUOTAD_AGGREGATOR_H
#define _XQUOTAD_AGGREGATOR_H

#include "xquota.h"
#include "stack.h"
#include "glusterfs3-xdr.h"
#include "inode.h"

typedef struct {
        void          *pool;
        xlator_t      *this;
        xlator_t      *active_subvol;
        inode_table_t *itable;
        loc_t          loc;
        dict_t        *xdata;
} xquotad_aggregator_state_t;

typedef int (*xquotad_aggregator_lookup_cbk_t) (xlator_t *this,
                                                call_frame_t *frame,
                                                void *rsp);
int
xqd_nameless_lookup (xlator_t *this, call_frame_t *frame, gfs3_lookup_req *req,
                     dict_t *xdata, xquotad_aggregator_lookup_cbk_t lookup_cbk);
int
xquotad_aggregator_init (xlator_t *this);

#endif
