#ifndef __XQUOTA_MEM_TYPES_H__
#define __XQUOTA_MEM_TYPES_H__

#include "mem-types.h"

enum gf_xquota_mem_types_ {
        gf_xquota_mt_xquota_inode_ctx_t = gf_common_mt_end + 1,
        gf_xquota_mt_xquota_priv_t,
        gf_xquota_mt_aggregator_state_t,
        gf_xquota_mt_end
};
#endif /* __XQUOTA_MEM_TYPES_H__ */

