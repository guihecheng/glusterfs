#ifndef __DIR_WORM_MEM_TYPES_H__
#define __DIR_WORM_MEM_TYPES_H__

#include "mem-types.h"

enum gf_dir_worm_mem_types_ {
        gf_dir_worm_mt_priv_t = gf_common_mt_end + 1,
        gf_dir_worm_mt_local_t,
        gf_dir_worm_mt_end
};
#endif
