/*
  Copyright (c) 2008-2012 Red Hat, Inc. <http://www.redhat.com>
  This file is part of GlusterFS.

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.
*/

#ifndef _GLOBALS_H
#define _GLOBALS_H

#define GF_DEFAULT_BASE_PORT 24007
#define GF_DEFAULT_VOLFILE_TRANSPORT "tcp"

#define GD_OP_VERSION_KEY     "operating-version"
#define GD_MIN_OP_VERSION_KEY "minimum-operating-version"
#define GD_MAX_OP_VERSION_KEY "maximum-operating-version"

/* RHS versions - OP-VERSION mapping
 *
 * RHS-2.0 Z    - 1
 * RHS-2.1 Z    - 2
 * RHS-2.1 u5   - 20105
 * RHS-3.0      - 30000
 * RHS-3.0.4    - 30004
 * RHGS-3.1     - 30702
 *
 *
 * NOTE:
 * Starting with RHS-3.0, the op-version will be multi-digit integer values
 * based on the RHS version, instead of a simply incrementing integer value. The
 * op-version for a given RHS X(Major).Y(Minor).Z(Update) release will be an
 * integer with digits XYZ. The Y and Z values will be 2 digits wide always
 * padded with 0 as needed. This should allow for some gaps between two Y
 * releases for backports of features in Z releases.
 *
 * NOTE:
 * Starting with RHGS-3.1, the op-version will be the same as the upstream
 * GlusterFS op-versions. This is to allow proper access to upstream clients of
 * version 3.7.x or greater, proper access to the RHGS volumes.
 */
#define GD_OP_VERSION_MIN  1 /* MIN is the fresh start op-version, mostly
                                should not change */
#define GD_OP_VERSION_MAX  GD_OP_VERSION_3_13_3 /* MAX VERSION is the maximum
                                                  count in VME table, should
                                                  keep changing with
                                                  introduction of newer
                                                  versions */

#define GD_OP_VERSION_RHS_3_0    30000 /* Op-Version of RHS 3.0 */

#define GD_OP_VER_PERSISTENT_AFR_XATTRS GD_OP_VERSION_RHS_3_0

#define GD_OP_VERSION_RHS_2_1_5  20105 /* RHS 2.1 update 5 */

#define GD_OP_VERSION_RHS_3_0_4  30004 /* Op-Version of RHS 3.0.4 */

#define GD_OP_VERSION_3_7_0    30700 /* Op-version for GlusterFS 3.7.0 */

#define GD_OP_VERSION_3_7_1    30701 /* Op-version for GlusterFS 3.7.1 */

#define GD_OP_VERSION_3_7_2    30702 /* Op-version for GlusterFS 3.7.2 */

#define GD_OP_VERSION_3_7_3    30703 /* Op-version for GlusterFS 3.7.3 */

#define GD_OP_VERSION_3_7_4    30704 /* Op-version for GlusterFS 3.7.4 */

#define GD_OP_VERSION_3_7_5    30705 /* Op-version for GlusterFS 3.7.5 */

#define GD_OP_VERSION_3_7_6    30706 /* Op-version for GlusterFS 3.7.6 */

#define GD_OP_VERSION_3_7_7    30707 /* Op-version for GlusterFS 3.7.7 */

#define GD_OP_VERSION_3_7_10   30710 /* Op-version for GlusterFS 3.7.10 */

#define GD_OP_VERSION_3_7_12   30712 /* Op-version for GlusterFS 3.7.12 */

#define GD_OP_VERSION_3_8_0    30800 /* Op-version for GlusterFS 3.8.0 */

#define GD_OP_VERSION_3_8_3    30803 /* Op-version for GlusterFS 3.8.3 */

#define GD_OP_VERSION_3_8_4    30804 /* Op-version for GlusterFS 3.8.4 */

#define GD_OP_VERSION_3_9_0    30900 /* Op-version for GlusterFS 3.9.0 */

#define GD_OP_VERSION_3_9_1    30901 /* Op-version for GlusterFS 3.9.1 */

#define GD_OP_VERSION_3_10_0   31000 /* Op-version for GlusterFS 3.10.0 */

#define GD_OP_VERSION_3_10_1   31001 /* Op-version for GlusterFS 3.10.1 */

#define GD_OP_VERSION_3_10_2   31002 /* Op-version for GlusterFS 3.10.2 */

#define GD_OP_VERSION_3_11_0   31100 /* Op-version for GlusterFS 3.11.0 */

#define GD_OP_VERSION_3_11_1   31101 /* Op-version for GlusterFS 3.11.1 */

#define GD_OP_VERSION_3_12_0   31200 /* Op-version for GlusterFS 3.12.0 */

#define GD_OP_VERSION_3_12_2   31202 /* Op-version for GlusterFS 3.12.2 */

#define GD_OP_VERSION_3_12_3   31203 /* Op-version for GlusterFS 3.12.3 */

#define GD_OP_VERSION_3_13_0   31300 /* Op-version for GlusterFS 3.13.0 */

#define GD_OP_VERSION_3_13_1   31301 /* Op-version for GlusterFS 3.13.1 */

#define GD_OP_VERSION_3_13_2   31302 /* Op-version for GlusterFS 3.13.2 */

#define GD_OP_VERSION_3_13_3   31303 /* Op-version for GlusterFS 3.13.3 */

/* Downstream only change */
#define GD_OP_VERSION_3_11_2   31102 /* Op-version for RHGS 3.3.1-async */
#define GD_OP_VERSION_3_13_3   31303 /* Op-version for RHGS-3.4-Batch Update-1*/
#define GD_OP_VERSION_3_13_4   31304 /* Op-version for RHGS-3.4-Batch Update-2*/

#include "xlator.h"

/* THIS */
#define THIS (*__glusterfs_this_location())
#define DECLARE_OLD_THIS        xlator_t *old_THIS = THIS

xlator_t **__glusterfs_this_location (void);
xlator_t *glusterfs_this_get (void);
int glusterfs_this_set (xlator_t *);

/* syncopctx */
void *syncopctx_getctx (void);
int syncopctx_setctx (void *ctx);

/* task */
void *synctask_get (void);
int synctask_set (void *);

/* uuid_buf */
char *glusterfs_uuid_buf_get (void);
/* lkowner_buf */
char *glusterfs_lkowner_buf_get (void);
/* leaseid buf */
char *glusterfs_leaseid_buf_get (void);

/* init */
int glusterfs_globals_init (glusterfs_ctx_t *ctx);

struct tvec_base* glusterfs_ctx_tw_get (glusterfs_ctx_t *ctx);
void glusterfs_ctx_tw_put (glusterfs_ctx_t *ctx);

extern const char *gf_fop_list[];
extern const char *gf_upcall_list[];

/* mem acct enable/disable */
int gf_global_mem_acct_enable_get (void);
int gf_global_mem_acct_enable_set (int val);
#endif /* !_GLOBALS_H */
