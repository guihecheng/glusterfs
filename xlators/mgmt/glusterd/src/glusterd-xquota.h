#ifndef _GLUSTERD_XQUOTA_
#define _GLUSTERD_XQUOTA_

int
glusterd_store_xquota_config (glusterd_volinfo_t *volinfo, char *path,
                              char *gfid_str, int opcode, char **op_errstr);

#endif
