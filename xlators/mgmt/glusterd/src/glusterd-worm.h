#ifndef _GLUSTERD_WORM_
#define _GLUSTERD_WORM_

int
glusterd_store_worm_config (glusterd_volinfo_t *volinfo, char *path,
                            char *gfid_str, int opcode, char **op_errstr);

#endif
