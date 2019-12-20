#ifndef _GLUSTERD_XQUOTAD_SVC_H_
#define _GLUSTERD_XQUOTAD_SVC_H_

#include "glusterd-svc-mgmt.h"

void
glusterd_xquotadsvc_build (glusterd_svc_t *svc);

int
glusterd_xquotadsvc_init (glusterd_svc_t *svc);

int
glusterd_xquotadsvc_start (glusterd_svc_t *svc, int flags);

int
glusterd_xquotadsvc_manager (glusterd_svc_t *svc, void *data, int flags);

int
glusterd_xquotadsvc_reconfigure ();

#endif
