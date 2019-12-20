#ifndef XQUOTAD_HELPERS_H
#define XQUOTAD_HELPERS_H

#include "rpcsvc.h"
#include "xquota.h"
#include "xquotad-aggregator.h"

void
xquotad_aggregator_free_state (xquotad_aggregator_state_t *state);

call_frame_t *
xquotad_aggregator_get_frame_from_req (rpcsvc_request_t *req);

#endif
