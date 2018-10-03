#!/bin/bash

. $(dirname $0)/../../include.rc
. $(dirname $0)/../../cluster.rc
. $(dirname $0)/../../volume.rc

function peer_count {
eval \$CLI_$1 peer status | grep 'Peer in Cluster (Connected)' | wc -l
}

cleanup

TEST launch_cluster 2

TEST $CLI_1 peer probe $H2;
EXPECT_WITHIN $PROBE_TIMEOUT 1 peer_count 1
EXPECT_WITHIN $PROBE_TIMEOUT 1 peer_count 2

TEST $CLI_1 volume create $V0 $H1:$B1/$V0 $H2:$B2/$V0

# rebooting a node which doesn't host bricks for any one volume
# peer should not go into rejected state
TEST kill_glusterd 2
TEST start_glusterd 2

EXPECT_WITHIN $PROBE_TIMEOUT 1 peer_count 1
EXPECT_WITHIN $PROBE_TIMEOUT 1 peer_count 2

cleanup
