#!/bin/bash

. $(dirname $0)/../../include.rc
. $(dirname $0)/../../traps.rc
. $(dirname $0)/../../volume.rc

function count_brick_processes {
        pgrep glusterfsd | wc -l
}

function count_brick_pids {
        $CLI --xml volume status all | sed -n '/.*<pid>\([^<]*\).*/s//\1/p' \
                                     | grep -v "N/A" | sort | uniq | wc -l
}

cleanup;

#bug-1560955 - brick status goes offline after remove-brick followed by add-brick
TEST glusterd
TEST $CLI volume set all cluster.brick-multiplex on
push_trapfunc "$CLI volume set all cluster.brick-multiplex off"
push_trapfunc "cleanup"

TEST $CLI volume create $V0 $H0:$B0/${V0}{1..3}
TEST $CLI volume start $V0

EXPECT_WITHIN $PROCESS_UP_TIMEOUT 1 count_brick_processes
EXPECT_WITHIN $PROCESS_UP_TIMEOUT 1 count_brick_pids
EXPECT_WITHIN $PROCESS_UP_TIMEOUT 3 online_brick_count


pkill glusterd
TEST glusterd
TEST $CLI volume remove-brick $V0 $H0:$B0/${V0}1 force
TEST $CLI volume add-brick $V0 $H0:$B0/${V0}1_new force

EXPECT_WITHIN $PROCESS_UP_TIMEOUT 1 count_brick_processes
EXPECT_WITHIN $PROCESS_UP_TIMEOUT 1 count_brick_pids
EXPECT_WITHIN $PROCESS_UP_TIMEOUT 3 online_brick_count
