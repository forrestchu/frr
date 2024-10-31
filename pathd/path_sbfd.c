/*
 * Copyright (C) 2020  NetDEF, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "memory.h"
#include "log.h"
#include "lib_errors.h"
#include "network.h"

#include "pathd/pathd.h"
#include "pathd/path_zebra.h"
#include "pathd/path_debug.h"
#include "pathd/path_ted.h"
#include "command.h"
#include "lib/bfd.h"
#include "pathd/path_nb.h"
#include "pathd/path_sbfd.h"
#include "lib/northbound_cli.h"

extern struct zclient *zclient;
extern struct thread_master *master;

static void sbfd_refresh_policy_group_state(struct srte_candidate_group * group)
{
	// struct srte_candidate_group *cpath_group, *safe_cg;
	struct srte_candidate *candidate, *safe_cpath;
	uint32_t cpath_up_count = 0;

	RB_FOREACH_SAFE (candidate, srte_candidate_pref_head, &group->candidate_paths, safe_cpath)
	{
		if (!candidate->segment_list)
		{
			continue;
		}

		if (candidate->status != SRTE_DETECT_DOWN)
		{
			cpath_up_count++;
		}
	}

	if (cpath_up_count > 0)
	{
		group->status = SRTE_DETECT_UP;
		group->up_cpath_num = cpath_up_count;
	}
	else
	{
		group->status = SRTE_DETECT_DOWN;
		group->up_cpath_num = 0;
	}
}

static int policy_sbfd_state_change(char *bfd_name, int state)
{
	struct srte_candidate *candidate;
	enum detection_status new_status = (state == BFD_STATUS_UP?SRTE_DETECT_UP: SRTE_DETECT_DOWN);
	struct srte_candidate_bfd_group search = {0};
	struct srte_candidate_bfd_group* group = NULL;

	zlog_warn( "bfd:%s update state to:%s", bfd_name, bfd_get_status_str(state));
	strncpy(search.bfd_name, bfd_name, BFD_NAME_SIZE);

	group = RB_FIND(srte_candidate_bfd_group_head, &sbfd_groups, &search);
	if(!group){
		srte_candidate_bfd_group_add_with_status(bfd_name, new_status);
		return 0;
	}

	group->status = new_status;

	RB_FOREACH (candidate, srte_candidate_bfd_head, &group->candidate_paths) 
	{
		if(candidate->status == new_status)
		    continue;

        zlog_info( "cpath:%s state update:%d -> %d", candidate->name, candidate->status, new_status);
		cpath_status_refresh(candidate, new_status);
		//mark cpath group as changed
		SET_FLAG(candidate->group->flags, F_CPATH_GROUP_STATE_CHANGE);

		sbfd_refresh_policy_group_state(candidate->group);
		//simplely assume that different cpath bind to different bfd_name
		//so a policy can bind to a bfd_name only once, we can directly update policy best cpath here
		srv6_choose_best_cpath_group(candidate->policy);
	}

	return 0;
}

void sr_sbfd_init()
{
	/* Initialize PATHD client functions */
	bfd_protocol_integration_init(zclient, master);
	hook_register(sbfd_state_change_hook, policy_sbfd_state_change);
}
