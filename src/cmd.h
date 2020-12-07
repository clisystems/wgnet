/*********************************************************************
wgnet WireGuard network utility

Copyright (C) 2020 - Andrew Gaylo - drew@clisystems.com

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

*******************************************************************/
#ifndef __CMD_H__
#define __CMD_H__

void cmd_init();

void cmd_enable_dryrun();

void cmd_list();

void cmd_show(char * config);
void cmd_default(char * config, bool force);

void cmd_status(char * config);
void cmd_net_up(char * config, bool force);
void cmd_net_down(char * config, bool force);
void cmd_net_restart(char * config, bool force);

void cmd_test(char * config);

#endif
