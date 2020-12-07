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

#include "defs.h"
#include "wg_conf.h"

void wg_conf_init()
{
    return;
}

bool wg_conf_load_iface(char * iface)
{
    char fullpath[250];
    sprintf(fullpath,"%s/%s.conf",WG_CONF_LOCATION,iface);

    if(g_verbose) printf("* Loading wg conf '%s'\n",fullpath);

    return true;
}

void wg_conf_dump()
{
    printf("WG conf dump:\n");
    printf("  WG_CONF_LOCATION: %s\n",WG_CONF_LOCATION);
    return;
}

// EOF
