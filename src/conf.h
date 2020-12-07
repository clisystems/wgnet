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
#ifndef __CONF_H__
#define __CONF_H__



void conf_init();

void conf_end();

// Data handling functions
void conf_dump();

void conf_set_interface(char * interface);
char * conf_get_interface();

bool conf_get_routesubnet();
int conf_get_routesubnet_cidr();
int conf_get_num_routed_networks();
char * conf_get_route_subnet(int id);

bool conf_get_enablenat();
char * conf_get_nat_outinterface();

int conf_get_num_firewall_hosts();
int conf_get_firewall_host_num_ports(int id);
char * conf_get_firewall_host_ip(int id);
uint16_t conf_get_firewall_host_port(int id,int port_id);

// File handling functions
void conf_set_path(char * newpath);
char * conf_get_path();

bool conf_exists(char * conf_name);

bool conf_remove(char * conf_name);

bool conf_load_default();

bool conf_load(char * conf_name);

bool conf_save(char * conf_name);

// MOVE THESE
uint32_t get_ip_of_interface(char * iface);
uint32_t get_netmask_of_interface(char * iface);
uint16_t cidr_from_netmask(uint32_t netmask);
void cidr_of_interface(char * iface, char * out, int max_len);

#endif
