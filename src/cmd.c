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

/*********************************************************************
 *
 * Overview:
 *
 * This file handles the business work of the system, it has higher
 * level functions for the commands (up, down, status, etc).  Helper
 * static functions are for doing the low level work of bringing up/down
 * the interface, or set/clear iptables chains
 *
 ********************************************************************/

#include "defs.h"
#include "cmd.h"
#include "wgnet_conf.h"
#include "wg_conf.h"
#include "wg_conf.h"
#include "defs_colors.h"

#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

// For handling ip and netmasks
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "wireguard.h"

#define ERROR(...)      RED();printf(__VA_ARGS__);NORMAL();

// Definitions
// ----------------------------------------------------------------------------

// Types
// ----------------------------------------------------------------------------
enum error_codes{
    OK = 0,
    ERROR_SETUP_DEVICE = -100,
    ERROR_DEVICE = -101,
    ERROR_DEVICE_UP = -102,
    ERROR_DEVICE_DOWN = -103,
    ERROR_ROUTING = -104,
    ERROR_NAT = -105,
    ERROR_FIREWALL = -106,
    ERROR_DEVICE_EXISTS = -107,
};
// Variables
// ----------------------------------------------------------------------------

// Local functions
// ----------------------------------------------------------------------------
static void _cmd_config_error(char * conf);

static int _bringup_interface(char * iface);
static int _bringup_routing();
static int _bringup_nat();
static int _bringup_firewall();
static int _bringup_lockdown_forwarding(char * iface);

static int _teardown_interface(char * iface);
static int _teardown_routing();
static int _teardown_nat();
static int _teardown_firewall();
static int _teardown_lockdown_forwarding(char * iface);

static int _run_command(char * command);
static int _test_command(char * command);
static bool _is_interface_running(char * iface);
static bool _interface_config_exists(char * iface);
static uint16_t _uint16_swap(uint16_t in);

// Public functions
// ----------------------------------------------------------------------------
static bool b_dryrun = false;

void cmd_init()
{
    return;
}

void cmd_enable_dryrun()
{
    if(g_verbose) printf("dry run mode = true\n");
    b_dryrun = true;
}

void cmd_show(char * config)
{
    if(!conf_exists(config)){_cmd_config_error(config);return;}
    
    // Load the data
    if(!conf_load(config)){
        ERROR("Error loading '%s'\n",config);
        return;
    }
    
    // Show the status
    conf_dump();
    
    return;
}

void cmd_list()
{
    DIR * dir;
    struct dirent *ent;
    char * path;
    char * devs;
    char * name;
    int len;
    int dev_num=0;

    // List configs
    path = conf_get_path();
    printf("Directory: %s\n",path);

    if ((dir = opendir(path)) != NULL)
    {
        while ((ent = readdir(dir)) != NULL)
        {
            char * name;
            name = ent->d_name;
            if(!cmp_const(name,".") && !cmp_const(name,"..") && strstr(name,".conf"))
            {
                BLUE();BOLD();
                printf ("  Config: %s\n", name);
                NORMAL();DEFAULT();
            }
        }
        closedir (dir);
    } else {
        printf("Directory %s does not exist\n",path);
    }


    // List devices
    devs = wg_list_device_names();
    wg_for_each_device_name(devs,name,len){
        wg_device * pdev;
        struct wg_peer * peerptr;
        int ret,peers;
        wg_key_b64_string base64;

        ret = wg_get_device(&pdev,name);
        if(ret<0){
            ERROR("Error getting device, are you root?\n");
            return;
        }

        wg_key_to_base64(base64,pdev->public_key);

        dev_num++;
        BOLD();GREEN();
        printf("\ninterface : %s\n",pdev->name);
        DEFAULT();NORMAL();
        printf("  Publickey: %s\n",base64);

        peers=0;
        wg_for_each_peer(pdev,peerptr)
        {
            YELLOW();BOLD();
            wg_key_to_base64(base64,peerptr->public_key);
            printf("  peer: %s\n",base64);
            DEFAULT();NORMAL();
            peers++;
        }
        printf("  Num Peers: %d\n",peers);
        //printf("  Acting as: %s\n",((pdev->flags&WGDEVICE_HAS_LISTEN_PORT)?"Server (ListenPort)":"Client"));
        wg_free_device(pdev);

    }
    if(dev_num==0)
    {
        printf("No active tunnels found\n");
    }

    return;
}

void cmd_default(char * config, bool force)
{
    bool error=false;

    if(g_verbose) printf("CMD 'default'\n");

    if(!force && conf_exists(config)){ERROR("Error, config file '%s' exists, skipping default\n",config);return;}

    if(!b_dryrun) conf_remove(config);
    conf_load_default();
    if(!b_dryrun) error = !conf_save(config);

    if(!error)
    {
        printf("Successfully created new config '%s'\n",config);
        conf_dump();
    }

    return;
}


void cmd_status(char * config)
{
    wg_device * dev;
    int ret;
    char * iface;

    // Do we have this config?
    if(!conf_exists(config)){_cmd_config_error(config);return;}

    // Load the data
    if(!conf_load(config)){
        ERROR("Error loading '%s'\n",config);
        return;
    }

    // Does the interface exist?
    iface = conf_get_interface();
    if(!iface || !_interface_config_exists(iface))
    {
        printf("%s: interface config does not exist, or we can't read it.\n",iface);

    }else{

        // Does the tunnel exist?
        ret = wg_get_device(&dev, iface);
        if(ret==-1){
            printf("Permission denied for interface '%s', are you root?\n",iface);
            return;
        }
        if(ret==-ENODEV){
            printf("%s: interface not up\n",iface);
            return;
        }


        // Show the tunnel info.
        // Match wg output
        // =========================================
        struct wg_peer * peerptr;
        int peers;
        wg_key_b64_string base64;
        wg_key_to_base64(base64,dev->public_key);
        GREEN();
        BOLD(); printf("interface: "); NORMAL(); GREEN(); printf("%s\n",dev->name);
        DEFAULT();
        BOLD(); printf("  public key: "); NORMAL(); printf("%s\n",base64);
        BOLD(); printf("  private key: "); NORMAL(); printf("(hidden)\n");
        //printf("  Flags: 0x%0X\n",dev->flags);
        // TODO: Servers are ???? clients are ????
        //printf("  Acting as: %s\n",((dev->flags&WGDEVICE_HAS_LISTEN_PORT)?"Server (ListenPort)":"Client"));
        BOLD(); printf("  listening port: "); NORMAL(); printf("%d\n",dev->listen_port);
        printf("\n");
        peers=0;
        wg_for_each_peer(dev,peerptr)
        {
            struct wg_allowedip * ptrallowip;
            wg_key_to_base64(base64,peerptr->public_key);
            YELLOW();
            BOLD(); printf("peer: "); NORMAL(); YELLOW(); printf("%s\n",base64);
            DEFAULT();
            BOLD(); printf("  endpoint: "); NORMAL();
            printf("%s:%d\n",inet_ntoa(peerptr->endpoint.addr4.sin_addr),_uint16_swap(peerptr->endpoint.addr4.sin_port));
            wg_for_each_allowedip(peerptr,ptrallowip)
            {
                BOLD(); printf("  allowed ips: "); NORMAL(); printf("%s/%d\n",inet_ntoa(ptrallowip->ip4),ptrallowip->cidr);
            }
            peers++;
        }
        //printf("  Peers: %d\n",peers);
        wg_free_device(dev);
        printf("\n");
    }

    // Show the network info.
    // =========================================
    BLUE(); BOLD(); printf("network: \n"); NORMAL();
    BOLD(); printf("  Route main subnet: "); NORMAL(); printf("%s\n",((conf_get_routesubnet())?"True":"False") );
    BOLD(); printf("  Routed subnets: "); NORMAL(); printf("%d\n",conf_get_num_routed_networks());
    BOLD(); printf("  Enable NAT: "); NORMAL(); printf("%s\n",((conf_get_enablenat())?"True":"False") );
    BOLD(); printf("  Firewall hosts: "); NORMAL(); printf("%d\n",conf_get_num_firewall_hosts());

    return;
}
void cmd_net_up(char * config, bool force)
{
    int ret;
    char * iface;

    // Make sure we have a config
    if(!conf_exists(config)){_cmd_config_error(config);return;}

    // Load the data
    if(!conf_load(config)){
        ERROR("Error loading '%s'\n",config);
        return;
    }

    // Get the interface
    iface = conf_get_interface();
    if(!iface){
        printf("Error getting interface from config");
        return;
    }

    // Make sure there is a config
    if(!iface || !_interface_config_exists(iface)){
        printf("%s: interface config doesn't exist, permission error?\n",iface);
        return;
    }

    // Bring up and configure device
    ret = _bringup_interface(iface);
    if(ret==ERROR_SETUP_DEVICE) return;
    if(ret==ERROR_DEVICE) goto net_up_err_end;
    if(ret==ERROR_DEVICE_EXISTS && force==false)
    {
        printf("Device is already up, skipping network setup, use -F to force setup\n");
        return;
    }


    // Set routing rules
    if(_bringup_routing()==ERROR_ROUTING) goto net_up_err_routing;

    // Set per-client firewall rules
    if(_bringup_firewall()==ERROR_FIREWALL) goto net_up_err_firewall;

    // Set NAT rules
    if(_bringup_nat()==ERROR_NAT) goto net_up_err_nat;

    // Set the policy for this interface to drop
    if(_bringup_lockdown_forwarding(iface)==ERROR_FIREWALL) goto net_up_err_firewall;

    return;

net_up_err_firewall:
    printf("Error setting up firewall, tearing down\n");
    _teardown_firewall();

net_up_err_routing:
    printf("Error setting up routing, tearing down\n");
    _teardown_routing();

net_up_err_nat:
    printf("Error setting up NAT, tearing down\n");
    _teardown_nat();

net_up_err_end:
    printf("Error setting up device, tearing down\n");
    _teardown_interface(iface);

    // Drop the block for this interface
    _teardown_lockdown_forwarding(iface);

    return;
}
void cmd_net_down(char * config, bool force)
{
    int ret;
    char * iface;

    // Make sure we have a config
    if(!conf_exists(config)){_cmd_config_error(config);return;}

    // Load the data
    if(!conf_load(config)){
        printf("Error loading '%s'\n",config);
        return;
    }

    // get the interface
    iface = conf_get_interface();
    if(!iface){
        printf("Error getting interface from config");
        return;
    }

    _teardown_nat();

    _teardown_firewall();

    _teardown_routing();

    _teardown_lockdown_forwarding(iface);

    // Tear down the interface
    _teardown_interface(iface);

    return;
}
void cmd_net_restart(char * config, bool force)
{
    cmd_net_down(config, force);

    cmd_net_up(config, force);

    return;
}

void cmd_test(char * config)
{
    #if 0
    RED();printf("Red\n");DEFAULT();
    GREEN();printf("Green\n");DEFAULT();
    YELLOW();printf("Yellow\n");DEFAULT();
    BLUE();printf("Blue\n");DEFAULT();
    WHITE();printf("White\n");DEFAULT();
    MAGENTA();printf("Magenta\n");DEFAULT();

    BOLD();
    RED();printf("Red\n");DEFAULT();
    GREEN();printf("Green\n");DEFAULT();
    YELLOW();printf("Yellow\n");DEFAULT();
    BLUE();printf("Blue\n");DEFAULT();
    WHITE();printf("White\n");DEFAULT();
    MAGENTA();printf("Magenta\n");DEFAULT();
    NORMAL();

    ERROR("Test error message\n");
    #endif

    return;
}

// Private functions
// ----------------------------------------------------------------------------
static void _cmd_config_error(char * conf)
{
    printf("Error, config file for '%s' does not exist\n",conf);
    return;
}
static int _bringup_interface(char * iface)
{
    char cmd[255];
    char * pch;
    uint16_t port;
    int x;
    int ret;
    int num_peers;

    // Skip if we are testing
    #ifdef SKIP_INTERFACE_CONTROL
    return OK;
    #endif

    // If already running, just return
    if(_is_interface_running(iface)){
        printf("%s: already running\n",iface);
        return ERROR_DEVICE_EXISTS;
    }

    if(g_verbose) printf("*Bring up interface '%s'\n",iface);

    // Option 1 use wg-quick
#if 1
    // Create the new device
    sprintf(cmd,"wg-quick up %s 2> /dev/null",iface);
    ret = _run_command(cmd);
    if(ret < 0){
        printf("Error setting up device, are you root?\n");
        return ERROR_SETUP_DEVICE;
    }
#endif


    // Option 2 use ip commands and wg setconf
#if 0
    // From docs:
    //ip link add dev wgtest123 type wireguard
    // wg setconf wg0 myconfig.conf

    // Create the new device
    sprintf(cmd,"ip link add dev %s type wireguard",iface);
    ret = _run_command(cmd);
    if(ret < 0){
        printf("Error setting up device, are you root?\n");
        return ERROR_SETUP_DEVICE;
    }

    // Configure the device
    sprintf(cmd,"bash -c 'wg setconf %s /etc/wireguard/%s.conf'",iface,iface);
    ret = _run_command(cmd);
    if(ret < 0){
        printf("Error setting config, are you root?\n");
        return ERROR_DEVICE;
    }
#endif


    // Option 3 use ip commands
#if 0

    // Create the new device
    sprintf(cmd,"ip link add dev %s type wireguard",iface);
    ret = _run_command(cmd);
    if(ret < 0){
        printf("Error setting up device, are you root?\n");
        return ERROR_SETUP_DEVICE;
    }

    // Set the IP address
    pch = conf_get_cidraddress();
    if(!pch){ printf("Error getting IP address\n"); return ERROR_DEVICE;}
    sprintf(cmd,"ip address add dev %s %s",config,pch);
    ret = _run_command(cmd);
    if(ret < 0){
        printf("Error setting IP address, are you root?\n");
        return ERROR_DEVICE;
    }

    // Set the private key
    pch = conf_get_privkey_base64();
    if(!pch){ printf("Error getting private key\n"); return ERROR_DEVICE;}
    sprintf(cmd,"bash -c 'wg set %s private-key <(echo \"%s\")'",config, pch);
    ret = _run_command(cmd);
    if(ret < 0){
        printf("Error setting device parameters, are you root?\n");
        return ERROR_DEVICE;
    }

    // Set the listen port
    port = conf_get_listenport();
    if(port!=0)
    {
        sprintf(cmd,"wg set %s listen-port %d",config, port);
        ret = _run_command(cmd);
        if(ret < 0){
            printf("Error setting device parameters, are you root?\n");
            return ERROR_DEVICE;
        }
    }
    else{ printf("DEBUG: Port is 0, so no listen port? Client only?\n"); }


    // Set peers
    num_peers = conf_get_numpeers();
    if(num_peers<0){ printf("Error getting private key\n"); return ERROR_DEVICE;}
    for(x=0;x<num_peers;x++)
    {
        char * key;
        char * ip;

        key = conf_get_peer_publickey(x);
        ip = conf_get_peer_cidraddress(x);

        if(!key || !ip)
        {
            printf("Error getting info from peers\n");
            continue;
        }

        sprintf(cmd,"wg set %s peer %s allowed-ips %s",config, key, ip);
        ret = _run_command(cmd);
        if(ret < 0){
            printf("Error setting peer information, are you root?\n");
            return ERROR_DEVICE;
        }
    }
#endif

    // Option 4 parse the wireguard config and use the wireguard library
#if 0

    // try and load the config for the interface
    if(!wg_conf_load_iface(iface)){
        printf("Error loading config file for iface '%s'\n",iface);
        return ERROR_DEVICE;
    }


    wg_conf_dump();

    /*
    wg_peer * ptr_last_peer = NULL;
    //wg_peer new_peer = {
    //    .flags = WGPEER_HAS_PUBLIC_KEY | WGPEER_REPLACE_ALLOWEDIPS
    //};
    wg_device new_device = {
        .name = wg_conf_get_iface_name(),
        .listen_port = wg_conf_get_listenport(),
        .flags = WGDEVICE_HAS_PRIVATE_KEY | WGDEVICE_HAS_LISTEN_PORT,
        .first_peer = NULL,
        .last_peer = NULL
    };

    // Set up the peers
    num_peers = wg_conf_get_numpeers();
    if(num_peers<0){ printf("Error getting private key\n"); return ERROR_DEVICE;}
    for(x=0;x<num_peers;x++)
    {
        wg_peer * P = malloc(wg_peer);
        char * key;
        char * ip;

        key = wg_conf_get_peer_publickey(x);
        ip = wg_conf_get_peer_cidraddress(x);

        if(!key || !ip)
        {
            printf("Error getting info for peer %d\n",x);
            free(P)???
            continue;
        }

        example Save info
        struct wg_allowedip = ip;
        p.public_key = key
        P.flags = WGPEER_HAS_PUBLIC_KEY | WGPEER_REPLACE_ALLOWEDIPS?????

        if(ptr_last_peer==NULL){
             ptr_last_peer=P;
             new_device.first_peer=P;
        }else{
            ptr_last_peer.next_peer = P;
            P.last_peer = P;
        }

    }

    if (wg_add_device(new_device.name) < 0) {
        perror("Unable to add device");
        exit(1);
    }

    // Set the IP address
    pch = conf_get_cidraddress();
    if(!pch){ printf("Error getting IP address\n"); return ERROR_DEVICE;}
    sprintf(cmd,"ip address add dev %s %s",config,pch);
    ret = _run_command(cmd);
    if(ret < 0){
        printf("Error setting IP address, are you root?\n");
        return ERROR_DEVICE;
    }

    if (wg_set_device(&new_device) < 0) {
        perror("Unable to set device");
        exit(1);
    }

    // Free all the peers?


     */

    return ERROR_SETUP_DEVICE;
#endif


    if(g_verbose) printf("Done setup\n");

    return OK;
}

static int _bringup_routing()
{
    char cmd[250];
    int ret;
    int nets,x;
    char * iface;

    if(g_verbose) printf("*Configure routing\n");

    // get the interface name
    iface = conf_get_interface();
    if(!iface)
    {
        printf("ERROR: interface NULL\n");
        return ERROR_ROUTING;
    }

    // Subnet routing

    // wg-quick adds and entry for each client to the ip routing table, thus, if routing is
    // enabled on the system, data from the wg network will find the routing and automatically
    // be forwarded.  So we want to BLOCK routing the subnet if conf_get_routesubnet() is FALSE
    if(conf_get_routesubnet() == false)
    {
        char cidr[25];
        struct in_addr a;
        a.s_addr = get_ip_of_interface(iface);
        sprintf(cidr,"%s/%d",inet_ntoa(a),conf_get_routesubnet_cidr());
        sprintf(cmd,"iptables -t filter -A FORWARD -i %s -d %s -j DROP",iface,cidr);
        ret = _run_command(cmd);
        if(ret<0){
            printf("Error setting subnet routing\n");
            return ERROR_ROUTING;
        }
    }


    // Set each network we want to route
    nets = conf_get_num_routed_networks();
    if(nets<0){ printf("Error routing subnets\n"); return ERROR_ROUTING; }
    for(x=0;x<nets;x++)
    {
        sprintf(cmd,"iptables -t filter -A FORWARD -i %s -d %s -j ACCEPT",iface,conf_get_route_subnet(x));
        ret = _run_command(cmd);
        if(ret<0){
            printf("Error setting subnet routing\n");
            return ERROR_ROUTING;
        }
    }

    return OK;
}
static int _bringup_nat()
{
    char cmd[250];
    int ret;
    char * iface;
    char * out_iface;

    if(g_verbose) printf("*Configure NAT\n");

    // Enable nat?
    if(!conf_get_enablenat()) return OK;

#if 0
    // get the input interface name
    iface = conf_get_interface();
    if(!iface)
    {
        printf("ERROR: interface NULL\n");
        return ERROR_NAT;
    }

    // get the output interface name
    out_iface = conf_get_nat_outinterface();
    if(!out_iface)
    {
        printf("ERROR: output interface NULL\n");
        return ERROR_NAT;
    }

    // Actually enable it for the subnet
    sprintf(cmd,"iptables -t nat -A POSTROUTING -i %s -o %s -j MASQUERADE",iface,out_iface);
    ret = _test_command(cmd);
    if(ret<0){
        printf("Error setting subnet routing\n");
        return ERROR_NAT;
    }
#else
    printf("TODO: NAT not enabled\n");
#endif

    return OK;
}
static int _bringup_firewall()
{
    char cmd[250];
    int ret, num_hosts;
    int x,y;
    char * iface;

    if(g_verbose) printf("*Configure firewall\n");

    // get the interface name
    iface = conf_get_interface();
    if(!iface)
    {
        printf("ERROR: interface NULL\n");
        return ERROR_FIREWALL;
    }

    // Loop over firewall_hosts and ports to add them to firewall
    num_hosts = conf_get_num_firewall_hosts();
    for(x=0;x<num_hosts;x++)
    {
        int ports;
        char * ip;
        ports = conf_get_firewall_host_num_ports(x);
        ip = conf_get_firewall_host_ip(x);
        if(ports<=0 || ip==NULL){
            printf("Invalid number of ports %d\n",ports);
            continue;
        }

        for(y=0;y<ports;y++)
        {
            int p;
            p = conf_get_firewall_host_port(x,y);
            if(p==0){
                printf("Invalid port\n");
                continue;
            }

            // Actually enable it for the subnet
            sprintf(cmd,"iptables -t filter -A FORWARD -i %s -d %s -p tcp --dport %d -j ACCEPT",iface,ip,p);
            ret = _run_command(cmd);
            if(ret<0){
                printf("Error setting subnet routing\n");
                return ERROR_FIREWALL;
            }
        }

    }

    return OK;
}
static int _bringup_lockdown_forwarding(char * iface)
{
    char cmd[250];
    int ret;

    if(g_verbose) printf("*Blocking all other FORWARD and INPUT packets\n");

    // Drop all FORWARD traffic from this interface
    sprintf(cmd,"iptables -t filter -A FORWARD -i %s -j DROP",iface);
    ret = _run_command(cmd);
    if(ret < 0){
        printf("Error setting firewall drop rule\n");
        return ERROR_FIREWALL;
    }

    // Drop all INPUT traffic from this interface
    sprintf(cmd,"iptables -t filter -A INPUT -i %s -j DROP",iface);
    ret = _run_command(cmd);
    if(ret < 0){
        printf("Error setting firewall drop rule\n");
        return ERROR_FIREWALL;
    }

    return OK;
}

static int _teardown_interface(char * iface)
{
    char cmd[250];
    int ret;

    // Skip if we are testing
    #ifdef SKIP_INTERFACE_CONTROL
    return OK;
    #endif

    // If not running, just return
    if(!_is_interface_running(iface)){
        printf("%s: not running\n",iface);
        return OK;
    }


    // Option 1 use wg-quick
#if 1
    // Use wg-quick
    sprintf(cmd,"wg-quick down %s 2> /dev/null",iface);
    ret = _run_command(cmd);
    if(ret < 0){
        printf("Error setting up device, are you root?\n");
        return ERROR_SETUP_DEVICE;
    }
#endif

    // Option 2 use ip commands
#if 0
   // From testing:
   //ip link set dev wgtest123 down
   //ip link del dev wgtest123

    // Bring link down
    sprintf(cmd,"ip link set dev %s down",iface);
    ret = _run_command(cmd);
    if(ret< 0){
       printf("Error bringing down device, are you root?\n");
       return ERROR_DEVICE_DOWN;
    }

    // Something went wrong, so tear down the device if it is up?
    sprintf(cmd,"ip link del dev %s",iface);
    ret = _run_command(cmd);
    if(ret < 0){
        printf("Error deleting device, are you root?\n");
        return ERROR_DEVICE_DOWN;
    }
#endif

    // Option 3 use wireguard library calls
#if 0
    wg_del_device(iface);
#endif


    return OK;
}
static int _teardown_routing()
{
    char cmd[250];
    int ret;
    int nets,x;
    char * iface;
    char cidr[25];
    struct in_addr a;

    if(g_verbose) printf("*Tear down routing\n");


    // get the interface name
    iface = conf_get_interface();
    if(!iface)
    {
        printf("ERROR: interface NULL\n");
        return ERROR_ROUTING;
    }


    // Delete the subnet blocking command
    a.s_addr = get_ip_of_interface(iface);
    sprintf(cidr,"%s/%d",inet_ntoa(a),conf_get_routesubnet_cidr());
    sprintf(cmd,"iptables -t filter -D FORWARD -i %s -d %s -j DROP 2> /dev/null",iface,cidr);
    ret = _run_command(cmd);
    if(ret<0){
        printf("Error setting subnet routing\n");
        return ERROR_ROUTING;
    }

    // For each network we want to route
    nets = conf_get_num_routed_networks();
    if(nets<0){ printf("Error un-routing subnets\n"); return ERROR_DEVICE_DOWN; }
    for(x=0;x<nets;x++)
    {
        sprintf(cmd,"iptables -t filter -D FORWARD -i %s -d %s -j ACCEPT 2> /dev/null",iface,conf_get_route_subnet(x));
        ret = _run_command(cmd);
        if(ret<0){
            printf("Error setting subnet routing\n");
            return ERROR_DEVICE_DOWN;
        }
    }


    return OK;
}
static int _teardown_nat()
{
    char cmd[250];
    int ret;
    char * iface;
    char * out_iface;

    if(g_verbose) printf("*Tear down NAT\n");

    // If the NAT is NOT enabled, don't try and remove it.  This is
    // to prevent other NAT issues
    if(!conf_get_enablenat()) return OK;

#if 0
    // get the input interface name
    iface = conf_get_interface();
    if(!iface)
    {
        printf("ERROR: interface NULL\n");
        return ERROR_NAT;
    }

    // get the output interface name
    out_iface = conf_get_nat_outinterface();
    if(!out_iface)
    {
        printf("ERROR: output interface NULL\n");
        return ERROR_NAT;
    }

    // disable it for the subnet
    sprintf(cmd,"iptables -t nat -D POSTROUTING -i %s -o %s -j MASQUERADE 2> /dev/null",iface,out_iface);
    ret = _test_command(cmd);
    if(ret<0){
       printf("Error setting subnet routing\n");
       return ERROR_NAT;
    }
#else
    printf("TODO: NAT not enabled\n");
#endif

    return OK;
}
static int _teardown_firewall()
{
    char cmd[250];
    int ret, num_hosts;
    int x,y;
    char * iface;

    if(g_verbose) printf("*Tear down firewall\n");

    // get the interface name
    iface = conf_get_interface();
    if(!iface)
    {
        printf("ERROR: interface NULL\n");
        return ERROR_FIREWALL;
    }

    // Clear firewall_hosts rules
    num_hosts = conf_get_num_firewall_hosts();
    for(x=0;x<num_hosts;x++)
    {
        int ports;
        char * ip;
        ports = conf_get_firewall_host_num_ports(x);
        ip = conf_get_firewall_host_ip(x);
        if(ports<=0 || ip==NULL){
            printf("Invalid number of ports %d\n",ports);
            continue;
        }

        for(y=0;y<ports;y++)
        {
            int p;
            p = conf_get_firewall_host_port(x,y);
            if(p==0){
                printf("Invalid port\n");
                continue;
            }

            // Actually enable it for the subnet
            sprintf(cmd,"iptables -t filter -D FORWARD -i %s -d %s -p tcp --dport %d -j ACCEPT 2> /dev/null",iface,ip,p);
            ret = _run_command(cmd);
            if(ret<0){
                printf("Error setting subnet routing\n");
                return ERROR_FIREWALL;
            }
        }

    }

    return OK;
}
static int _teardown_lockdown_forwarding(char * iface)
{
    char cmd[250];
    int ret;

    if(g_verbose) printf("*Remove blocking all other FORWARD and INPUT packets\n");

    // Delete FORWARD rule
    sprintf(cmd,"iptables -t filter -D FORWARD -i %s -j DROP 2> /dev/null",iface);
    ret = _run_command(cmd);
    if(ret < 0){
        printf("Error setting firewall drop rule\n");
        return ERROR_FIREWALL;
    }

    // Delete INPUT rule
    sprintf(cmd,"iptables -t filter -D INPUT -i %s -j DROP 2> /dev/null",iface);
    ret = _run_command(cmd);
    if(ret < 0){
        printf("Error setting firewall drop rule\n");
        return ERROR_FIREWALL;
    }

    return OK;
}


static int _run_command(char * command)
{
    if(b_dryrun || g_verbose){
        printf("SYS: '%s'\n",command);
        if(b_dryrun ) return 0;
    }
    int ret;
    ret = system(command);
    return ret;
}

static int _test_command(char * command)
{
    printf("CMD: '%s'\n",command);
    return 0;
}

static bool _is_interface_running(char * iface)
{
    int ret;
    wg_device * dev;

    // Does the tunnel exist?
    ret = wg_get_device(&dev, iface);
    if(ret==-1){
       printf("Permission denied, are you root?\n");
       return false;
    }
    if(ret==-ENODEV){
       return false;
    }
    wg_free_device(dev);
    return true;
}

static bool _interface_config_exists(char * iface)
{
    char name[200];
    if(!iface) return false;
    sprintf(name,"/etc/wireguard/%s.conf",iface);
    if( access( name, F_OK ) == 0 ) {
        return true;
    }
    //printf("File '%s' does not exist, can this user access it?\n",name);
    return false;
}
static uint16_t _uint16_swap(uint16_t in)
{
    uint16_t tmp16;
    tmp16 = in&0xFF;
    tmp16<<=8;
    tmp16 |= (in>>8)&0xff;
    return tmp16;
}
// EOF

