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
 * This file handles the configuration parsing.  This file loads a
 * config, and stores the data in the module scope cfg_t variables.
 * Accessor functions allow the cmd.c source to set/set values.
 *
 ********************************************************************/

#include "defs.h"
#include "wgnet_conf.h"

#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <confuse.h>

#include "wireguard/wireguard.h"


// Definitions
// ----------------------------------------------------------------------------

// Types
// ----------------------------------------------------------------------------
cfg_opt_t routing_opts[] = {
    CFG_BOOL("RouteSubnet", cfg_false, CFGF_NONE),
    CFG_STR_LIST("Networks", "{}", CFGF_NONE),
    CFG_END()
};
cfg_opt_t nat_opts[] = {
    CFG_BOOL("enabled", cfg_false, CFGF_NONE),
    CFG_STR("OutInterface", NULL, CFGF_NONE),
    CFG_END()
};
cfg_opt_t firewall_host_opts[] = {
    CFG_STR("Host", "", CFGF_NONE),
    CFG_INT_LIST("AllowedPorts", "{}", CFGF_NONE),
    CFG_END()
};
cfg_opt_t opts[] = {
    CFG_STR("interface", NULL, CFGF_NONE),
    CFG_SEC("routing", routing_opts, CFGF_NONE),
    CFG_SEC("nat", nat_opts, CFGF_NONE),
    CFG_SEC("firewall_host", firewall_host_opts, CFGF_MULTI ),
    CFG_END()
};

// Variables
// ----------------------------------------------------------------------------
char config_path[240];
char config_fullpath[255];
cfg_t * current_cfg;

// Local functions
// ----------------------------------------------------------------------------
static char * _conf_make_fullpath(char * name);
static bool _conf_direxists(char * path);
static void _conf_free_current_cfg();
static void _conf_dump(cfg_t * current_cfg);

// Public functions
// ----------------------------------------------------------------------------
void conf_init()
{
    sprintf(config_path,"%s",DEFAULT_CONFIG_PATH);
    current_cfg = NULL;
    return;
}

void conf_end()
{
    _conf_free_current_cfg();
    if(g_verbose) printf("Conf ending, freeing memory\n");
    return;
}

// Data access functions
// ----------------------------------------------------------------------------
void conf_dump()
{
    _conf_dump(current_cfg);
    return;
}
void conf_set_interface(char * interface)
{
    if(!current_cfg || !interface) return;
    cfg_setstr(current_cfg, "interface", interface);
    return;
}

char * conf_get_interface()
{
    if(!current_cfg) return NULL;
    return cfg_getstr(current_cfg, "interface");
}

bool conf_get_routesubnet()
{
    cfg_t * sec;
    if(!current_cfg) return false;
    sec = cfg_getnsec(current_cfg, "routing", 0);
    if(!sec) return false;
    return cfg_getbool(sec, "RouteSubnet");
}
int conf_get_routesubnet_cidr()
{
    return 24;
}


int conf_get_num_routed_networks()
{
    cfg_t * sec;
    if(!current_cfg) return -1;
    sec = cfg_getnsec(current_cfg, "routing", 0);
    return cfg_size(sec, "Networks");
}

char * conf_get_route_subnet(int id)
{
    cfg_t * sec,host;
    if(!current_cfg) return NULL;
    sec = cfg_getnsec(current_cfg, "routing", 0);
    if(!sec) return NULL;
    return cfg_getnstr(sec, "Networks", id);
}

bool conf_get_enablenat()
{
    cfg_t * sec;
    if(!current_cfg) return false;
    sec = cfg_getnsec(current_cfg, "nat", 0);
    return cfg_getbool(sec, "enabled");
}
char * conf_get_nat_outinterface()
{
    cfg_t * sec;
    if(!current_cfg) return NULL;
    sec = cfg_getnsec(current_cfg, "nat", 0);
    return cfg_getstr(sec, "OutInterface");
}

int conf_get_num_firewall_hosts()
{
    return cfg_size(current_cfg, "firewall_host");;
}

int conf_get_firewall_host_num_ports(int id)
{
    cfg_t * sec;
    if(!current_cfg) return -1;
    sec = cfg_getnsec(current_cfg, "firewall_host", id);
    if(!sec) return -1;

    return cfg_size(sec, "AllowedPorts");
}

char * conf_get_firewall_host_ip(int id)
{
    cfg_t * sec;
    if(!current_cfg) return NULL;
    sec = cfg_getnsec(current_cfg, "firewall_host", id);
    if(!sec) return NULL;
    return cfg_getstr(sec, "Host");
}

uint16_t conf_get_firewall_host_port(int id,int port_id)
{
    cfg_t * sec;
    if(!current_cfg) return 0;
    sec = cfg_getnsec(current_cfg, "firewall_host", id);
    if(!sec) return 0;
    return cfg_getnint(sec,"AllowedPorts",port_id);
}


// Config file functions
// ----------------------------------------------------------------------------
void conf_set_path(char * newpath)
{
    // Remove trailing slashes
    int len = strlen(newpath);
    while(len && newpath[len-1]=='/'){
        newpath[len-1]=0;
        len = strlen(newpath);
    }
    if(len<=0) return;
            
    // Save path
    if(g_verbose) printf("conf, new path is '%s'\n",newpath);
    strncpy(config_path,newpath,sizeof(config_path));
    
    // check path exists, if it doesn't, error!
    if(!_conf_direxists(newpath))
    {
        mkdir(newpath, S_IRWXU );
    }
    return;
}

char * conf_get_path()
{
    return config_path;
}

bool conf_exists(char * conf_name)
{
    char * file;

    // See if the passed file is valid
    if(g_verbose) printf("checking '%s'...",conf_name);
    if( access( conf_name, F_OK ) != -1 ) {
        if(g_verbose) printf("exists\n");
        return true;
    }
    if(g_verbose) printf("does NOT exist\n");

    // See if the file adding the path and .conf exists
    file = _conf_make_fullpath(conf_name);
    if(g_verbose) printf("checking '%s'...",file);
    if( access( file, F_OK ) != -1 ) {
        if(g_verbose) printf("exists\n");
        return true;
    }
    if(g_verbose) printf("does NOT exist\n");
    return false;
}

bool conf_remove(char * conf_name)
{
    char * file;

    // See if the passed file is valid
    if( access( conf_name, F_OK ) != -1 ) {
        if(g_verbose) printf("removing '%s'\n",conf_name);
        return (unlink(conf_name)==0);
    }

    file = _conf_make_fullpath(conf_name);
    if(g_verbose) printf("removing '%s'\n",file);
    return (unlink(file)==0);
}

bool conf_load_default()
{
    cfg_t * cfg;

    if(g_verbose) printf("config default data loaded\n");

    cfg = cfg_init(opts, CFGF_NOCASE);

    _conf_free_current_cfg();
    current_cfg = cfg;
    return true;
}

bool conf_load(char * conf_name)
{
    char * file;

    // If the file exists, use that, if not, use
    // the default location .conf
    if( access( conf_name, F_OK ) != -1 ) {
        file = conf_name;
    }else{
        file = _conf_make_fullpath(conf_name);
    }

    if(g_verbose) printf("Loading '%s'\n",file);

    cfg_t *cfg;
    int ret;

    cfg = cfg_init(opts, CFGF_NOCASE);
    ret = cfg_parse(cfg, file);
    //printf("cfg_parse ret %d\n",ret);
    if (ret == CFG_FILE_ERROR) {
        printf("Error: file error\n");
    } else if (ret == CFG_PARSE_ERROR) {
        printf("Error: parse error\n");
    }else{

        //_conf_dump(cfg);

        _conf_free_current_cfg();
        current_cfg = cfg;
        return true;
    }

    cfg_free(cfg);
    return false;
}

bool conf_save(char * conf_name)
{
    FILE * fp;
    char * file;

    // if the file name, has the .conf, use that, otherwise
    // format the name
    if(strstr(conf_name,".conf")!=NULL)
    {
        file = conf_name;
    }else{
        file = _conf_make_fullpath(conf_name);
    }


    if(g_verbose) printf("Saving '%s'\n",file);
    printf("Open file '%s'\n",file);
    fp  = fopen(file, "w" );
    if(fp)
    {
        // Write the data
        cfg_print(current_cfg, fp);
        fclose(fp);
    }else{
        printf("Error writing to file '%s'\n",file);
        return false;
    }
    
    return true;
}


#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

// Should prob move these to new 'util' source file

// https://stackoverflow.com/questions/2283494/get-ip-address-of-an-interface-on-linux
uint32_t get_ip_of_interface(char * iface)
{
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    // get ip4 address
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

    // ioctl
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);

    return (uint32_t)((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
    #if 0
    strncpy(ip,inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), max_size);
    return;
    #endif
}

uint32_t get_netmask_of_interface(char * iface)
{
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    // get ip4 address
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

    // ioctl
    ioctl(fd, SIOCGIFNETMASK, &ifr);
    close(fd);

    return (uint32_t)((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr;
}

uint16_t cidr_from_netmask(uint32_t netmask)
{
    int x=0;
    while(netmask&0x1){
        x++;
        netmask>>=1;
    }
    return x;
}

void cidr_of_interface(char * iface, char * out, int max_len)
{
    struct in_addr a;
    int cidr;
    a.s_addr = (unsigned long)get_ip_of_interface(iface);
    cidr = cidr_from_netmask(get_netmask_of_interface(iface));
    snprintf(out,max_len,"%s/%d",inet_ntoa(a),cidr);
    return;
}

// Public functions
// ----------------------------------------------------------------------------
static char * _conf_make_fullpath(char * name)
{
    sprintf(config_fullpath,"%s/%s.conf",config_path,name);
    return config_fullpath;
}

static bool _conf_direxists(char * path)
{
    DIR* dir = opendir(path);
    if (dir) {
        closedir(dir);
        if(g_verbose) printf("Dir '%s' exists\n",path);
        return true;
    }
    if(g_verbose) printf("Dir '%s' does NOT exist\n",path);
    return false;
}

static void _conf_free_current_cfg()
{
    if(current_cfg)
    {
        cfg_free(current_cfg);
        current_cfg=NULL;
    }
    return;
}

static void _conf_dump_sec_routing(cfg_t * sec)
{
    int x,n;
    if(!sec) return;
    printf("  - RouteSubnet: %s\n",((cfg_getbool(sec, "RouteSubnet"))?"true":"false"));
    n = cfg_size(sec, "Networks");
    printf("  - Route %d networks\n", n);
    for(x = 0; x < n; x++)
    {
        printf("  - Network %s\n", cfg_getnstr(sec, "Networks", x));
    }
    return;
}

static void _conf_dump_sec_nat(cfg_t * sec)
{
    int x,n;
    if(!sec) return;
    printf("  - enabled: %s\n",((cfg_getbool(sec, "enabled"))?"true":"false"));

    // Future, per host nat-ing?
    #if 0
    n = cfg_size(sec, "Hosts");
    printf("  - Found %d hosts\n", n);
    for(x = 0; x < n; x++)
    {
        printf("  - Host %s\n", cfg_getnstr(sec, "Hosts", x));
    }
    #endif
    return;
}

static void _conf_dump_sec_firewall(cfg_t * sec)
{
    int x,n;
    if(!sec) return;
    printf("  - Host %s\n",cfg_getstr(sec, "Host"));
    x = cfg_size(sec, "AllowedPorts");
    printf("  - Allowed ports %d\n", x);
    for(n = 0; n < x; n++)
    {
        printf("    - Port %ld\n", cfg_getnint(sec, "AllowedPorts", n));
    }
}

static void _conf_dump(cfg_t * cfg)
{
    int n,x,y;
    int ports;
    cfg_t *sec;

    printf("interface = %s\n", cfg_getstr(cfg, "interface"));

    // Routing
    printf("* Routing\n");
    _conf_dump_sec_routing(cfg_getnsec(cfg, "routing", 0));

    // NAT
    printf("* NAT\n");
    _conf_dump_sec_nat(cfg_getnsec(cfg, "nat", 0));

    // Firewall hosts
    n = cfg_size(cfg, "firewall_host");
    printf("* Firewall hosts (%d found)\n", n);
    for (x = 0; x < n; x++) {
        printf("* Firewall host %d\n", x);
        _conf_dump_sec_firewall(cfg_getnsec(cfg, "firewall_host", x));
    }
    printf("\n");

    return;
}

// EOF
