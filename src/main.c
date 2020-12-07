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
 * This file sets up the system, parses the command line options and
 * passes all variables to functions in the cmd.c source file.
 *
 ********************************************************************/

#include "defs.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <getopt.h>

#include "cmd.h"
#include "wgnet_conf.h"
#include "wg_conf.h"

// Definitions
// ----------------------------------------------------------------------------

// Types and enums
// ----------------------------------------------------------------------------

// Variables
// ----------------------------------------------------------------------------
bool g_verbose = false;

// Local prototypes
// ----------------------------------------------------------------------------

// Functions
// ----------------------------------------------------------------------------
void sigint_handler(int arg)
{
    printf("<---- catch ctrl-c\n");
    // g_running=false; // Kill any looping in the system?
}


void usage()
{
    printf("wgnet - WireGuard Network Tool\n\n");
    printf("The WireGuard provided wg and wg-quick tools manage WireGuard\n");
    printf("interfaces and add a route for the subnet. This tool allows users\n");
    printf("to set the network perameters of the network.  An config file holds a\n");
    printf("network inteface and network settings and the program controls the\n");
    printf("bring up or tear down of the interface, routing, firewall, and NAT.\n");
    printf("\n");
    printf("wgnet config files are not WireGuard config files\n\n");
    printf("Usage: wgnet <config> <command>\n");
    printf("   config           wgnet config to operate on\n");
    printf("   command          Action to take on the config\n");
    printf("        status (default)  Show the status of the config\n");
    printf("        showconf          Show the saved config settings\n");
    printf("        new               Create a new config\n");
    printf("        up                Bring up the named config\n");
    printf("        down              Tear down the named config\n");
    printf("        restart           Restart the named config, (reloads all parameters from config file)\n");
    printf("\n");
    printf("   --dryrun, -D     Dry run, don't actually do changes\n");
    printf("   --path, -P       Set the path of the config files\n");
    printf("   -L               List config files and directory, and exit\n");
    printf("   -F               Force operations (overwrite for 'new' command)\n");
    printf("   --version, -V    Print version info and exit\n");
    printf("   -v               Enable verbose output\n");
    printf("   -h?              Program help (This output)\n");
    exit(0);
}


// Main function
// ----------------------------------------------------------------------------
int main(int argc,char** argv)
{
    int tty_fd;
    fd_set rfds;
    struct timeval tv;
    int retval;
    int optchar;
    char config[200] = "";
    char command[20] = "status";
    bool force = false;
    bool list_files = false;
    
    
    struct option longopts[] = {
    { "verbose", no_argument,       0, 'v' },
    { "dryrun", no_argument,       0, 'D' },
    { "path", required_argument,       0, 'P' },
    { "version", no_argument,       0, 'V' },
    { 0, 0, 0, 0 }
    };

    #ifdef DUMP_ARGS
    printf("argc=%d\n",argc);
    for(int x=0;x<argc;x++)
    {
        printf("  - arg[%d] = '%s'\n",x,argv[x]);
    }
    #endif
    
    // Initialize systems before anything
    conf_init();
    cmd_init();
    
    // Arg check, if no args, just do a listing of the config files
    if(argc<2){
        list_files = true;
        //usage();
    }else{
        // Save the name of the config
        strncpy(config,argv[1],sizeof(config)-1);
    }
    
    // Save command if it exists
    if(argc>=3)
    {
        strncpy(command,argv[2],sizeof(command));
    }
    
    // TODO: Loop over args once to get -v before processing others?
    
    // Process the command line options
    while ((optchar = getopt_long(argc, argv, "DLFVvh?", \
           longopts, NULL)) != -1)
    {
       switch (optchar)
       {
       case 'D':
            cmd_enable_dryrun();
            break;
       case 'P':
            conf_set_path(optarg);
            break;
       case 'F':
            force = true;
            if(g_verbose) printf("Force = true\n");
            break;
       case 'L':
           list_files = true;
           break;
       case 'v':
           printf("Verbose = true\n");
           g_verbose = true;
           break;
       case 'V':
           printf("wgnet - WireGuard network tool\n");
           printf("Build %s %s - CLI Systems LLC\n",__DATE__,__TIME__);
           printf("Version %s\n",PROG_VERSION);
           exit(0);
       default:
           usage();
           break;
       }
    };
    
    // Setup system
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    // Special case, no args, just list files and exit
    if(list_files)
    {
        cmd_list();
        exit(0);
    }


    // Handle data from stdin
    if(g_verbose) printf("Processing config '%s' command '%s'\n",config,command);
    
    // Process the command
    if(cmp_const(command,"showconf")){
        cmd_show(config);
    }else if(cmp_const(command,"status")){
        cmd_status(config);
    }else if(cmp_const(command,"new")){
        cmd_default(config,force);
    }else if(cmp_const(command,"up")){
        cmd_net_up(config, force);
    }else if(cmp_const(command,"down")){
        cmd_net_down(config, force);
    }else if(cmp_const(command,"restart")){
        cmd_net_restart(config, force);

    // Run tests?
    }else if(cmp_const(command,"test")){
            cmd_test(config);
    }else{
        printf("Unknown command '%s'\n",command);
    }
    

    conf_end();

    // Shutdown system  
    if(g_verbose) printf("Terminating\n");
    return EXIT_SUCCESS;
}

// EOF
