#ifndef __DEFS_H__
#define __DEFS_H__

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#define PROG_VERSION    "0.1.0"

// ONLY global variable
extern bool g_verbose;

// Show arguments in main
//#define DUMP_ARGS

// This will disable bringing the interface up or down
//#define SKIP_INTERFACE_CONTROL

#define DEFAULT_CONFIG_PATH     "/etc/wgnet"

#define USEC_PER_SEC	1000000

// Quick utility macros
#define strset(B,S) do{strncpy(&(B),S,sizeof(S)-1);}while(0)
#define pbuf(B,N)	do{int x=0;for(x=0;x<(N);x++) printf("0x%02X,",(B)[x]); printf("\n");}while(0)
#define cmp_const(B,S)	(strncmp((B),(S),sizeof(S)-1)==0)

#endif
