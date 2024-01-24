#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/time.h>
#include <cutils/properties.h>

#include "am_cas.h"


#define INF(fmt, ...)       fprintf(stdout, fmt, ##__VA_ARGS__)
#define ERR(fmt, ...)       fprintf(stderr, "error:" fmt, ##__VA_ARGS__)


extern bool CreateVideoTunnelId(int* id);
extern void ReleaseSurface();



static void usage(char* argv0)
{
    printf("Usage:   %s [-c|-r]\n", argv0);
    printf("  -c  create tunner id. Called before running cas_hal_test.\n");
    printf("      Keep running during cas_hal_test. Ctrl+C to quit after cas_hal_test quit.\n\n");
    printf("  -r  release the surface. Called after quit from cas_hal_test.\n\n");
}

int main( int argc, char *argv[] )
{

    static int VideoTunnelId = 0;


    if (argc == 2) {
        if (strcmp(argv[1], "-c") == 0) {
            INF("Set VideoTunnelId \n");
            if (CreateVideoTunnelId(&VideoTunnelId) == true) {
                INF("CreateVideoTunnelId 's value: %d \n", VideoTunnelId);
                while (1) {
                    }
            } else {
                INF("CreateVideoTunnelId error.\n");
                return -1;
            }
            return 0;
        }
        if (strcmp(argv[1], "-r") == 0) {
            INF("ReleaseSureface\n");
            ReleaseSurface();
            return 0;
        }
        // end
        usage(argv[0]);
        return 0;
    } else {
        usage(argv[0]);
        return 0;
    }
}
