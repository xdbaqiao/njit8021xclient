/*************************************************************************
* File Name: main.c
* Author: Bingo
* Mail: baqiaoyancao@163.com
* Created Time: 2012年07月16日 星期一 14时31分30秒
*************************************************************************/

#include "8021X.h"


int main( int argc, char *argv[] )
{
    struct userinfo info;

    if( getuid() != 0 )
    {
        fprintf( stderr, "Error: Need root permission!\n");
        exit(-1);
    }
    if( argc <3 || argc > 4)
    {
        printf("Error!\n"
                "USAGE:h3c username passwd\n"
                "      h3c username passwd eth0\n"
                "      h3c username passwd eth1\n" );
        exit(-1);
    }

    info.username = argv[1];
    info.passwd = argv[2];
    if( argc ==3 ) info.devname = "eth0";
    else info.devname = argv[3];

    Authentication(&info);
    return 0;
}
