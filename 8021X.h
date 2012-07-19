#ifndef _8021X_H
#define _8021X_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

struct userinfo
{
    char *username;
    char *passwd;
    char *devname;
};

extern int Authentication(struct userinfo *info);
#endif
