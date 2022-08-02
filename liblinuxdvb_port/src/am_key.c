#ifdef _FORTIFY_SOURCE
#undef _FORTIFY_SOURCE
#endif
/***************************************************************************
 * Copyright (c) 2014 Amlogic, Inc. All rights reserved.
 *
 * This source code is subject to the terms and conditions defined in the
 * file 'LICENSE' which is part of this source code package.
 *
 * Description:
 */
/**\file
 * \brief AMLogic 解扰器驱动
 *
 * \author Gong Ke <ke.gong@amlogic.com>
 * \date 2010-08-06: create the document
 ***************************************************************************/

#define CA_DEBUG_LEVEL 0

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include "aml_key.h"
#include "am_cas.h"

/****************************************************************************
 * Macro definitions
 ***************************************************************************/

#define DEV_NAME "/dev/key"
/****************************************************************************
 * Static data
 ***************************************************************************/

/****************************************************************************
 * API functions
 ***************************************************************************/
static int s_fd = -1;
int key_open (void)
{
    char buf[32];

    if (s_fd != -1)
        return s_fd;

    snprintf(buf, sizeof(buf), "/dev/key");
    s_fd = open(buf, O_RDWR);
    if (s_fd == -1) {
        printf("cannot open \"%s\" (%d:%s)", DEV_NAME, errno, strerror(errno));
        return -1;
    }
    printf("%s key fd:%d\n", buf, s_fd);
    return s_fd;
}

int key_close(int fd)
{
    if (fd == -1) {
        printf("key_close invalid fd\n");
        return 0;
    }
    close(fd);
    s_fd = -1;
    return 0;
}

/*
 * key_malloc contains slot alloc and slot config
 * the API also can be split to 2 APIs key_alloc/key_config
 */
int key_malloc(int fd, int key_userid, int key_algo, int is_iv)
{
    int ret = 0;
    struct key_alloc alloc_param;
    struct key_config config_param;

    if (fd == -1) {
        CA_DEBUG(0, "key malloc fd invalid\n");
        return -1;
    }
    alloc_param.is_iv = is_iv;
    alloc_param.key_index  = -1;

    ret = ioctl(fd, KEY_ALLOC, &alloc_param);
    if (ret == 0) {
        CA_DEBUG(0, "key_malloc index:%d\n", alloc_param.key_index);
    } else {
        CA_DEBUG(0, "fail \"%s\" (%d:%s)", DEV_NAME, errno, strerror(errno));
        return -1;
    }

    config_param.key_index = alloc_param.key_index;
    config_param.key_userid = key_userid;
    config_param.key_algo = key_algo;
    ret = ioctl(fd, KEY_CONFIG, &config_param);
    if (ret) {
        CA_DEBUG(0, "slot config failed\n");
    }

    return alloc_param.key_index;
}

int key_free(int fd, int key_index)
{
    int ret = 0;

    printf("key_free fd:%d key_index:%d\n", fd, key_index);
    if (fd == -1 || key_index == -1) {
        printf("key_free invalid parameter, fd:%d, key_index:%d\n", fd, key_index);
        return -1;
    }

    ret = ioctl(fd, KEY_FREE, key_index);
    if (ret == 0) {
        printf("key_free key_index:%d success\n", key_index);
        return 0;
    } else {
        printf("key_free key_index:%d fail\n", key_index);
        return -1;
    }
}

int key_set(int fd, int key_index, char *key, int key_len)
{
    int ret = 0;
    struct key_descr key_d;

    if (fd == -1 || key_index ==  -1 || key_len > 32) {
        printf("key_set invalid parameter, fd:%d, key_index:%d, key_len:%d\n",
            fd, key_index, key_len);
        return -1;
    }

    key_d.key_index = key_index;
    memcpy(&key_d.key, key, key_len);
    key_d.key_len = key_len;
    ret = ioctl(fd, KEY_SET, &key_d);
    if (ret == 0) {
        printf("key_set success\n");
        return 0;
    } else {
        printf("key_set fail\n");
        return -1;
    }
}

