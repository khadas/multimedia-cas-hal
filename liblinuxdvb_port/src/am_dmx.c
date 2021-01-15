/**
 * @brief   linux dvb demux wrapper
 * @file    am_dmx.c
 * @date    02/27/2020
 * @author  Yahui Han
 */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/dvb/dmx.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "am_cas.h"
#include "am_dmx.h"

#define DMX_COUNT (3)
#define DMX_FILTER_COUNT (32*DMX_COUNT)
#define SEC_BUF_SIZE (4096)
#define DMX_POLL_TIMEOUT (200)

#define DMX_FILTER_MASK_ISEMPTY(m)	(!(*(m)))
#define DMX_FILTER_MASK_CLEAR(m)	(*(m)=0)
#define DMX_FILTER_MASK_ISSET(m,i)	(*(m)&(1<<(i)))
#define DMX_FILTER_MASK_SET(m,i)	(*(m)|=(1<<(i)))

#define CA_DEBUG_LEVEL 2

typedef struct
{
    int dev_no;
    int fd;
    int used;
    int enable;
    int need_free;
    am_dmx_data_cb cb;
    void *user_data;
}dvb_dmx_filter_t;

typedef struct
{
    int running;
    pthread_t thread;
    pthread_mutex_t lock;

    dvb_dmx_filter_t filter[DMX_FILTER_COUNT];
}dvb_dmx_t;

static dvb_dmx_t g_dvb_dmx;

static void* dmx_data_thread(void *arg)
{
    int i, fid;
    int ret;
    int cnt, len;
    uint32_t mask;
    uint8_t *sec_buf = NULL;
    int fids[DMX_FILTER_COUNT];
    struct pollfd fds[DMX_FILTER_COUNT];
    dvb_dmx_filter_t *filter = NULL;
    dvb_dmx_t *dmx = (dvb_dmx_t *)arg;

    sec_buf = (uint8_t *)malloc(SEC_BUF_SIZE);

    while(dmx->running)
    {
	cnt = 0;
	mask = 0;

	pthread_mutex_lock(&g_dvb_dmx.lock);

	for (fid = 0; fid < DMX_FILTER_COUNT; fid++)
	{
	    if (dmx->filter[fid].need_free)
            {
		filter = &dmx->filter[fid];
                close(filter->fd);
                filter->used = 0;
		filter->need_free = 0;
		filter->cb = NULL;
            }

	    if (dmx->filter[fid].used)
	    {
		fds[cnt].events = POLLIN | POLLERR;
		fds[cnt].fd = dmx->filter[fid].fd;
		fids[cnt] = fid;
		cnt++;
	    }
	}

	pthread_mutex_unlock(&g_dvb_dmx.lock);

	if (!cnt)
    {
        usleep(20);
	    continue;
    }

	ret = poll(fds, cnt, DMX_POLL_TIMEOUT);
	if (ret <= 0)
	{
	    //usleep(10000);
	    continue;
	}

	for (i = 0; i < cnt; i++)
	{
	    if (fds[i].revents & (POLLIN | POLLERR))
	    {
		pthread_mutex_lock(&g_dvb_dmx.lock);
		filter = &dmx->filter[fids[i]];
		if (!filter->enable || !filter->used || filter->need_free)
		{
		    CA_DEBUG(1, "ch[%d] not used, not read", fids[i], len);
		    len = 0;
		}
		else
		{
                    len = read(filter->fd, sec_buf, SEC_BUF_SIZE);
		    if (len <= 0)
		    {
			CA_DEBUG(1, "read demux filter[%d] failed (%s) %d", fids[i], strerror(errno), errno);
		    }
		}
		pthread_mutex_unlock(&g_dvb_dmx.lock);

		//if (len)
		//    CA_DEBUG(1, "tid[%#x] ch[%d] %#x bytes", sec_buf[0], fids[i], len);

		if (len > 0 && filter->cb)
		{
		    filter->cb(filter->dev_no, fids[i], sec_buf, len, filter->user_data);
		}
	    }
	}
    }

    if (sec_buf)
    {
	free(sec_buf);
    }

    return NULL;
}

static dvb_dmx_filter_t* get_filter(int dev_no, int fhandle)
{
    if (dev_no >= DMX_COUNT)
    {
	CA_DEBUG(1, "wrong dmx device no %d", dev_no);
	return NULL;
    }

    if (fhandle >= DMX_FILTER_COUNT)
    {
	CA_DEBUG(1, "wrong filter no");
	return NULL;
    }

    if (!g_dvb_dmx.filter[fhandle].used)
    {
	CA_DEBUG(1, "filter %d not allocated", fhandle);
	return NULL;
    }

    return &g_dvb_dmx.filter[fhandle];
}

int am_dmx_init(void)
{
    if (g_dvb_dmx.running)
    {
	    CA_DEBUG(1, "dmx already initialized");
	    return -1;
    }

    memset(&g_dvb_dmx, 0, sizeof(dvb_dmx_t));
    pthread_mutex_init(&g_dvb_dmx.lock, NULL);
    g_dvb_dmx.running = 1;
    pthread_create(&g_dvb_dmx.thread, NULL, dmx_data_thread, &g_dvb_dmx);

    CA_DEBUG(2, "%s", __FUNCTION__);
    return 0;
}

int am_dmx_alloc_filter(int dev_no, int *fhandle)
{
    int fd;
    int fid;
    dvb_dmx_filter_t *filter = NULL;
    char dev_name[32];

    if (dev_no >= DMX_COUNT)
    {
	CA_DEBUG(1, "alloc failed, wrong dmx device no %d", dev_no);
	return -1;
    }

    pthread_mutex_lock(&g_dvb_dmx.lock);
    filter = &g_dvb_dmx.filter[0];
    for (fid = 0; fid < DMX_FILTER_COUNT; fid++)
    {
	if (!filter[fid].used)
	{
	    break;
	}
    }

    if (fid >= DMX_FILTER_COUNT)
    {
	CA_DEBUG(1, "no free section filter");
	pthread_mutex_unlock(&g_dvb_dmx.lock);
	return -1;
    }

    memset(dev_name, 0, sizeof(dev_name));
    sprintf(dev_name, "/dev/dvb0.demux%d", dev_no);    
    fd = open(dev_name, O_RDWR);
    if (fd == -1)
    {
	CA_DEBUG(1, "cannot open \"%s\" (%s)", dev_name, strerror(errno));
	pthread_mutex_unlock(&g_dvb_dmx.lock);
	return -1;
    }

    memset(&filter[fid], 0, sizeof(dvb_dmx_filter_t));
    filter[fid].dev_no = dev_no;
    filter[fid].fd = fd;
    filter[fid].used = 1;
    *fhandle = fid;

    pthread_mutex_unlock(&g_dvb_dmx.lock);

    CA_DEBUG(2, "%s fhandle = %d", __FUNCTION__, fid);
    return 0;
}

int am_dmx_set_sec_filter(int dev_no, int fhandle, const struct dmx_sct_filter_params *params)
{
    int ret = -1;
    dvb_dmx_filter_t *filter = NULL;
    
    CAS_ASSERT(params);

    pthread_mutex_lock(&g_dvb_dmx.lock);

    filter = get_filter(dev_no, fhandle);
    if (filter)
    {
	ret = ioctl(filter->fd, DMX_SET_FILTER, params);
    }

    pthread_mutex_unlock(&g_dvb_dmx.lock);

    CA_DEBUG(2, "%s pid = %#x, ret = %d", __FUNCTION__, params->pid, ret);
    return ret;
}

int am_dmx_set_buffer_size(int dev_no, int fhandle, int size)
{
    int ret = -1;
    dvb_dmx_filter_t *filter = NULL;

    pthread_mutex_lock(&g_dvb_dmx.lock);

    filter = get_filter(dev_no, fhandle);
    if (filter)
    {
	ret = ioctl(filter->fd, DMX_SET_BUFFER_SIZE, size);
    }

    pthread_mutex_unlock(&g_dvb_dmx.lock);

    CA_DEBUG(2, "%s ret = %d", __FUNCTION__, ret);
    return ret;
}

int am_dmx_free_filter(int dev_no, int fhandle)
{
    int ret = -1;
    dvb_dmx_filter_t *filter = NULL;

    pthread_mutex_lock(&g_dvb_dmx.lock);

    filter = get_filter(dev_no, fhandle);
    if (filter)
    {
	filter->need_free = 1;
	ret = 0;
    }

    pthread_mutex_unlock(&g_dvb_dmx.lock);

    CA_DEBUG(2, "%s ret = %d, fhandle = %d", __FUNCTION__, ret, fhandle);
    return ret;
}

int am_dmx_start_filter(int dev_no, int fhandle)
{
    int ret = -1;
    dvb_dmx_filter_t *filter = NULL;

    pthread_mutex_lock(&g_dvb_dmx.lock);

    filter = get_filter(dev_no, fhandle);
    if (filter && !filter->enable)
    {
	ret = ioctl(filter->fd, DMX_START, 0);
	if (ret == 0)
	{
	    filter->enable = 1;
	}
    }

    pthread_mutex_unlock(&g_dvb_dmx.lock);

    CA_DEBUG(2, "%s ret = %d", __FUNCTION__, ret);
    return ret;
}

int am_dmx_stop_filter(int dev_no, int fhandle)
{
    int ret = -1;
    dvb_dmx_filter_t *filter = NULL;

    pthread_mutex_lock(&g_dvb_dmx.lock);

    filter = get_filter(dev_no, fhandle);
    if (filter && filter->enable)
    {
	ret = ioctl(filter->fd, DMX_STOP, 0);
	if (ret == 0)
	{
	    filter->enable = 0;
	}
    }

    pthread_mutex_unlock(&g_dvb_dmx.lock);

    CA_DEBUG(2, "%s ret = %d", __FUNCTION__, ret);
    return ret;
}

int am_dmx_set_callback(int dev_no, int fhandle, am_dmx_data_cb cb, void *user_data)
{
    int ret = -1;
    dvb_dmx_filter_t *filter = NULL;

    pthread_mutex_lock(&g_dvb_dmx.lock);
    filter = get_filter(dev_no, fhandle);
    if (filter)
    {
	filter->cb = cb;
	filter->user_data = user_data;
	ret = 0;
    }

    pthread_mutex_unlock(&g_dvb_dmx.lock);

    CA_DEBUG(2, "%s ret = %d", __FUNCTION__, ret);
    return ret;
}

int am_dmx_term(int dev_no)
{
    int i;
    int open_count = 0;
    dvb_dmx_filter_t *filter = NULL;

    pthread_mutex_lock(&g_dvb_dmx.lock);

    for (i = 0; i < DMX_FILTER_COUNT; i++)
    {
	filter = &g_dvb_dmx.filter[i];
	if (filter->used && filter->dev_no == dev_no)
	{
	    if (filter->enable)
	    {
		ioctl(filter->fd, DMX_STOP, 0);
	    }
	    //TODO: close here?
	    close(filter->fd);
	} else if (filter->used)
	{
	    open_count++;
	}
    }

    if (open_count == 0)
    {
	g_dvb_dmx.running = 0;
	pthread_join(g_dvb_dmx.thread, NULL);
	pthread_mutex_destroy(&g_dvb_dmx.lock);
    }

    pthread_mutex_unlock(&g_dvb_dmx.lock);

    return 0;
}
