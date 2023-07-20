#ifndef _AM_DMX_H
#define _AM_DMX_H

#include "dmx.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef void (*am_dmx_data_cb) (int dev_no, int fd, const unsigned char *data, int len, void *user_data);

int am_dmx_init(void);
int am_dmx_alloc_filter(int dev_no, int *fhandle);
int am_dmx_set_sec_filter(int dev_no, int fhandle, const struct dmx_sct_filter_params *params);
int am_dmx_set_buffer_size(int dev_no, int fhandle, int size);
int am_dmx_free_filter(int dev_no, int fhandle);
int am_dmx_start_filter(int dev_no, int fhandle);
int am_dmx_stop_filter(int dev_no, int fhandle);
int am_dmx_set_callback(int dev_no, int fhandle, am_dmx_data_cb cb, void *user_data);

#ifdef __cplusplus
}
#endif
#endif
