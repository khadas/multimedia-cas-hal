#ifndef CA_DEBUG_LEVEL
#define CA_DEBUG_LEVEL 2
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/dvb/dmx.h>
#include <linux/dvb/ca.h>

#include "UniversalClient_API.h"
#include "UniversalClient_Common_SPI.h"
#include "UniversalClient_IPTV_API.h"
#include "UniversalClient_Stdlib.h"
#include "UniversalClient_Common_API.h"
#include "UniversalClient_DVB_API.h"
#include "UniversalClient_SPI.h"
#include "UniversalClient_Types.h"

//#undef ANDROID

#include "am_cas.h"
#include "caclientapi.h"
#include "ird_cas.h"


#define DUMP_DEBUG

#define PVR_SESSION_KEY_CHECK_LOOP (5)
#define PVR_SESSION_KEY_CHECK_TIME (300)   //500ms

#define DMX_DEVICE_NO  (0)
#define MAX_AES_IV_LEN (16)

static pthread_mutex_t mutex_lock = PTHREAD_MUTEX_INITIALIZER;

static HAL_DMX_Channel s_dmx_channels[HAL_DMX_CHANNEL_NUM];
static HAL_DMX_Filter s_dmx_filters[HAL_DMX_FILTER_NUM];
static HAL_DESC_Slot s_desc_slots[HAL_DESC_SLOT_NUM];

static uint8_t session_key[16];
static uint8_t s_aes_cbc_iv[MAX_AES_IV_LEN] = {0x49, 0x72, 0x64, 0x65, 0x74, 0x6f, 0xa9, 0x43, 0x6f, 0x70, 0x79, 0x72, 0x69, 0x67, 0x68, 0x74};

static int b_set_pvr_session_key = 0;

static void process_section_callback(int dev_no, int fid, const uint8_t *data, int len, void *user_data)
{
	HAL_DMX_Channel *ch = AML_NULL;
	HAL_DMX_Filter  *f = AML_NULL;
	uc_notify_callback notifyCallback;
	uc_buffer_st	sections;
	uint32_t index = 0;

#ifdef DUMP_DEBUG
	CA_DEBUG(0, "[%s], device no: %d, fid: %d, data len: %d\n", __FUNCTION__, dev_no, fid, len);
	CA_DEBUG(0, "[%02x][%02x][%02x][%02x][%02x][%02x][%02x][%02x]\n", data[0], data[1], data[2], data[3], \
										data[4], data[5], data[6], data[7]);
#endif

	for (index = 0; index < HAL_N_ELEM(s_dmx_filters); index ++)
	{
		f = &s_dmx_filters[index];

		if (f->fd == fid)
		{
			ch = f->channel;
			notifyCallback = (uc_notify_callback)ch->connect_notify;
			sections.bytes = malloc(len);
			sections.length = len;

			memset(sections.bytes, 0x00, len);
			memcpy(sections.bytes, data, len);

			notifyCallback((uc_connection_handle)ch->connect, &sections);

#if 0
			/* dump EMM section into file**/
			if (sections.bytes[0] != 0x81 && sections.bytes[0] != 0x80)
			{
				FILE *fpt;
				int i = 0;

				fpt = fopen("/data/vendor/irdeto/section.txt","a");
				for (i = 0 ; i < sections.length; i++)
				{
					fprintf(fpt, "0x%02x ", sections.bytes[i]);
				}

				fprintf(fpt, "\n");
				fclose(fpt);
			}
#endif

			free(sections.bytes);
		}
	}
}

static int file_echo(const char *name, const char *cmd)
{
    int fd, ret, len;
    fd = open(name, O_WRONLY);
    if (fd == -1)
    {
	CA_DEBUG(0, "cannot open file \"%s\"", name);
        return -1;
    }

    len = strlen(cmd);
    ret = write(fd, cmd, len);
    if (ret != len)
    {
	CA_DEBUG(0, "write failed file:\"%s\" cmd:\"%s\" error:\"%s\"", name, cmd, strerror(errno));
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

static void copy_key_data(ifcp_keydata_t *p_keydata, ifcp_keydata_response_t *p_key_data_response, uc_IFCP_input *pInput, uc_IFCP_output *pOutput)
{
	uint32_t index = 0;

	memset(p_keydata, 0x00, sizeof(ifcp_keydata_t));
	memset(p_key_data_response, 0x00, sizeof(ifcp_keydata_response_t));

	p_keydata->kl_info.header[0] = pInput->pIFCPInfo->pKLCInfo->header[0];
	p_keydata->kl_info.header[1] = pInput->pIFCPInfo->pKLCInfo->header[1];
	p_keydata->kl_info.header[2] = pInput->pIFCPInfo->pKLCInfo->header[2];
	p_keydata->kl_info.extra_data_control_byte = pInput->pIFCPInfo->pKLCInfo->ED_Ctrl;

	CA_DEBUG(0, "extraData length: %d\n", pInput->pIFCPInfo->pKLCInfo->extraData.length);
	if ((pInput->pIFCPInfo->pKLCInfo->extraData.bytes != AML_NULL) && (pInput->pIFCPInfo->pKLCInfo->extraData.length != 0))
	{
		p_keydata->kl_info.extra_data.p_data = pInput->pIFCPInfo->pKLCInfo->extraData.bytes;
		p_keydata->kl_info.extra_data.data_len = pInput->pIFCPInfo->pKLCInfo->extraData.length;
	}

	CA_DEBUG(0, "payload length: %d\n", pInput->pIFCPInfo->pKLCInfo->payload.length);
	p_keydata->kl_info.key_payload.p_data = pInput->pIFCPInfo->pKLCInfo->payload.bytes;
	p_keydata->kl_info.key_payload.data_len = pInput->pIFCPInfo->pKLCInfo->payload.length;

	if (pInput->pIFCPInfo->pApplicationControlInfo != AML_NULL)
	{
		for (index = 0; index < IFCP_APP_CONTROL_INFO_HEADER_LEN; index++)
		{
			p_keydata->app_info.header[index] = pInput->pIFCPInfo->pApplicationControlInfo->header[index];
		}

		if ((pInput->pIFCPInfo->pApplicationControlInfo->payload.bytes != AML_NULL) && (pInput->pIFCPInfo->pApplicationControlInfo->payload.length != 0))
		{
			p_keydata->app_info.app_control_payload.p_data = pInput->pIFCPInfo->pApplicationControlInfo->payload.bytes;
			p_keydata->app_info.app_control_payload.data_len = pInput->pIFCPInfo->pApplicationControlInfo->payload.length;
		}
	}

	CA_DEBUG(0, "response length = %d, appResponse length = %d\n", pOutput->response.length, pOutput->appResponse.length);
	p_key_data_response->kl_response.p_data = pOutput->response.bytes;
	p_key_data_response->kl_response_len = p_key_data_response->kl_response.data_len = pOutput->response.length;

	p_key_data_response->app_control_response.p_data = pOutput->appResponse.bytes;
	p_key_data_response->app_control_response_len = p_key_data_response->app_control_response.data_len = pOutput->appResponse.length;

	return;
}

Ird_status_t Spi_Stream_Init(void)
{
	Ird_status_t ret = IRD_NO_ERROR;
	uint32_t index = 0;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	am_dmx_init();

    pthread_mutex_init(&mutex_lock, NULL);

	for (index = 0; index < HAL_N_ELEM(s_dmx_channels); index++)
	{
		s_dmx_channels[index].id = index;
		s_dmx_channels[index].state = HAL_DMX_CHANNEL_STATE_IDLE;
		s_dmx_channels[index].pid = INVALID_PID;
		s_dmx_channels[index].stream_type = INVALID_STREAM_TYPE;
		s_dmx_channels[index].filters = AML_NULL;
		s_dmx_channels[index].fd = -1;
		s_dmx_channels[index].buffer_size = 32 * 1024;
		s_dmx_channels[index].connect = 0;
		s_dmx_channels[index].connect_notify = AML_NULL;
	}

	for (index = 0; index < HAL_N_ELEM(s_dmx_filters); index++)
	{
		s_dmx_filters[index].id = index;
		s_dmx_filters[index].channel = AML_NULL;
		s_dmx_filters[index].next = AML_NULL;
		s_dmx_filters[index].state = HAL_DMX_FILTER_STATE_IDLE;
		s_dmx_filters[index].pid = INVALID_PID;
		s_dmx_filters[index].fd = -1;
		s_dmx_filters[index].has_filter = 0;
		s_dmx_filters[index].depth = -1;
	}

	for (index = 0; index < HAL_N_ELEM(s_desc_slots); index++)
	{
		s_desc_slots[index].id = index;
		s_desc_slots[index].channel = AML_NULL;
		s_desc_slots[index].next = AML_NULL;
		s_desc_slots[index].state = HAL_DMX_FILTER_STATE_IDLE;
		s_desc_slots[index].pid = INVALID_PID;
		s_desc_slots[index].fd = -1;
	}

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);

	return ret;
}

Ird_status_t Spi_Stream_SetCSSK(uc_cssk_info * pCSSKInfo)
{
	Ird_status_t ret = IRD_NO_ERROR;
	uint32_t index = 0;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	for (index = 0; index < pCSSKInfo->pCSSK->length; index++)
	{
		session_key
[index] = pCSSKInfo->pCSSK->bytes[index];
	}

#ifdef DUMP_DEBUG
	CA_DEBUG(0, "prnit CSSK, length: %d\n", pCSSKInfo->pCSSK->length);
	CA_DEBUG(0, "[%02x][%02x][%02x][%02x][%02x][%02x][%02x][%02x][%02x][%02x][%02x][%02x][%02x][%02x][%02x][%02x]\n", \
											pCSSKInfo->pCSSK->bytes[0], pCSSKInfo->pCSSK->bytes[1], \
											pCSSKInfo->pCSSK->bytes[2], pCSSKInfo->pCSSK->bytes[3], \
											pCSSKInfo->pCSSK->bytes[4], pCSSKInfo->pCSSK->bytes[5], \
											pCSSKInfo->pCSSK->bytes[6], pCSSKInfo->pCSSK->bytes[7], \
											pCSSKInfo->pCSSK->bytes[8], pCSSKInfo->pCSSK->bytes[9], \
											pCSSKInfo->pCSSK->bytes[10], pCSSKInfo->pCSSK->bytes[11], \
											pCSSKInfo->pCSSK->bytes[12], pCSSKInfo->pCSSK->bytes[13], \
											pCSSKInfo->pCSSK->bytes[14], pCSSKInfo->pCSSK->bytes[15]);
#endif

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);

	return ret;
}

Ird_status_t Spi_Wait_SetPVRSession_Key()
{
	Ird_status_t ret = IRD_NO_ERROR;
	int count = 0;

	CA_DEBUG(0, "[%s] step in\n", __FUNCTION__);

	while (count < PVR_SESSION_KEY_CHECK_LOOP)
	{

		CA_DEBUG(0, "[%s] to check if set PVR session key, times: %d\n", __FUNCTION__, count);

		if (b_set_pvr_session_key == 1)
		{
			break;
		}

		usleep(PVR_SESSION_KEY_CHECK_TIME * 1000);
		count ++;
	}

	if (count == PVR_SESSION_KEY_CHECK_LOOP)
	{
		ret = IRD_NOT_READY;
	}

	CA_DEBUG(0, "[%s] step out\n", __FUNCTION__);

	return ret;
}

uc_result UniversalClientSPI_Stream_Open(uc_connection_stream_type streamType,
								const uc_stream_open_params *pStreamOpenParams, uc_stream_handle *pStreamHandle)
{
	HAL_DMX_Channel *ch = AML_NULL;
	uint32_t index = 0;
	int dmx_dev = -1;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	pthread_mutex_lock(&mutex_lock);

	for (index = 0; index < HAL_N_ELEM(s_dmx_channels); index++)
	{
		ch = &s_dmx_channels[index];
		if (ch->state == HAL_DMX_CHANNEL_STATE_IDLE)
		{
			break;
		}
	}

	CA_DEBUG(0, "[%s]: process streamType: %d\n", __FUNCTION__, streamType);

	CA_DEBUG(0, "pServiceContext: %x\n", pStreamOpenParams->pServiceContext);
	CA_DEBUG(0, "protocol type: %d, pid: %x\n", pStreamOpenParams->caStream.protocolType, pStreamOpenParams->caStream.pid);

	ch->stream_type = streamType;
	ch->pid = pStreamOpenParams->caStream.pid;
	ch->state = HAL_DMX_CHANNEL_STATE_ALLOCATED;

	dmx_dev = ird_get_dmx_dev(pStreamOpenParams->pServiceContext);
	ch->dmx_dev = (dmx_dev != -1)?dmx_dev:DMX_DEVICE_NO;

	CA_DEBUG(0, "get and set demux device no: %d\n", ch->dmx_dev);

	*pStreamHandle = ch->id;

	CA_DEBUG(0, "[%s]: stream open success, dmx_dev: %d, streamHandle: %d\n", __FUNCTION__, ch->dmx_dev, *pStreamHandle);

	pthread_mutex_unlock(&mutex_lock);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Stream_Close(uc_stream_handle *pStreamHandle)
{
	HAL_DMX_Channel *ch = AML_NULL;
	HAL_DMX_Filter  *f = AML_NULL;
	uint32_t index = 0;
	uc_connection_stream_type streamType;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	CA_DEBUG(0, "[%s]: ready to close streamHandle: %d\n", __FUNCTION__, *pStreamHandle);

	pthread_mutex_lock(&mutex_lock);

	for (index = 0; index < HAL_N_ELEM(s_dmx_channels); index++)
	{
		ch = &s_dmx_channels[index];
		if (ch->id == *pStreamHandle)
		{
			break;
		}
	}

	f = ch->filters;
	while (f)
	{
		if (f->state == HAL_DMX_FILTER_STATE_CLOSED)
		{
			f->state = HAL_DMX_FILTER_STATE_IDLE;
		}
		f = f->next;
	}

	ch->state = HAL_DMX_CHANNEL_STATE_IDLE;

	streamType = (uc_connection_stream_type)ch->stream_type;
	if ((streamType == UC_CONNECTION_STREAM_TYPE_PVR_RECORD) || (streamType == UC_CONNECTION_STREAM_TYPE_PVR_PLAYBACK))
	{
		CA_DEBUG(0, "[%s]: set PVR session key flag to false\n", __FUNCTION__);
		b_set_pvr_session_key = 0;
	}

	pthread_mutex_unlock(&mutex_lock);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Stream_Start(uc_stream_handle streamHandle)
{
	HAL_DMX_Channel *ch = AML_NULL;
	HAL_DMX_Filter  *f = AML_NULL;
	uint32_t index = 0;
	int ret = -1;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	CA_DEBUG(0, "[%s]: ready to start streamHandle: %d\n", __FUNCTION__, streamHandle);

	pthread_mutex_lock(&mutex_lock);

	for (index = 0; index < HAL_N_ELEM(s_dmx_channels); index++)
	{
		ch = &s_dmx_channels[index];
		if (ch->id == streamHandle)
		{
			break;
		}
	}

	f = ch->filters;
	while (f)
	{
		CA_DEBUG(0, "[%s]: start filter pointer: 0x%x \n", __FUNCTION__, f);

		ret = am_dmx_start_filter(ch->dmx_dev, f->fd);
		CA_DEBUG(0, "[%s]: start filter filterHandle %d, ret = %d\n", __FUNCTION__, f->fd, ret);

		f->state = HAL_DMX_FILTER_STATE_ENABLED;
		f = f->next;
	}

	ch->state = HAL_DMX_CHANNEL_STATE_STARTED;

	pthread_mutex_unlock(&mutex_lock);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Stream_Stop(uc_stream_handle streamHandle)
{
	HAL_DMX_Channel *ch = AML_NULL;
	HAL_DMX_Filter	*f = AML_NULL;
	uint32_t index = 0;
	int ret = -1;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	CA_DEBUG(0, "[%s]: ready to stop streamHandle: 0x%d\n", __FUNCTION__, streamHandle);

	pthread_mutex_lock(&mutex_lock);

	for (index = 0; index < HAL_N_ELEM(s_dmx_channels); index++)
	{
		ch = &s_dmx_channels[index];
		if (ch->id == streamHandle)
		{
			break;
		}
	}

	f = ch->filters;
	while (f)
	{
		CA_DEBUG(0, "[%s]: stop filter pointer: 0x%x\n", __FUNCTION__, f);

		ret = am_dmx_stop_filter(ch->dmx_dev, f->fd);
		CA_DEBUG(0, "[%s]: stop filter filterHandle %d, ret = %d\n", __FUNCTION__, f->fd, ret);

		f = f->next;
	}

	ch->state = HAL_DMX_CHANNEL_STATE_CLOSED;

	pthread_mutex_unlock(&mutex_lock);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}


uc_result UniversalClientSPI_Stream_OpenFilter(uc_stream_handle streamHandle, uc_filter_handle *pFilterHandle)
{
	HAL_DMX_Channel *ch = AML_NULL;
	HAL_DMX_Filter  *f = AML_NULL;
	uint32_t index = 0;
	int result = 0;
	int fhandle = 0;
    int ret = -1;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	CA_DEBUG(0, "[%s]: ready to open filter for streamHandle: %d\n", __FUNCTION__, streamHandle);

	pthread_mutex_lock(&mutex_lock);

	for (index = 0; index < HAL_N_ELEM(s_dmx_channels); index++)
	{
		ch = &s_dmx_channels[index];
		if (ch->id == streamHandle)
		{
			break;
		}
	}

	for (index = 0; index < HAL_N_ELEM(s_dmx_filters); index ++)
	{
	    f = &s_dmx_filters[index];

	    if (f->state == HAL_DMX_FILTER_STATE_IDLE)
	{
			break;
	}
	}

	if (index < HAL_N_ELEM(s_dmx_filters))
	{
		f->next     = ch->filters;
		ch->filters = f;

		f->channel    = ch;
		f->fd         = -1;
		f->state      = HAL_DMX_FILTER_STATE_ALLOCATED;
		f->pid        = ch->pid;
		f->depth      = -1;
		f->has_filter = 0;
	}

#ifdef DUMP_DEBUG
	HAL_DMX_Filter *temp_f = ch->filters;

	CA_DEBUG(0, "----print all node:\n");
	while (temp_f)
	{
		CA_DEBUG(0, "pointer: 0x%x, id: %d, state: %d, fd: %d, pid: 0x%x, has_filter: %d, next: 0x%x\n", \
								temp_f, temp_f->id, temp_f->state, temp_f->fd, temp_f->pid, \
								temp_f->has_filter, temp_f->next);
		temp_f = temp_f->next;
	}
	CA_DEBUG(0, "----end\n");
#endif

	result = am_dmx_alloc_filter(ch->dmx_dev, &fhandle);
	if (result != 0)
	{
		CA_DEBUG(0, "[%s]: dmx allocate filter fail\n", __FUNCTION__);
		pthread_mutex_lock(&mutex_lock);
		return UC_ERROR_NULL_PARAM;
	}

	f->fd = fhandle;
	ret = am_dmx_set_callback(ch->dmx_dev, f->fd, process_section_callback, AML_NULL);
	ret = am_dmx_set_buffer_size(ch->dmx_dev, f->fd, f->channel->buffer_size);

	*pFilterHandle = f->id;

	CA_DEBUG(0, "[%s]: open filter success, filterHandle: %d\n", __FUNCTION__, *pFilterHandle);

	pthread_mutex_unlock(&mutex_lock);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Stream_SetFilter(uc_filter_handle filterHandle, const uc_filter *pFilterRules)
{
	HAL_DMX_Filter *f = AML_NULL;
	uint32_t index = 0, fidx = 0;
	uint32_t filter_depth = 0;
    int ret = -1;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	CA_DEBUG(0, "[%s]: ready to set filter for filterHandle: %d\n", __FUNCTION__, filterHandle);

	pthread_mutex_lock(&mutex_lock);

	for (index = 0; index < HAL_N_ELEM(s_dmx_filters); index ++)
	{
	    f = &s_dmx_filters[index];

	    if ((f->state == HAL_DMX_FILTER_STATE_ALLOCATED || f->state == HAL_DMX_FILTER_STATE_ENABLED)&& f->id == filterHandle)
	{
			break;
	}
	}

#ifdef DUMP_DEBUG
		CA_DEBUG(1,"match: (%d)\n", pFilterRules->filterDepth);
		for (int i = 0; i < pFilterRules->filterDepth; i++)
			CA_DEBUG(1,"[%d]0x%0x ", i, pFilterRules->match[i]);
		CA_DEBUG(1,"\n");

		CA_DEBUG(1,"mask: (%d)\n", pFilterRules->filterDepth);
		for (int i = 0; i < pFilterRules->filterDepth; i++)
			CA_DEBUG(1,"[%d]0x%0x ", i, pFilterRules->mask[i]);
		CA_DEBUG(1,"\n");

#if 0
		/* dump EMM filter parameter into file **/
		if (pFilterRules->match[0] != 0x81 && pFilterRules->match[0] != 0x80)
		{
			FILE *fpt;
			int i = 0;

			fpt = fopen("/data/filter_match.txt","a");

			fprintf(fpt, "fd: %d\n", f->fd);
			for (i = 0 ; i < pFilterRules->filterDepth; i++)
			{
				fprintf(fpt, "0x%02x ", pFilterRules->match[i]);
			}

			fprintf(fpt, "\n");

			for (i = 0 ; i < pFilterRules->filterDepth; i++)
			{
				fprintf(fpt, "0x%02x ", pFilterRules->mask[i]);
			}

			fprintf(fpt, "\n\n\n");
			fclose(fpt);
		}
#endif
#endif

	memset(&f->filter, 0, sizeof(dmx_filter_t));
	for (index = 0; index < pFilterRules->filterDepth; index++)
	{
		if ((index != 1) && (index != 2))
		{
			f->filter.filter[fidx] = pFilterRules->match[index];
			f->filter.mask[fidx] = pFilterRules->mask[index];
			fidx++ ;
		}
	}

    if (f->pid != INVALID_PID)
	{
		struct dmx_sct_filter_params params;
		memset(&params, 0, sizeof(params));
		params.pid    = f->pid;
		params.filter = f->filter;

		if (f->state == HAL_DMX_FILTER_STATE_ALLOCATED)
		{
			CA_DEBUG(1, "[%s]: set filter, fd:%d, pid: %x, buffer size:0x%x, state: %d\n", __FUNCTION__, f->fd, f->channel->pid, f->channel->buffer_size, f->channel->state);

			ret = am_dmx_set_sec_filter(f->channel->dmx_dev, f->fd, &params);
			if (f->channel->state == HAL_DMX_CHANNEL_STATE_STARTED)
			{
				ret |= am_dmx_start_filter(f->channel->dmx_dev, f->fd);
				f->state = HAL_DMX_FILTER_STATE_ENABLED;
			}

		    f->has_filter = 1;
			f->depth = fidx;
		}
		else if (f->state == HAL_DMX_FILTER_STATE_ENABLED)
		{
			CA_DEBUG(1, "[%s]: set filter, fd:%d, pid: %x\n", __FUNCTION__, f->fd, f->channel->pid);

			ret = am_dmx_stop_filter(f->channel->dmx_dev, f->fd);
			ret |= am_dmx_set_sec_filter(f->channel->dmx_dev, f->fd, &params);
			ret |= am_dmx_start_filter(f->channel->dmx_dev, f->fd);
		}

		CA_DEBUG(1, "DMX_SET_FILTER ret:%d, pid:%#x, fd:%d, depth len:%d\n", ret, f->pid, f->fd, f->depth);
    }
	else
	{
		CA_DEBUG(1, "DMX_SET_FILTER failed, pid:%#x\n", f->pid);
	}

#ifdef DUMP_DEBUG
	CA_DEBUG(1, "pointer: 0x%x, id: %d, state: %d, fd: %d, pid: 0x%x, has_filter: %d, next: 0x%x\n", \
							f, f->id, f->state, f->fd, f->pid, \
							f->has_filter, f->next);
#endif

	pthread_mutex_unlock(&mutex_lock);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Stream_CloseFilter(uc_stream_handle streamHandle, uc_filter_handle *pFilterHandle)
{
	HAL_DMX_Channel *ch = AML_NULL;
	HAL_DMX_Filter  *f = AML_NULL, *pre_f = AML_NULL, *del_f = AML_NULL;
    int ret = -1;

	uint32_t index = 0;
	int result = 0;
	int fhandle = 0;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	CA_DEBUG(0, "[%s]: ready to close filterHandle %d for streamHandle: %d\n", __FUNCTION__, *pFilterHandle, streamHandle);

	pthread_mutex_lock(&mutex_lock);

	for (index = 0; index < HAL_N_ELEM(s_dmx_channels); index++)
	{
		ch = &s_dmx_channels[index];
		if (ch->id == streamHandle)
		{
			CA_DEBUG(0, "found channel, filters: %x\n", ch->filters);
			break;
		}
	}

	f = ch->filters;
	while (f)
	{
		if (f->id == *pFilterHandle)
		{
			del_f = f;

			/* Header of the linked list*/
			if (pre_f == AML_NULL)
			{
				ch->filters = del_f->next;
			}
			else
			{
				pre_f->next = del_f->next;
			}
			break;
		}
		pre_f = f;
		f = f->next;
	}

#ifdef DUMP_DEBUG
	HAL_DMX_Filter *temp_f = ch->filters;

	CA_DEBUG(0, "----print all node:\n");
	while (temp_f)
	{
		CA_DEBUG(0, "pointer: 0x%x, id: %d, state: %d, fd: %d, pid: 0x%x, has_filter: %d, next: 0x%x\n", \
								temp_f, temp_f->id, temp_f->state, temp_f->fd, temp_f->pid, \
								temp_f->has_filter, temp_f->next);
		temp_f = temp_f->next;
	}
	CA_DEBUG(0, "----end\n");
#endif

	am_dmx_stop_filter(ch->dmx_dev, del_f->fd);
	ret = am_dmx_free_filter(ch->dmx_dev, del_f->fd);

	CA_DEBUG(0, "[%s]: close filter: %d, ret = %d\n", __FUNCTION__, del_f->fd, ret);

	del_f->fd = -1;
	del_f->channel = AML_NULL;
	del_f->next = AML_NULL;
	del_f->state = HAL_DMX_FILTER_STATE_IDLE;
	del_f->pid = INVALID_PID;
	del_f->depth = -1;
	del_f->has_filter = 0;

	pthread_mutex_unlock(&mutex_lock);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Stream_Connect( uc_stream_handle streamHandle,
									uc_connection_handle connectionHandle, uc_notify_callback notifyCallback)
{
	HAL_DMX_Channel *ch = AML_NULL;
	uint32_t index = 0;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	CA_DEBUG(0, "[%s]: ready to connect %d for streamHandle: %d\n", __FUNCTION__, connectionHandle, streamHandle);

	pthread_mutex_lock(&mutex_lock);

	for (index = 0; index < HAL_N_ELEM(s_dmx_channels); index++)
	{
		ch = &s_dmx_channels[index];
		if (ch->id == streamHandle)
		{
			break;
		}
	}

	ch->connect = connectionHandle;
	ch->connect_notify = (void *)notifyCallback;

	pthread_mutex_unlock(&mutex_lock);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Stream_Extended_Connect(uc_stream_handle streamHandle,
									uc_connection_handle connectionHandle, uc_notify_callback_extended notifyCallback)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Stream_Disconnect(uc_stream_handle streamHandle, uc_connection_handle connectionHandle)
{
	HAL_DMX_Channel *ch = AML_NULL;
	uint32_t index = 0;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	CA_DEBUG(0, "[%s]: ready to disconnect %d for streamHandle: %d\n", __FUNCTION__, connectionHandle, streamHandle);

	pthread_mutex_lock(&mutex_lock);

	for (index = 0; index < HAL_N_ELEM(s_dmx_channels); index++)
	{
		ch = &s_dmx_channels[index];
		if (ch->id == streamHandle)
		{
			break;
		}
	}

	ch->connect_notify = AML_NULL;

	pthread_mutex_unlock(&mutex_lock);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Stream_Send(uc_stream_handle streamHandle, const uc_stream_send_payload *pBytes)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Stream_AddComponent(uc_stream_handle streamHandle,
									const uc_elementary_component *pComponent)
{
	HAL_DMX_Channel *ch = AML_NULL;
	HAL_DESC_Slot	*desc = AML_NULL;
	uint32_t index = 0;
    int ret = -1;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	CA_DEBUG(0, "[%s]: add component for streamHandle: %d\n", __FUNCTION__, streamHandle);

	pthread_mutex_lock(&mutex_lock);

	for (index = 0; index < HAL_N_ELEM(s_dmx_channels); index++)
	{
		ch = &s_dmx_channels[index];
		if (ch->id == streamHandle)
		{
			break;
		}
	}

	for (index = 0; index < HAL_N_ELEM(s_desc_slots); index ++)
	{
	    desc = &s_desc_slots[index];

	    if (desc->state == HAL_DESC_STATE_IDLE)
	{
			break;
	}
	}

	if (index < HAL_N_ELEM(s_desc_slots))
	{
#if 0
		if (ch->descramblers == AML_NULL)
		{
			pipeline_mode_e mode = PIPELINE_MODE_LIVE;
			if (ch->dmx_dev != 0)
			{
				mode = PIPELINE_MODE_RECORD;
			}

			ret = pipeline_create(ch->dmx_dev, mode, &ch->pipe_id);
			CA_DEBUG(0, "[%s]: create pipeline for dmx_dev: %d, ret: %d, mode: %d, pipe_id: %d\n", __FUNCTION__, \
												ch->dmx_dev, ret, mode, ch->pipe_id);
		}
#endif

		desc->next     = ch->descramblers;
		ch->descramblers = desc;

		desc->channel    = ch;
		desc->fd         = -1;
		desc->state      = HAL_DESC_STATE_ALLOCATED;
		desc->pid        = pComponent->componentStream.pid;
	}

	pthread_mutex_unlock(&mutex_lock);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Stream_RemoveComponent(uc_stream_handle streamHandle,
									const uc_elementary_component *pComponent)
{
	HAL_DMX_Channel *ch = AML_NULL;
	HAL_DESC_Slot	*desc = AML_NULL, *pre_desc = AML_NULL, *del_desc = AML_NULL;
	uint32_t index = 0;
    int ret = -1;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	CA_DEBUG(0, "[%s]: remove component for streamHandle: %d\n", __FUNCTION__, streamHandle);

	pthread_mutex_lock(&mutex_lock);

	for (index = 0; index < HAL_N_ELEM(s_dmx_channels); index++)
	{
		ch = &s_dmx_channels[index];
		if (ch->id == streamHandle)
		{
			break;
		}
	}

	desc = ch->descramblers;
	while (desc)
	{
		if ((desc->state == HAL_DESC_STATE_ALLOCATED || desc->state == HAL_DESC_STATE_ENABLED)
				&& desc->pid == pComponent->componentStream.pid)
		{
			CA_DEBUG(0, "[%s]:found remove pid: %x\n", __FUNCTION__, desc->pid);
			del_desc = desc;

			/* Header of the linked list*/
			if (pre_desc == AML_NULL)
			{
				ch->descramblers = del_desc->next;
			}
			else
			{
				pre_desc->next = del_desc->next;
			}
			break;
		}
		pre_desc = desc;
		desc = desc->next;
	}

	if (del_desc->fd != -1)
	{
		ret = MSR_DscRemovePid(del_desc->fd, del_desc->pid);
		CA_DEBUG(0, "[%s]:remove pid: %x, ret = %d\n", __FUNCTION__, del_desc->pid, ret);

		ret = MSR_DscClose(desc->fd);
		CA_DEBUG(0, "[%s]:close desc, ret = %d\n", __FUNCTION__, ret);
	}

#if 0
	if (ch->descramblers == AML_NULL)
	{
		ret = pipeline_release(ch->pipe_id);
		CA_DEBUG(0, "[%s]: release pipeline, ret: %d, pipe_id: %d \n", __FUNCTION__, ret, ch->pipe_id);
		ch->pipe_id = -1;
	}
#endif

	del_desc->fd = -1;
	del_desc->channel = AML_NULL;
	del_desc->next = AML_NULL;
	del_desc->state = HAL_DESC_STATE_IDLE;
	del_desc->pid = INVALID_PID;

	pthread_mutex_unlock(&mutex_lock);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Stream_SetDescramblingKey(uc_stream_handle streamHandle,
									const uc_key_info *pKeyInfo, uc_uint32 keyVersion)
{
	uc_result result = UC_ERROR_SUCCESS;
	HAL_DMX_Channel *ch = AML_NULL;
	HAL_DESC_Slot	*desc = AML_NULL;
	uint32_t index = 0;
	int32_t ret = 0;
	char buf[64];
	char source[20];
	int32_t algo, nSlot;
	int32_t key_type;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	CA_DEBUG(0, "[%s]: streamHandle: %d, Algorithm: 0x%02x, KeyProtection: %d, KeyLen: %d, keyVersion: %d\n", __FUNCTION__, streamHandle, \
						pKeyInfo->descramblingKeyAlgorithm, pKeyInfo->descramblingKeyProtection, \
						pKeyInfo->pDescramblingKey->length, keyVersion);

	pthread_mutex_lock(&mutex_lock);

	for (index = 0; index < HAL_N_ELEM(s_dmx_channels); index++)
	{
		ch = &s_dmx_channels[index];
		if (ch->id == streamHandle)
		{
			break;
		}
	}

	switch (keyVersion)
	{
		case DSC_KEY_TYPE_EVEN:
		{
			key_type = 0;
			break;
		}

		case DSC_KEY_TYPE_ODD:
		{
			key_type = 1;
			break;
		}
	}

	desc = ch->descramblers;
	while (desc)
	{
		if (desc->state == HAL_DESC_STATE_ALLOCATED)
		{
			switch (pKeyInfo->descramblingKeyAlgorithm)
			{
				case UC_DK_ALGORITHM_DVB_CSA:
					algo = DSC_ALGORITHM_DVB_CSA;
					break;

				case UC_DK_ALGORITHM_AES_128_CBC:
				case UC_DK_ALGORITHM_IRDETO_AES_128_CBC:
					algo = DSC_ALGORITHM_AES_128_CBC;
					break;
			}

			ret = MSR_DscOpen(ch->dmx_dev, algo, &nSlot);
			if (ret == 0)
			{
				CA_DEBUG(0, "desc open success, nSlot = %d\n", nSlot);
			}
			else
			{
				CA_DEBUG(0, "desc open error, ret = %d\n", ret);
			}

			desc->fd = nSlot;
			ret = MSR_DscAddPid(desc->fd, desc->pid);
			if (ret == 0)
			{
				CA_DEBUG(0, "desc set pid(%x) success, nSlot: %d\n", desc->pid, nSlot);
			}
			else
			{
				CA_DEBUG(0, "desc set pid(%x) error, ret = %d\n", desc->pid, ret);
			}

			desc->state = HAL_DESC_STATE_ENABLED;
		}

		if (desc->state == HAL_DESC_STATE_ENABLED)
		{
			if (pKeyInfo ->descramblingKeyProtection == UC_DK_PROTECTION_CLEAR)
			{
				ret = MSR_DscSetKey(desc->fd, key_type, pKeyInfo->pDescramblingKey->bytes, pKeyInfo->pDescramblingKey->length);
				CA_DEBUG(0, "[%s]: descrambler set Key, ret = %d\n", __FUNCTION__, ret);
			}
			else if(pKeyInfo ->descramblingKeyProtection == UC_DK_PROTECTION_AES)
			{
				ret = MSR_DscSetIV(desc->fd, key_type, s_aes_cbc_iv, MAX_AES_IV_LEN);
				CA_DEBUG(0, "[%s]: descrambler AES protection set IV, ret = %d\n", __FUNCTION__, ret);

				ret |= MSR_DscSetCWSK(desc->fd, DSC_PROTECTION_AES, session_key, 16);
				CA_DEBUG(0, "[%s]: descrambler AES protection session Key, ret = %d\n", __FUNCTION__, ret);

				ret |= MSR_DscSetKey(desc->fd, key_type, pKeyInfo->pDescramblingKey->bytes, pKeyInfo->pDescramblingKey->length);
				CA_DEBUG(0, "[%s]: descrambler AES protection set Key, ret = %d\n", __FUNCTION__, ret);
			}
			else if(pKeyInfo ->descramblingKeyProtection == UC_DK_PROTECTION_AES_TRANSFORM)
			{
				ret = MSR_DscSetIV(desc->fd, key_type, s_aes_cbc_iv, MAX_AES_IV_LEN);
				CA_DEBUG(0, "[%s]: descrambler AES SCOT protection set IV, ret = %d\n", __FUNCTION__, ret);

				ret |= MSR_DscSetCWSK(desc->fd, DSC_PROTECTION_AES_SCOT, session_key, 16);
				CA_DEBUG(0, "[%s]: descrambler AES SCOT protection session Key, ret = %d\n", __FUNCTION__, ret);

				ret |= MSR_DscSetKey(desc->fd, key_type, pKeyInfo->pDescramblingKey->bytes, pKeyInfo->pDescramblingKey->length);
				CA_DEBUG(0, "[%s]: descrambler AES SCOT protection set Key, ret = %d\n", __FUNCTION__, ret);
			}
			else
			{
				CA_DEBUG(0, "[%s]: not support key protection: %d\n", __FUNCTION__, pKeyInfo ->descramblingKeyProtection);
			}

			if (ret != 0)
			{
				CA_DEBUG(0, "[%s]: descrambler set keys error\n", __FUNCTION__);
				result = UC_ERROR_NULL_PARAM;
			}
		}

		desc = desc->next;
	}

	pthread_mutex_unlock(&mutex_lock);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);

	return result;
}

uc_result UniversalClientSPI_Stream_CleanDescramblingKey(uc_stream_handle streamHandle)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_IFCP_LoadImage(uc_IFCP_image *pImage)
{
	ifcp_flexicore_data_t flexicore_data;
	uc_result result = UC_ERROR_SUCCESS;
	int32_t ret = 0;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	CA_DEBUG(0, "[%s]: activation message length: %d, ram iamge length: %d\n", __FUNCTION__, pImage->activationMessage.length, pImage->ramImage.length);

	flexicore_data.activation_message.p_data = pImage->activationMessage.bytes;
	flexicore_data.activation_message.data_len = pImage->activationMessage.length;
	flexicore_data.activation_message.size = 0;

	flexicore_data.flexicore_ram_image.p_data = pImage->ramImage.bytes;
	flexicore_data.flexicore_ram_image.data_len = pImage->ramImage.length;
	flexicore_data.flexicore_ram_image.size = 0;

	ret = IFCP_LoadImage(&flexicore_data);
	if (ret != 0)
	{
		CA_DEBUG(0, "[%s]: IFCP Image loading failed, ret=%d\n", __FUNCTION__, ret);
		result = UC_ERROR_NULL_PARAM;
	}

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return result;
}

uc_result UniversalClientSPI_IFCP_Communicate(uc_IFCP_input *pInput, uc_IFCP_output *pOutput)
{
	uc_result result = UC_ERROR_SUCCESS;
	uc_stream_handle streamHandle;
	HAL_DMX_Channel *ch = AML_NULL;
	HAL_DESC_Slot	*desc = AML_NULL;
	uint32_t index = 0;
	int32_t ret = 0;
	char buf[64];
	char source[20];
	int32_t algo, nSlot;
	int32_t key_type;
	k_buffer_t init_vector;
	ifcp_keydata_t key_data;
	ifcp_keydata_response_t key_data_response;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	CA_DEBUG(0, "[%s]: command type: %d, KLC header[%02x][%02x][%02x], ED_Ctrl: %x, ApplicationControlInfo: %x\n", __FUNCTION__, pInput->commandType, \
										pInput->pIFCPInfo->pKLCInfo->header[0], pInput->pIFCPInfo->pKLCInfo->header[1], pInput->pIFCPInfo->pKLCInfo->header[2], \
										pInput->pIFCPInfo->pKLCInfo->ED_Ctrl, pInput->pIFCPInfo->pApplicationControlInfo);

	switch (pInput->commandType)
	{
		case UC_IFCP_COMMAND_SET_DESCRAMBLING_KEY:
		case UC_IFCP_COMMAND_LOAD_TDC:
		{
			CA_DEBUG(0, "[%s]: streamHandle: %x, keyVersion: %d, descramblingKeyAlgorithm: 0x%02x\n", __FUNCTION__, \
											pInput->additionalInfo.forDescramblingKey.streamHandle, \
											pInput->additionalInfo.forDescramblingKey.keyVersion, \
											pInput->additionalInfo.forDescramblingKey.descramblingKeyAlgorithm);
			streamHandle = pInput->additionalInfo.forDescramblingKey.streamHandle;
			break;
		}

		case UC_IFCP_COMMAND_SET_PVR_SESSION_KEY:
		{
			CA_DEBUG(0, "[%s]: streamHandle: %x, algorithm: %d, keyIndex: 0x%x\n", __FUNCTION__, \
											pInput->additionalInfo.forPVRSessionKey.streamHandle, \
											pInput->additionalInfo.forPVRSessionKey.algorithm, \
											pInput->additionalInfo.forPVRSessionKey.keyIndex);
			streamHandle = pInput->additionalInfo.forPVRSessionKey.streamHandle;
			break;
		}
	}

	pthread_mutex_lock(&mutex_lock);

	for (index = 0; index < HAL_N_ELEM(s_dmx_channels); index++)
	{
		ch = &s_dmx_channels[index];
		if (ch->id == streamHandle)
		{
			break;
		}
	}

	if (pInput->commandType != UC_IFCP_COMMAND_SET_PVR_SESSION_KEY)
	{
		/** load Transformation data container (TDC) structure by IFCP command */
		if (pInput->commandType == UC_IFCP_COMMAND_LOAD_TDC)
		{
			CA_DEBUG(0, "[SCOT] begin to copy key data\n");
			copy_key_data(&key_data, &key_data_response, pInput, pOutput);
			ret = IFCP_LoadScotData(&key_data, &key_data_response);
			if (ret == 0)
			{
				CA_DEBUG(0, "[SCOT] kl_response_len = %d, buffer len = %d, size = %d\n", key_data_response.kl_response_len, key_data_response.kl_response.data_len, key_data_response.kl_response.size);
				CA_DEBUG(0, "[SCOT] app_control_response_len = %d, buffer len = %d, size = %d\n", key_data_response.app_control_response_len, key_data_response.app_control_response.data_len, key_data_response.app_control_response.size);
				pOutput->response.length = key_data_response.kl_response_len;
				pOutput->appResponse.length = key_data_response.app_control_response_len;
			}
			else
			{
				CA_DEBUG(0, "[%s] SCOT ifcp set descrambler key data failed, ret = %d\n", __FUNCTION__, ret);
				result = UC_ERROR_NULL_PARAM;
			}
		}

		switch (pInput->additionalInfo.forDescramblingKey.keyVersion)
		{
			case DSC_KEY_TYPE_EVEN:
			{
				key_type = 0;
				break;
			}

			case DSC_KEY_TYPE_ODD:
			{
				key_type = 1;
				break;
			}
		}

		desc = ch->descramblers;
		while (desc)
		{
			if (desc->state == HAL_DESC_STATE_ALLOCATED)
			{
				switch (pInput->additionalInfo.forDescramblingKey.descramblingKeyAlgorithm)
				{
					case UC_DK_ALGORITHM_DVB_CSA:
						algo = DSC_ALGORITHM_DVB_CSA;
						break;

					case UC_DK_ALGORITHM_AES_128_CBC:
					case UC_DK_ALGORITHM_IRDETO_AES_128_CBC:
						algo = DSC_ALGORITHM_AES_128_CBC;
						break;
				}

				ret = MSR_DscOpen(ch->dmx_dev, algo, &nSlot);
				if (ret == 0)
				{
					CA_DEBUG(0, "desc open success, nSlot = %d\n", nSlot);
				}
				else
				{
					CA_DEBUG(0, "desc open error, ret = %d\n", ret);
				}

				desc->fd = nSlot;
				ret = MSR_DscAddPid(desc->fd, desc->pid);
				if (ret == 0)
				{
					CA_DEBUG(0, "desc set pid(%x) success, nSlot: %d\n", desc->pid, nSlot);
				}
				else
				{
					CA_DEBUG(0, "desc set pid(%x) error, ret = %d\n", desc->pid, ret);
				}

				desc->state = HAL_DESC_STATE_ENABLED;
			}

			if (desc->state == HAL_DESC_STATE_ENABLED)
			{
				memset(&init_vector, 0x00, sizeof(k_buffer_t));
				init_vector.p_data = s_aes_cbc_iv;
				init_vector.data_len = MAX_AES_IV_LEN;

				CA_DEBUG(0, "[non-SCOT] begin to copy key data\n");
				copy_key_data(&key_data, &key_data_response, pInput, pOutput);
				ret = IFCP_SetDescramblingKeyData(desc->fd, key_type, &init_vector, &key_data, &key_data_response);
				if (ret == 0)
				{
					CA_DEBUG(0, "[non-SCOT] kl_response_len = %d, buffer len = %d, size = %d\n", key_data_response.kl_response_len, key_data_response.kl_response.data_len, key_data_response.kl_response.size);
					CA_DEBUG(0, "[non-SCOT] app_control_response_len = %d, buffer len = %d, size = %d\n", key_data_response.app_control_response_len, key_data_response.app_control_response.data_len, key_data_response.app_control_response.size);
					pOutput->response.length = key_data_response.kl_response_len;
					pOutput->appResponse.length = key_data_response.app_control_response_len;
				}
				else
				{
					CA_DEBUG(0, "[%s] ifcp set descrambler key data failed, ret = %d\n", __FUNCTION__, ret);
					result = UC_ERROR_NULL_PARAM;
				}
			}

			desc = desc->next;
		}
	}
	else
	{
		pvr_crypto_algo_t algo;

		CA_DEBUG(0, "[secure PVR] begin to copy key data\n");
		copy_key_data(&key_data, &key_data_response, pInput, pOutput);

		if (pInput->additionalInfo.forPVRSessionKey.algorithm == UC_DK_ALGORITHM_AES_128_CBC)
		{
			algo = PVR_CRYPTO_ALGO_AES;
			ret = IFCP_SetPVRSessionKeyData(0, pInput->additionalInfo.forPVRSessionKey.keyIndex, algo, &key_data, &key_data_response);
			if (ret == 0)
			{
				CA_DEBUG(0, "[secure PVR] kl_response_len = %d, buffer len = %d, size = %d\n", key_data_response.kl_response_len, key_data_response.kl_response.data_len, key_data_response.kl_response.size);
				CA_DEBUG(0, "[secure PVR] app_control_response_len = %d, buffer len = %d, size = %d\n", key_data_response.app_control_response_len, key_data_response.app_control_response.data_len, key_data_response.app_control_response.size);

				pOutput->response.length = key_data_response.kl_response_len;
				pOutput->appResponse.length = key_data_response.app_control_response_len;

				b_set_pvr_session_key = 1;
			}
			else
			{
				CA_DEBUG(0, "[%s] ifcp set PVR session key failed, ret = %d\n", __FUNCTION__, ret);
				result = UC_ERROR_NULL_PARAM;
			}
		}
		else
		{
			CA_DEBUG(0, "[%s] not support algorithm: %d\n", __FUNCTION__, pInput->additionalInfo.forPVRSessionKey.algorithm);
		}
	}

	pthread_mutex_unlock(&mutex_lock);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return result;
}

uc_result UniversalClientSPI_SCOT_LoadTransformationData(const uc_buffer_st *pEncryptedTask, uc_uint32 tdcCount, uc_tdc_data_for_spi *pTdcData)
{
	k_buffer_t task;
	scot_tdc_list_t scot_data;
	uc_result result = UC_ERROR_SUCCESS;
	int index = 0;
	int32_t ret = 0;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	CA_DEBUG(0, "pEncryptedTask len = %d, tdcCount = %d\n", pEncryptedTask->length, tdcCount);
	task.p_data = pEncryptedTask->bytes;
	task.data_len = pEncryptedTask->length;

	scot_data.nb_elements = tdcCount;
	scot_data.p_tdc_list = malloc (sizeof(k_buffer_t) * tdcCount);
	for (index = 0; index < tdcCount; index ++)
	{
		scot_data.p_tdc_list[index].p_data = pTdcData[index].tdc;
		scot_data.p_tdc_list[index].data_len = pTdcData[index].length;
	}

	/** now open desc, always return dsc_id = 0 */
	ret = MSR_DscLoadScotTD(0, &task, scot_data);
	if (ret != 0)
	{
		CA_DEBUG(0, "[%s]: desc load scot TD failed, ret = %d\n", __FUNCTION__, ret);
		result = UC_ERROR_NULL_PARAM;
	}

	free(scot_data.p_tdc_list);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

