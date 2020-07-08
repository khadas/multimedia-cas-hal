#ifndef CA_DEBUG_LEVEL
#define CA_DEBUG_LEVEL 2
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/un.h>

#include "cJSON.h"

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
#include "am_cas_internal.h"
#include "caclientapi.h"
#include "ird_cas.h"
#include "ird_cas_internal.h"

typedef void (*app_callback_fun)(char *json);

#define MYEMMSERVICECONTEXT  (void *)0x00010001
#define MYEMMMESSAGEPROCDATA (void *)0x00020001
#define MYECMSERVICECONTEXT  (void *)0x00010002
#define MYECMMESSAGEPROCDATA (void *)0x00020002

#define MAX_JSON_LENGTH (1024)

#define CAS_SYSTEM "Irdeto"

#define MULTIPLE_PLAY_NUM (1)

typedef struct service_handle
{
    int active;
	IRD_SERVICE_TYPE type;
	uc_service_handle serviceHandle;
} service_handle_st;

static pthread_mutex_t _monitor_lock = PTHREAD_MUTEX_INITIALIZER;

static service_handle_st g_EmmServiceHandle;
static service_handle_st g_EcmServiceHandle[MULTIPLE_PLAY_NUM];

static char SecureCoreStatus[MAX_SECURECORE_STATUS_SIZE] = {0};
static char SecureCoreDownload[MAX_SECURECORE_STATUS_SIZE] = {0};
static char IFCPImageStatus[MAX_SECURECORE_STATUS_SIZE] = {0};
static char IFCPImageDownload[MAX_SECURECORE_STATUS_SIZE] = {0};

static app_callback_fun app_callback = AML_NULL;
static finger_print_st s_finger_print;
static int b_caclient_init_finished = 0;

static service_monitor_st *p_monitor_head = AML_NULL;


#if 1
void _test_thread()
{
	service_monitor_list_st stMonitorList;
	int index = 0;

	AM_APP_ConfigServiceMonitor(g_EcmServiceHandle[0].serviceHandle, 1);

	sleep(2);

	while (1)
	{
		AM_APP_GetServiceMonitorList(&stMonitorList);

		CA_DEBUG(0, "[%s]: get new monitor count: %d\n", __FUNCTION__, stMonitorList.monitorCount);
		for (index = 0; index < stMonitorList.monitorCount; index++)
		{
			CA_DEBUG(0, "[%s]: new monitor string: \"%s\"\n", __FUNCTION__, stMonitorList.monitorStr[index]);

#if 0
			FILE *fpt;

			fpt = fopen("/data/vendor/irdeto/monitor.txt","a");
			fprintf(fpt, "%s\n", stMonitorList.monitorStr[index]);
			fclose(fpt);
#endif
		}

		CA_DEBUG(0, "[%s]: print end\n", __FUNCTION__);

		AM_APP_FreeServiceMonitorList(stMonitorList);

		sleep(5);
	}
}

void _satrt_test_thread()
{
	DKI_tid_t pthread_id;

	if (pthread_create(&pthread_id, NULL,
				  (void *(* _Nonnull)(void *))_test_thread, 0) != 0)
	{
		CA_DEBUG(0, "[%s]: pthread_create error\n", __FUNCTION__);
		return;
	}
}
#endif

static void _free_memory_list(int num, char **memoryList)
{
	for (int index = 0; index < num; index++)
	{
		if (memoryList[index] != AML_NULL)
		{
			free(memoryList[index]);
			memoryList[index] = AML_NULL;
		}
	}

	free(memoryList);
	memoryList = AML_NULL;
}

static void _UTCToYMD(uc_sint32 utcDate, uc_sint32 *pYear, uc_sint32 *pMonth, uc_sint32 *pDay)
{
    uc_sint32 y = 0;
    uc_sint32 m = 0;
    uc_sint32 d = 0;
    uc_sint32 k = 0;
    utcDate +=  745518;/*745518: UTC: from 1900.1.1 to 2000.01.01*/
    y =  (uc_sint32) ((utcDate  - 15078.2) / 365.25);
    m =  (uc_sint32) ((utcDate - 14956.1 - (uc_sint32)(y * 365.25) ) / 30.6001);
    d =  (uc_sint32) (utcDate - 14956 - (uc_sint32)(y * 365.25) - (uc_sint32)(m * 30.6001));
    k =  (m == 14 || m == 15) ? 1 : 0;
    y = y + k;
    m = m - 1 - k*12;
    *pYear = y;
    *pMonth = m;
    *pDay = d;
}

static void _struct_to_json(App_Msg_Type msg_type, void *p_data_structure, char *p_out_json)
{
	char *p_json = AML_NULL;

	CA_DEBUG(0, "process msg type: %d\n", msg_type);

	switch (msg_type)
	{
		case APP_ERROR_BANNER:
		{
			errorcode_text_st *p_errorcode_text = (errorcode_text_st *)p_data_structure;
			cJSON *root = cJSON_CreateObject();

			cJSON_AddItemToObject(root, "cas_system", cJSON_CreateString(CAS_SYSTEM));
			cJSON_AddItemToObject(root, "msg_type", cJSON_CreateNumber(msg_type));
			cJSON_AddItemToObject(root, "index", cJSON_CreateNumber(p_errorcode_text->index));
			cJSON_AddItemToObject(root, "content", cJSON_CreateString(p_errorcode_text->screen_text));

			p_json = cJSON_Print(root);
			memcpy(p_out_json, p_json, strlen(p_json));

			cJSON_Delete(root);
			break;
		}

		case APP_MESSAGE_TEXT:
		{
			message_text_st *p_msg_text = (message_text_st *)p_data_structure;
			cJSON *root = cJSON_CreateObject();

			cJSON_AddItemToObject(root, "cas_system", cJSON_CreateString(CAS_SYSTEM));
			cJSON_AddItemToObject(root, "msg_type", cJSON_CreateNumber(msg_type));
			cJSON_AddItemToObject(root, "force", cJSON_CreateBool(p_msg_text->bForce));
			cJSON_AddItemToObject(root, "content", cJSON_CreateString(p_msg_text->content));

			p_json = cJSON_Print(root);
			memcpy(p_out_json, p_json, strlen(p_json));

			cJSON_Delete(root);
			break;
		}

		case APP_ATTRIBUTE_DISPLAY:
		{
			attribute_display_st *p_msg_attribute = (attribute_display_st *)p_data_structure;
			cJSON *root = cJSON_CreateObject();

			cJSON_AddItemToObject(root, "cas_system", cJSON_CreateString(CAS_SYSTEM));
			cJSON_AddItemToObject(root, "msg_type", cJSON_CreateNumber(msg_type));
			cJSON_AddItemToObject(root, "force", cJSON_CreateBool(p_msg_attribute->bForce));
			cJSON_AddItemToObject(root, "flash", cJSON_CreateBool(p_msg_attribute->bFlash));
			cJSON_AddItemToObject(root, "banner", cJSON_CreateBool(p_msg_attribute->bBanner));
			cJSON_AddItemToObject(root, "duration", cJSON_CreateNumber(p_msg_attribute->duration));
			cJSON_AddItemToObject(root, "coverage_percent", cJSON_CreateNumber(p_msg_attribute->coverage_percent));
			cJSON_AddItemToObject(root, "content", cJSON_CreateString(p_msg_attribute->content));

			p_json = cJSON_Print(root);
			memcpy(p_out_json, p_json, strlen(p_json));

			cJSON_Delete(root);
			break;
		}

		case APP_FINGER_PRINT:
		{
			finger_print_st *p_finger_print = (finger_print_st *)p_data_structure;
			cJSON *root = cJSON_CreateObject();

			cJSON_AddItemToObject(root, "cas_system", cJSON_CreateString(CAS_SYSTEM));
			cJSON_AddItemToObject(root, "msg_type", cJSON_CreateNumber(msg_type));
			cJSON_AddItemToObject(root, "flash", cJSON_CreateBool(p_finger_print->bFlash));
			cJSON_AddItemToObject(root, "duration", cJSON_CreateNumber(p_finger_print->duration));
			cJSON_AddItemToObject(root, "coverage_percent", cJSON_CreateNumber(p_finger_print->coverage_percent));
			cJSON_AddItemToObject(root, "location_x", cJSON_CreateNumber(p_finger_print->location_x));
			cJSON_AddItemToObject(root, "location_y", cJSON_CreateNumber(p_finger_print->location_y));
			cJSON_AddItemToObject(root, "bg_transparency", cJSON_CreateNumber(p_finger_print->bg_transparency));
			cJSON_AddItemToObject(root, "bg_colour", cJSON_CreateNumber(p_finger_print->bg_colour));
			cJSON_AddItemToObject(root, "font_transparency", cJSON_CreateNumber(p_finger_print->font_transparency));
			cJSON_AddItemToObject(root, "font_colour", cJSON_CreateNumber(p_finger_print->font_colour));
			cJSON_AddItemToObject(root, "font_type", cJSON_CreateNumber(p_finger_print->font_type));
			cJSON_AddItemToObject(root, "content", cJSON_CreateString(p_finger_print->content));

			p_json = cJSON_Print(root);
			memcpy(p_out_json, p_json, strlen(p_json));

			cJSON_Delete(root);
			break;
		}
	}

#if 0
	FILE *fpt;
	fpt = fopen("/data/vendor/irdeto/notify.txt", "a");
	fprintf(fpt, "%s\n", p_json);
	fclose(fpt);
#endif

	if (p_json != AML_NULL)
	{
		free(p_json);
	}
}

char* _replace_sub_str(const char* str, const char* srcSubStr, const char* dstSubStr, char* out)
{
	char *p;
	char *_out = out;
	const char *_str = str;
	const char *_src = srcSubStr;
	const char *_dst = dstSubStr;
	int src_size = strlen(_src);
	int dst_size = strlen(_dst);
	int len = 0;

	do
	{
		p = strstr(_str, _src);
		if (p == 0)
		{
			strcpy(_out, _str);
			return out;
		}

		len = p - _str;
		memcpy(_out, _str, len);
		memcpy(_out + len, _dst, dst_size);
		_str = p + src_size;
		_out = _out + len + dst_size;

	} while(p);

	return out;
}

static void _notify_msg_to_app(char *p_json)
{
	uint8_t tmep_buffer[MAX_JSON_LENGTH] = {0};

	CA_DEBUG(0, "output json string: \'%s\'\n", p_json);

	if (app_callback == AML_NULL)
	{
		CA_DEBUG(0, "app_callback is null\n");
		return;
	}

	memset(tmep_buffer, 0x00, sizeof(tmep_buffer));
	_replace_sub_str(p_json, "\n", " ", tmep_buffer);

	CA_DEBUG(0, "convert output json string: \'%s\'\n", tmep_buffer);
	app_callback(tmep_buffer);
}


static void _append_monitor_to_list(char *p_monitor_in)
{
	service_monitor_st *p_new_monitor = AML_NULL;
	service_monitor_st *p_current_monitor = AML_NULL;

	CA_DEBUG(0, "[%s] step in, append new monitor to list.\n", __FUNCTION__);


	pthread_mutex_lock(&_monitor_lock);

	p_new_monitor = malloc(sizeof(service_monitor_st));
	if (p_new_monitor == AML_NULL)
	{
		CA_DEBUG(0, "[%s] p_new_monitor malloc memory failed\n", __FUNCTION__);
		pthread_mutex_unlock(&_monitor_lock);
		return;
	}

	memset(p_new_monitor, 0x00, sizeof(service_monitor_st));
	p_new_monitor->next = AML_NULL;
	// add 1 byte to fill the end of string '\0'
	p_new_monitor->monitorStr = malloc(strlen(p_monitor_in) + 1);
	if (p_new_monitor->monitorStr == AML_NULL)
	{
		CA_DEBUG(0, "[%s] p_new_monitor->monitorStr malloc memory failed\n", __FUNCTION__);
		free(p_new_monitor);
		pthread_mutex_unlock(&_monitor_lock);
		return;
	}

	CA_DEBUG(0, "[%s] p_new_monitor: %x, p_new_monitor->monitorStr: %x\n", __FUNCTION__, p_new_monitor, p_new_monitor->monitorStr);
	memset(p_new_monitor->monitorStr, 0x00, strlen(p_monitor_in) + 1);
	memcpy(p_new_monitor->monitorStr, p_monitor_in, strlen(p_monitor_in));

	if (p_monitor_head == AML_NULL)
	{
		p_monitor_head = p_new_monitor;
	}
	else
	{
		p_current_monitor = p_monitor_head;
		CA_DEBUG(0, "[%s] p_current_monitor: %x, p_current_monitor->next: %x\n", __FUNCTION__, p_current_monitor, p_current_monitor->next);

		while (p_current_monitor->next != AML_NULL)
		{
			p_current_monitor = p_current_monitor->next;
		}

		p_current_monitor->next = p_new_monitor;
	}

	pthread_mutex_unlock(&_monitor_lock);

	return;
}

static void _clear_monitor_list()
{
	service_monitor_st *p_del_monitor = AML_NULL;

	pthread_mutex_lock(&_monitor_lock);

	while (p_monitor_head != AML_NULL)
	{
		p_del_monitor = p_monitor_head;
		p_monitor_head = p_monitor_head->next;

		CA_DEBUG(0, "[%s] p_del_monitor: %x, p_del_monitor->monitorStr: %x\n", __FUNCTION__, p_del_monitor, p_del_monitor->monitorStr);

		free(p_del_monitor->monitorStr);
		free(p_del_monitor);
	}

	pthread_mutex_unlock(&_monitor_lock);
}

static void MyGlobalMessageProc(uc_global_message_type message,  void* lpVoid)
{
	CA_DEBUG(0, "Global message type: 0x%x\n", message);

    switch (message)
    {
        case UC_GLOBAL_DEBUG:
        {
            uc_char *pText = (uc_char *)lpVoid;
            CA_DEBUG(0, "Debug output: %s\n", pText);
            break;
        }

		case UC_GLOBAL_EXTENDED_RAW_IRD_MESSAGE:
        {
            uc_raw_ird_msg *p_raw_ird_msg = (uc_raw_ird_msg *)lpVoid;
			uint8_t destination_ID = 0;
			uint16_t payload_length = 0;
			uint8_t *p_pay_load = AML_NULL;
			uint8_t ird_offset = 0;
			char json_buffer[MAX_JSON_LENGTH] = {0};

			CA_DEBUG(0, "p_raw_ird_msg length = %d\n", p_raw_ird_msg->length);
			if ((p_raw_ird_msg->rawIrdMsg != AML_NULL) && (p_raw_ird_msg->length != 0))
			{
				destination_ID = (p_raw_ird_msg->rawIrdMsg[ird_offset] >> 4) & 0x0F;
				payload_length = ((p_raw_ird_msg->rawIrdMsg[ird_offset] << 8) | p_raw_ird_msg->rawIrdMsg[ird_offset+1]) & 0x0FFF;
				CA_DEBUG(0, "destination_ID: %d, message_length: %d\n", destination_ID, payload_length);

				ird_offset += 2;
				p_pay_load = &(p_raw_ird_msg->rawIrdMsg[ird_offset]);
				switch (destination_ID)
				{
					/* Text messages */
					case 0x00:
					{
						uint8_t text_message_type = 0;
						uint8_t message_class = 0;
						uint8_t flush_buffer = 0;
						uint8_t club_message = 0;
						uint8_t year = 0, month = 0, day = 0, hour = 0, minute = 0;
						uint8_t offset = 0;
						mail_type_t type;
						mail_priority_t priority;

						uint8_t *message_bytes = AML_NULL;
						uint8_t message_length = 0;

						message_text_st s_message_text;

						memset(&s_message_text, 0x00, sizeof(message_text_st));
						CA_DEBUG(0, "Text messages, type: %x, structure: %x\n", p_pay_load[offset], p_pay_load[offset+1]);

						text_message_type = p_pay_load[offset] >> 4;
						offset += 1;

						/**
							0x00 Text – Mailbox
							0x01 Text – Announcement  */
						if ((text_message_type == 0x00) || (text_message_type == 0x01))
						{
							message_class = p_pay_load[offset] >> 5;
							flush_buffer = (p_pay_load[offset] >> 4) & 0x01;
							club_message = (p_pay_load[offset] >> 2) & 0x01;

							offset += 1;
							/* Normal */
							if (message_class == 0x00)
							{
								priority = MAIL_PRIORITY_NORMAL;
								CA_DEBUG(0, "normal message \n");
							}
							/* Timed (automatic erase after date/time) */
							else if (message_class == 0x01)
							{
								year = (p_pay_load[offset] >> 1) & 0xFE;
								month = ((p_pay_load[offset] & 0x01) << 3) || ((p_pay_load[offset+1] >> 5) & 0x07);
								day = p_pay_load[offset+1] & 0x1F;
								hour = p_pay_load[offset+2] >> 3;
								minute = p_pay_load[offset+2] & 0x07;

								CA_DEBUG(0, "message class, year: %d, month: %d, day: %d, hour: %d, hour: %d\n", \
															year, month, day, hour, minute);
								offset += 3;
							}
							/* Forced Display */
							else if (message_class == 0x02)
							{
								CA_DEBUG(0, "Forced Display \n");
								s_message_text.bForce = 1;
								priority = MAIL_PRIORITY_FORCED;
							}

							if (club_message == 1)
							{
								offset += 2;
							}

							message_length = p_pay_load[offset];
							message_bytes = &p_pay_load[offset+1];

							memcpy(s_message_text.content, message_bytes, message_length);

							// save mail
							type = (text_message_type == 0x00)?MAIL_TYPE_MAILBOX:MAIL_TYPE_ANNOUNCEMENT;

							if (IRD_NO_ERROR != ird_mail_save(type, priority, message_bytes, message_length))
							{
								CA_DEBUG(0, "save mail failed, type: %d, priority: %d\n", type, priority);
							}

							CA_DEBUG(0, "show message: %s\n", s_message_text.content);

							memset(json_buffer, 0x00, sizeof(json_buffer));
							_struct_to_json(APP_MESSAGE_TEXT, (void *)&s_message_text, json_buffer);
							_notify_msg_to_app(json_buffer);
						}
					}
					break;

					/* Decoder control */
					case 0x01:
					{
					}
					break;

					/* Attributed Display */
					case 0x04:
					{
						uint8_t message_type = 0;
						uint16_t duration = 0;
						uint8_t display_method = 0;
						uint8_t fp_type = 0;
						uint8_t offset = 0;
						uint8_t text_len = 0;
						uint8_t *text_bytes = AML_NULL;
						uint8_t coverage = 0;

						message_type = p_pay_load[offset];
						offset += 1;
						duration = (p_pay_load[offset] << 8) | p_pay_load[offset+1];
						offset += 2;
						display_method = p_pay_load[offset];
						offset += 1;
						fp_type  = p_pay_load[offset] >> 7;
						text_len = ((p_pay_load[offset] << 8) | p_pay_load[offset+1]) & 0x0FFF;
						offset += 2;
						text_bytes = &p_pay_load[offset];

						CA_DEBUG(0, "message_type: %d, duration: %d, display_method: %x, fp_type: %d, text_len: %d\n", \
									message_type, duration, display_method, fp_type, text_len);
						/* Normal */
						if (message_type == 0x00)
						{
							attribute_display_st s_attribute_display;
							memset(&s_attribute_display, 0x00, sizeof(attribute_display_st));

							s_attribute_display.bForce = 0;
							memcpy(s_attribute_display.content, text_bytes, text_len);

							// save mail
							if (IRD_NO_ERROR != ird_mail_save(MAIL_TYPE_ATTRIBUTE, MAIL_PRIORITY_NORMAL, text_bytes, text_len))
							{
								CA_DEBUG(0, "save mail failed, type: %d, priority: %d\n", MAIL_TYPE_ATTRIBUTE, MAIL_PRIORITY_NORMAL);
							}

							CA_DEBUG(0, "forced text notify\n");
							CA_DEBUG(0, "show message: %s\n", s_attribute_display.content);

							memset(json_buffer, 0x00, sizeof(json_buffer));
							_struct_to_json(APP_ATTRIBUTE_DISPLAY, (void *)&s_attribute_display, json_buffer);
							_notify_msg_to_app(json_buffer);
						}
						/* Forced Text */
						else if (message_type == 0x01)
						{
							attribute_display_st s_attribute_display;
							memset(&s_attribute_display, 0x00, sizeof(attribute_display_st));

							s_attribute_display.duration = duration;
							s_attribute_display.bForce = 1;
							/* Flashing */
							if ((display_method & 0x01) == 0)
							{
								s_attribute_display.bFlash = 1;
							}
							/* Banner */
							if (((display_method >> 1) & 0x01) == 1)
							{
								s_attribute_display.bBanner = 1;
							}

							/* Coverage-Code */
							coverage = ((display_method >> 2) & 0x3F);
							if (coverage < 63)
							{
								s_attribute_display.coverage_percent = (float)coverage/63 * 99;
							}
							else
							{
								s_attribute_display.coverage_percent = 100;
							}

							memcpy(s_attribute_display.content, text_bytes, text_len);

							// save mail
							if (IRD_NO_ERROR != ird_mail_save(MAIL_TYPE_ATTRIBUTE, MAIL_PRIORITY_FORCED, text_bytes, text_len))
							{
								CA_DEBUG(0, "save mail failed, type: %d, priority: %d\n", MAIL_TYPE_ATTRIBUTE, MAIL_PRIORITY_FORCED);
							}

							CA_DEBUG(0, "forced text notify, bFlash: %d, bBanner: %d, coverage_percent:%d\n", \
										s_attribute_display.bFlash, s_attribute_display.bBanner, s_attribute_display.coverage_percent);
							CA_DEBUG(0, "show message: %s\n", s_attribute_display.content);

							memset(json_buffer, 0x00, sizeof(json_buffer));
							_struct_to_json(APP_ATTRIBUTE_DISPLAY, (void *)&s_attribute_display, json_buffer);
							_notify_msg_to_app(json_buffer);
						}
						/* Fingerprint */
						else if (message_type == 0x02)
						{
							if (fp_type == 1)
							{
								/* not support covert fingerprinting */
								break;
							}

							s_finger_print.duration = duration;

							/* Flashing */
							if ((display_method & 0x01) == 0)
							{
								s_finger_print.bFlash = 1;
							}
							/* Coverage-Code */
							coverage = ((display_method >> 2) & 0x3F);
							if (coverage < 63)
							{
								s_finger_print.coverage_percent = (float)coverage/63 * 99;
							}
							else
							{
								s_finger_print.coverage_percent = 100;
							}

							memcpy(s_finger_print.content, text_bytes, text_len);

							CA_DEBUG(0, "finger print notify, bFlash: %d, coverage_percent:%d\n", \
										s_finger_print.bFlash, s_finger_print.coverage_percent);
							CA_DEBUG(0, "show message: %s\n", s_finger_print.content);

							memset(json_buffer, 0x00, sizeof(json_buffer));
							_struct_to_json(APP_FINGER_PRINT, (void *)&s_finger_print, json_buffer);
							_notify_msg_to_app(json_buffer);
						}
						/* Fingerprinting options */
						else if (message_type == 0x03)
						{
							uint8_t TLV_tag = 0;
							uint8_t TLV_len = 0;
							uint8_t *TLV_bytes = AML_NULL;

							if (fp_type == 1)
							{
								/* not support covert fingerprinting */
								break;
							}

							memset(&s_finger_print, 0x00, sizeof(finger_print_st));
							if (text_len > 0)
							{
								TLV_tag = text_bytes[0];
								TLV_len = text_bytes[1];

								CA_DEBUG(0, "Fingerprinting_Options_TLV, tag :%d, length :%d\n", TLV_tag, TLV_len);
								if ((TLV_tag == 0x00) && (TLV_len > 0))
								{
									TLV_bytes = &text_bytes[2];
									s_finger_print.location_x = TLV_bytes[0];
									s_finger_print.location_y = TLV_bytes[1];
									s_finger_print.bg_transparency = TLV_bytes[2];
									s_finger_print.bg_colour = TLV_bytes[3] << 16 | TLV_bytes[4] << 8 | TLV_bytes[5];
									s_finger_print.font_transparency = TLV_bytes[6];
									s_finger_print.font_colour = TLV_bytes[7] << 16 | TLV_bytes[8] << 8 | TLV_bytes[9];
									s_finger_print.font_type = TLV_bytes[10];
								}
							}
							else
							{
								/* default finger printing options*/
								s_finger_print.location_x = 300;
								s_finger_print.location_y = 150;
								s_finger_print.bg_transparency = 0x00;
								s_finger_print.bg_colour = 0xFFFF00;
								s_finger_print.font_transparency = 0xFF;
								s_finger_print.font_colour = 0x0000FF;
								s_finger_print.font_type = 0;
							}

							CA_DEBUG(0, "EOF Options Variable, location_x: 0x%x, location_y: 0x%x, bg_transparency: 0x%x, bg_colour: : 0x%06x, font_transparency: 0x%x, font_colour: : 0x%06x, font_type : 0x%x\n", \
									s_finger_print.location_x, s_finger_print.location_y, s_finger_print.bg_transparency, s_finger_print.bg_colour, \
									s_finger_print.font_transparency, s_finger_print.font_colour, s_finger_print.font_type);
						}
					}
					break;
				}
			}
            break;
        }

		case UC_GLOBAL_NOTIFY_FLEXIFLASH_MESSAGE:
        {
			uc_flexiflash_msg *flexiflash_msg = (uc_flexiflash_msg *)lpVoid;

			CA_DEBUG(0, "Secure Core Status: %s\n", flexiflash_msg->secureCoreListStatus);
			CA_DEBUG(0, "Packages Download Progress: %s\n", flexiflash_msg->packagesDownloadProgressInfo);

			snprintf(SecureCoreStatus, MAX_SECURECORE_STATUS_SIZE, "%s", flexiflash_msg->secureCoreListStatus);
			snprintf(SecureCoreDownload, MAX_SECURECORE_STATUS_SIZE, "%s", flexiflash_msg->packagesDownloadProgressInfo);
            break;
        }

		case UC_GLOBAL_NOTIFY_IFCP_IMAGE_MESSAGE:
        {
			uc_IFCP_image_msg *ifcp_image_msg = (uc_IFCP_image_msg *)lpVoid;

			CA_DEBUG(0, "IFCP Image Status: %s\n", ifcp_image_msg->imageStatus);
			CA_DEBUG(0, "IFCP Image Download Progress: %s\n", ifcp_image_msg->packagesDownloadProgressInfo);

			snprintf(IFCPImageStatus, MAX_SECURECORE_STATUS_SIZE, "%s", ifcp_image_msg->imageStatus);
			snprintf(IFCPImageDownload, MAX_SECURECORE_STATUS_SIZE, "%s", ifcp_image_msg->packagesDownloadProgressInfo);
            break;
        }

		case UC_GLOBAL_NOTIFY_API_AVAILABLE:
        {
			CA_DEBUG(0, "All APIs are now available and can be called by the device application.\n");
			b_caclient_init_finished = 1;
            break;
        }

		case UC_GLOBAL_NOTIFY_ACTIVE_OPERATORS:
        {
			uc_buffer_st *active_operators = (uc_buffer_st *)lpVoid;
			uint32_t index = 0;
			uint32_t *operator_list;

			CA_DEBUG(0, "operators num: %d\n", active_operators->length);
			operator_list = (uint32_t *)active_operators->bytes;
			for (index = 0; index < active_operators->length; index++)
			{
				CA_DEBUG(0, "operator ID: 0x%x\n", operator_list[index]);
			}
            break;
        }

        default:
        {
            CA_DEBUG(0, "Unknown message type.\n");
            break;
        }
    }
}

void MyServiceMessageProc(void *pMessageProcData, uc_service_message_type message, void *pVoid)
{
	CA_DEBUG(0, "Service message process type: 0x%x\n", message);

    switch (message)
    {
        case UC_ECM_STATUS:
        {
            // an ECM arrived. The status of the ECM is contained within a structure.
            uc_ecm_status_st *pEcmStatus = (uc_ecm_status_st *)pVoid;

            // check to make sure this is the right service.
            if (pMessageProcData == MYECMMESSAGEPROCDATA)
            {
                // technically, different transport protocols can have different information.
                // For now, only DVB is supported.
                if (pEcmStatus->caStream.protocolType == UC_STREAM_DVB)
                {
                    CA_DEBUG(0, "Received ECM status '%s' for PID 0x%08X\n",
                        pEcmStatus->statusMessage,
                        pEcmStatus->caStream.pid);
                }
            }
            else
            {
                CA_DEBUG(0, "Received ECM status for unknown service.\n");
            }
            break;
        }

        case UC_EMM_STATUS:
        {
            // an EMM arrived. The status of the EMM is contained within another structure.
            uc_emm_status_st *pEmmStatus = (uc_emm_status_st *)pVoid;

            // check to make sure this is the right service.
            if (pMessageProcData == MYEMMMESSAGEPROCDATA)
            {
                // technically, different transport protocols can have different information.
                // For now, only DVB is supported.
                if (pEmmStatus->caStream.protocolType == UC_STREAM_DVB)
                {
                    CA_DEBUG(0, "Received EMM status '%s' for PID 0x%08X\n",
                        pEmmStatus->statusMessage,
                        pEmmStatus->caStream.pid);
                }
            }
            else
            {
                CA_DEBUG(0, "Received EMM status for unknown service.\n");
            }
            break;
        }

        case UC_SERVICE_STATUS:
        {
            uc_service_status_st *pServiceStatus = (uc_service_status_st *)pVoid;
			errorcode_text_st s_errorcode_text;
			char *screen_text = AML_NULL;
			int error_index;
			char json_buffer[1024] = {0};

			CA_DEBUG(0, "Received Service status '%s'\n", pServiceStatus->statusMessage);

			memset(&s_errorcode_text, 0x00, sizeof(errorcode_text_st));
			memset(json_buffer, 0x00, sizeof(json_buffer));
			screen_text = (char *)ird_get_screen_text(pServiceStatus->statusMessage, &error_index);
			if (screen_text != AML_NULL)
			{
				CA_DEBUG(0, "error_index: %d,  msg: :\'%s\'\n", error_index, screen_text);
				CA_DEBUG(0, "length: %d\n", strlen(screen_text));

				s_errorcode_text.index = error_index;
				memcpy(s_errorcode_text.screen_text, screen_text, strlen(screen_text));

				_struct_to_json(APP_ERROR_BANNER, (void *)&s_errorcode_text, json_buffer);
				_notify_msg_to_app(json_buffer);
			}

            break;
        }

		case UC_SERVICE_ECM_MONITOR_STATUS:
		{
			uc_service_monitor_status_st *pServiceMonitor = (uc_service_monitor_status_st *)pVoid;

			CA_DEBUG(0, "Ecm monitor: '%s'\n", pServiceMonitor->pMessage);
			_append_monitor_to_list(pServiceMonitor->pMessage);

			break;
		}

		case UC_SERVICE_EMM_MONITOR_STATUS:
		{
			uc_service_monitor_status_st *pServiceMonitor = (uc_service_monitor_status_st *)pVoid;

			CA_DEBUG(0, "Emm monitor: '%s'\n", pServiceMonitor->pMessage);
			_append_monitor_to_list(pServiceMonitor->pMessage);

			break;
		}

        default:
        {
            CA_DEBUG(0, "Received unknown message: 0x%08X\n", message);
            break;
        }
    }
}

int ird_client_init(void)
{
	int32_t ret = 0;

	ret = CA_init();
	CA_DEBUG(0, "client init result = %d\n", ret);

	Spi_Stream_Init();

	pthread_mutex_init(&_monitor_lock, NULL);

    return 0;
}

void ird_client_start(void)
{
	uc_result relsut;

    relsut = UniversalClient_StartCaClient(MyGlobalMessageProc);
	CA_DEBUG(0, "client start relsut = %x\n", relsut);

	return;
}

void ird_open_service(IRD_SERVICE_TYPE type)
{
    uc_result result = UC_ERROR_SUCCESS;
	uc_service_handle serviceHandle;
	int index = 0;

	switch (type)
	{
		case IRD_PLAY_EMM:
		{
	        result = UniversalClient_OpenService(MYEMMSERVICECONTEXT, MyServiceMessageProc, \
									            MYEMMMESSAGEPROCDATA, &serviceHandle);
			if (result == UC_ERROR_SUCCESS)
			{
				g_EmmServiceHandle.serviceHandle = serviceHandle;
				g_EmmServiceHandle.type = IRD_PLAY_EMM;
				g_EmmServiceHandle.active = 1;

				CA_DEBUG(0, "open emm service success, serviceHandle: %x\n", serviceHandle);
			}
			else
			{
				CA_DEBUG(0, "open emm service failed, result: %d\n", result);
			}

			break;
		}

		case IRD_PLAY_LIVE:
		{
			for (index = 0; index < MULTIPLE_PLAY_NUM; index++)
			{
				if (g_EcmServiceHandle[index].active == 0)
				{
					break;
				}

				if (g_EcmServiceHandle[index].type == IRD_PLAY_LIVE)
				{
					CA_DEBUG(0, "live service has been open, do nothing\n");
					return;
				}
			}

			if (index == MULTIPLE_PLAY_NUM)
			{
				CA_DEBUG(0, "no enough ecm service handle\n");
				return;
			}

			result = UniversalClient_OpenService(MYECMSERVICECONTEXT, MyServiceMessageProc, \
												MYECMMESSAGEPROCDATA, &serviceHandle);
			if (result == UC_ERROR_SUCCESS)
			{
				g_EcmServiceHandle[index].serviceHandle = serviceHandle;
				g_EcmServiceHandle[index].type = IRD_PLAY_LIVE;
				g_EcmServiceHandle[index].active = 1;

				CA_DEBUG(0, "open ecm[%d] service success, serviceHandle: %x\n", index, serviceHandle);
			}
			else
			{
				CA_DEBUG(0, "open ecm[%d] service failed, result: %d\n", index, result);
			}

			break;
		}
	}
	return;
}

void ird_close_service(IRD_SERVICE_TYPE type)
{
    uc_result result = UC_ERROR_SUCCESS;
	uc_service_handle serviceHandle;
	int index = 0;

	switch (type)
	{
		case IRD_PLAY_EMM:
		{
			if (g_EmmServiceHandle.active == 1)
			{
				serviceHandle = g_EmmServiceHandle.serviceHandle;

				CA_DEBUG(0, "close emm service serviceHandle: %x\n", serviceHandle);
				result = UniversalClient_CloseService(&serviceHandle);
				if (result == UC_ERROR_SUCCESS)
				{
					CA_DEBUG(0, "close emm service success\n");
					g_EmmServiceHandle.active = 0;
				}
				else
				{
					CA_DEBUG(0, "close emm service fail, relsut: %x\n", result);
				}
			}
			break;
		}

		case IRD_PLAY_LIVE:
		{
			for (index = 0; index < MULTIPLE_PLAY_NUM; index++)
			{
				if ((g_EcmServiceHandle[index].active == 1) && (g_EcmServiceHandle[index].type == IRD_PLAY_LIVE))
				{
					break;
				}
			}

			if (index == MULTIPLE_PLAY_NUM)
			{
				CA_DEBUG(0, "not found targt service handle\n");
				return;
			}

			serviceHandle = g_EcmServiceHandle[index].serviceHandle;
			CA_DEBUG(0, "close ecm service serviceHandle: %x\n", serviceHandle);
			result = UniversalClient_CloseService(&serviceHandle);
			if (result == UC_ERROR_SUCCESS)
			{
				CA_DEBUG(0, "close ecm service success\n");
				g_EcmServiceHandle[index].active = 0;
			}
			else
			{
				CA_DEBUG(0, "close ecm service fail, relsut: %x\n", result);
			}
			break;
		}
	}

	return;
}

int ird_process_pmt(uint8_t *pdata, uint16_t len)
{
    uc_result result = UC_ERROR_SUCCESS;
	uc_buffer_st bytes = {0};

	bytes.bytes = pdata;
	bytes.length = len;
	result = UniversalClient_DVB_NotifyPMT(g_EcmServiceHandle[0].serviceHandle, &bytes);

	CA_DEBUG(0, "notify PMT result = %x\n", result);
    return 0;
}

int ird_process_cat(uint8_t *pdata, uint16_t len)
{
    uc_result result = UC_ERROR_SUCCESS;
	uc_buffer_st bytes = {0};

	bytes.bytes = pdata;
	bytes.length = len;
    result = UniversalClient_DVB_NotifyCAT(g_EmmServiceHandle.serviceHandle, &bytes);

	CA_DEBUG(0, "notify CAT result = %x\n", result);
    return 0;
}

void ird_register_msg_notify(app_callback_fun p_app_callbakck)
{
	CA_DEBUG(0, "[%s], p_app_callbakck: %x\n", __FUNCTION__, p_app_callbakck);
	app_callback = p_app_callbakck;
}

void ird_clear_screen_msg()
{
	errorcode_text_st s_errorcode_text;
	char *screen_text = AML_NULL;
	int error_index;
	char json_buffer[MAX_JSON_LENGTH] = {0};

	memset(&s_errorcode_text, 0x00, sizeof(errorcode_text_st));
	memset(json_buffer, 0x00, sizeof(json_buffer));
	screen_text = (char *)ird_get_screen_text(ERR_MSG_D100, &error_index);
	if (screen_text != AML_NULL)
	{
		CA_DEBUG(0, "error_index: %d,  msg: :\'%s\'\n", error_index, screen_text);
		CA_DEBUG(0, "length: %d\n", strlen(screen_text));

		s_errorcode_text.index = error_index;
		memcpy(s_errorcode_text.screen_text, screen_text, strlen(screen_text));
	}

	_struct_to_json(APP_ERROR_BANNER, (void *)&s_errorcode_text, json_buffer);
	_notify_msg_to_app(json_buffer);
}

Ird_status_t AM_APP_GetAllService(service_type_st *stAllService)
{
	int index = 0;

	if (b_caclient_init_finished == 0)
	{
		CA_DEBUG(0, "ca client not init finnish yet\n");
		return IRD_NOT_READY;
	}

	CA_DEBUG(0, "[%s] get in.\n", __FUNCTION__);
	if (stAllService == AML_NULL)
	{
		CA_DEBUG(0, "[%s] invalid parameter, stAllService: %x\n", __FUNCTION__, stAllService);
		return IRD_INVALID_PARAMETER;
	}

	stAllService->serviceHandle[index] = g_EmmServiceHandle.serviceHandle;
	sprintf(stAllService->serviceName[index], "Broadcast EMM Service");
	index++;

	if (g_EcmServiceHandle[0].active == 1)
	{
		stAllService->serviceHandle[index] = g_EcmServiceHandle[0].serviceHandle;
		sprintf(stAllService->serviceName[index], "Descramble Service");
		index++;
	}

	stAllService->count = index;
	CA_DEBUG(0, "[%s] all sevrice count: %d\n", __FUNCTION__, index);

	return IRD_NO_ERROR;
}

Ird_status_t AM_APP_GetServiceStatus(uint32_t serviceHandle,  service_status_st *pService)
{
	uc_service_status_st stServiceStatus;
	uc_uint32 nStreamCount;
	uc_service_stream_status_st *pStreamStatusList;
	uint32_t index = 0;

	if (b_caclient_init_finished == 0)
	{
		CA_DEBUG(0, "ca client not init finnish yet\n");
		return IRD_NOT_READY;
	}

	CA_DEBUG(0, "[%s] get in. serviceHandle: %x\n", __FUNCTION__, serviceHandle);
	if ((serviceHandle != g_EmmServiceHandle.serviceHandle) && (serviceHandle != g_EcmServiceHandle[0].serviceHandle))
	{
		CA_DEBUG(0, "[%s] invalid service handle: %x\n", __FUNCTION__, serviceHandle);
		return IRD_INVALID_PARAMETER;
	}

	pService->serviceHandle = serviceHandle;
	UniversalClient_Extended_GetServiceStatus(serviceHandle, &stServiceStatus);
	snprintf(pService->serviceStatus, sizeof(pService->serviceStatus), "%s", stServiceStatus.statusMessage);

	UniversalClient_GetStreamStatus(serviceHandle, &nStreamCount, &pStreamStatusList);
	pService->streamCount = nStreamCount;
	pService->streamMsg = malloc(nStreamCount * sizeof(char*));

	if (pService->streamMsg == AML_NULL)
	{
		CA_DEBUG(0, "stream message list malloc memory failed\n");
		return IRD_FAILURE;
	}

	if (serviceHandle == g_EmmServiceHandle.serviceHandle)
	{
		for (index = 0; index < nStreamCount; index++)
		{
			pService->streamMsg[index] = (char*)malloc(MAX_SERVICE_STREAM_LEN);
			if (pService->streamMsg[index] == AML_NULL)
			{
				CA_DEBUG(0, "stream message malloc memory failed\n");
				_free_memory_list(nStreamCount, pService->streamMsg);
				return IRD_FAILURE;
			}

			snprintf(pService->streamMsg[index], MAX_SERVICE_STREAM_LEN, "EMM : 0x%04x, %s, 0x%04x", \
								pStreamStatusList[index].caStream.pid, pStreamStatusList[index].streamStatusMessage, \
								pStreamStatusList[index].caSystemID);
		}
	}
	else
	{
		char _temp_es_str[MAX_SERVICE_STREAM_LEN];
		uint16_t offset = 0;

		memset(_temp_es_str, 0x00, sizeof(_temp_es_str));
		sprintf(_temp_es_str, "%s", "ES :");
		offset += 4;
		for (index = 0; index < nStreamCount; index++)
		{
			pService->streamMsg[index] = (char*)malloc(MAX_SERVICE_STREAM_LEN);
			if (pService->streamMsg[index] == AML_NULL)
			{
				CA_DEBUG(0, "stream message malloc memory failed\n");
				_free_memory_list(nStreamCount, pService->streamMsg);
				return IRD_FAILURE;
			}

			for (int idx = 0; idx < pStreamStatusList[index].componentCount; idx++)
			{
				sprintf(_temp_es_str + offset, "0x%04x, ", pStreamStatusList[index].componentStreamArray[idx].pid);
				offset += 8;
			}
			_temp_es_str[offset] = '\0';

			snprintf(pService->streamMsg[index], MAX_SERVICE_STREAM_LEN, "%sECM :0x%04x, %s, 0x%04x", \
								_temp_es_str, pStreamStatusList[index].caStream.pid, pStreamStatusList[index].streamStatusMessage, \
								pStreamStatusList[index].caSystemID);
		}
	}

	UniversalClient_FreeStreamStatus(&pStreamStatusList);

	return IRD_NO_ERROR;
}

void AM_APP_FreeServiceStatus(service_status_st pService)
{
	if (b_caclient_init_finished == 0)
	{
		CA_DEBUG(0, "ca client not init finnish yet\n");
		return;
	}

	CA_DEBUG(0, "[%s] get in.\n", __FUNCTION__);
	if (pService.streamMsg != AML_NULL)
	{
		_free_memory_list(pService.streamCount, pService.streamMsg);
	}

	return;
}

Ird_status_t AM_APP_GetProductStatus(uint32_t *pCount, product_status_st **ppProdcutStatus)
{
	uc_uint32 nProductCount;
	uc_product_status *pProductList;

	if (b_caclient_init_finished == 0)
	{
		CA_DEBUG(0, "ca client not init finnish yet\n");
		return IRD_NOT_READY;
	}

	CA_DEBUG(0, "[%s] get in.\n", __FUNCTION__);
	if ((pCount == AML_NULL) || (ppProdcutStatus == AML_NULL))
	{
		CA_DEBUG(0, "[%s] invalid parameter, pCount: %x, ppProdcutStatus: %x\n", __FUNCTION__, pCount, ppProdcutStatus);
		return IRD_INVALID_PARAMETER;
	}

	if (UniversalClient_GetProductList(&nProductCount, &pProductList) != UC_ERROR_SUCCESS)
	{
		CA_DEBUG(0, "get product list failed\n");
		return IRD_FAILURE;
	}

	*pCount = nProductCount;
	*ppProdcutStatus = malloc(sizeof(product_status_st) * nProductCount);
	if (*ppProdcutStatus == AML_NULL)
	{
		CA_DEBUG(0, "prodcut status list malloc memory failed\n");
		return IRD_FAILURE;
	}

	CA_DEBUG(0, "[%s] get product count: %d\n", __FUNCTION__, nProductCount);
	for (int index = 0; index < nProductCount; index++)
	{
		uc_sint32 nYear = 0, nMonth = 0, nDay = 0;

		_UTCToYMD(pProductList[index].startingDate , &nYear, &nMonth, &nDay);

		(*ppProdcutStatus)[index].sectorNumber = pProductList[index].sector_number;
		(*ppProdcutStatus)[index].productID = pProductList[index].product_id[0] << 8 | pProductList[index].product_id[1];
		sprintf((*ppProdcutStatus)[index].startDate, "%04d/%02d/%02d", nYear, nMonth, nDay);
		(*ppProdcutStatus)[index].durationDay = pProductList[index].duration;
		(*ppProdcutStatus)[index].CASystemID = pProductList[index].caSystemID;

		if (pProductList[index].entitled)
		{
			sprintf((*ppProdcutStatus)[index].entitled, "TRUE");
		}
		else
		{
			sprintf((*ppProdcutStatus)[index].entitled, "FALSE");
		}

		switch (pProductList[index].productType)
		{
			case UC_PRODUCT_TYPE_NORMAL:
				sprintf((*ppProdcutStatus)[index].productType, "Normal Product");
				break;

			case UC_PRODUCT_TYPE_PVR:
				sprintf((*ppProdcutStatus)[index].productType, "PVR Product");
				break;
		}

		switch (pProductList[index].sourceType)
		{
			case UC_SOURCE_TYPE_CCA:
				sprintf((*ppProdcutStatus)[index].source, "CCA");
				break;

			case UC_SOURCE_TYPE_SCA:
				sprintf((*ppProdcutStatus)[index].source, "SCA");
				break;
		}
	}

	UniversalClient_FreeProductList(&pProductList);

	return IRD_NO_ERROR;
}

void AM_APP_FreeProductStatus(product_status_st **ppProdcutStatus)
{
	if (b_caclient_init_finished == 0)
	{
		CA_DEBUG(0, "ca client not init finnish yet\n");
		return;
	}

	CA_DEBUG(0, "[%s] get in.\n", __FUNCTION__);
	if (ppProdcutStatus == AML_NULL)
	{
		CA_DEBUG(0, "[%s] invalid parameter, ppProdcutStatus: %x\n", __FUNCTION__, ppProdcutStatus);
		return;
	}

	if (ppProdcutStatus != AML_NULL)
	{
		free(*ppProdcutStatus);
	}
	*ppProdcutStatus = AML_NULL;
}

Ird_status_t AM_APP_GetClientStatus(client_status_st *pClientStatus)
{
	uc_buffer_st _tmpBuffer;
	int index = 0;
	uc_client_id client_id;
	uc_serial_number serial_number;
	uc_uint16 nLockId;
	uc_byte nSecureType;
	uc_nationality stNationality;
	uc_tms_data stTmsData;
	uc_ca_extended_section_count stCaSectionCount;

	if (b_caclient_init_finished == 0)
	{
		CA_DEBUG(0, "ca client not init finnish yet\n");
		return IRD_NOT_READY;
	}

	CA_DEBUG(0, "[%s] get in.\n", __FUNCTION__);
	if (pClientStatus == AML_NULL)
	{
		CA_DEBUG(0, "[%s] invalid parameter, pClientStatus: %x\n", __FUNCTION__, pClientStatus);
		return IRD_INVALID_PARAMETER;
	}

	_tmpBuffer.bytes = malloc(MAX_CLIENT_MALLOC_SIZE);
	_tmpBuffer.length = MAX_CLIENT_MALLOC_SIZE;
	memset(pClientStatus, 0x00, sizeof(client_status_st));

	/** CCA Agent version */
	memset(_tmpBuffer.bytes, 0x00, MAX_CLIENT_MALLOC_SIZE);
	UniversalClient_GetVersion(&_tmpBuffer);
	sprintf(pClientStatus->agentVersion, "%s", _tmpBuffer.bytes);

	/** Build Information */
	memset(_tmpBuffer.bytes, 0x00, MAX_CLIENT_MALLOC_SIZE);
	UniversalClient_GetBuildInformation(&_tmpBuffer);
	sprintf(pClientStatus->build, "%s", _tmpBuffer.bytes);

	/** Client ID */
	memset(_tmpBuffer.bytes, 0x00, MAX_CLIENT_MALLOC_SIZE);
	UniversalClient_Extended_GetClientIDString(&client_id);
	for (index = 0; index < client_id.validOperatorCount; index++)
	{
		snprintf(pClientStatus->clientID[index], MAX_CLIENT_STRING_LEN, "%s, 0x%04x", \
					client_id.clientID[index].clientIDString, client_id.clientID[index].caSystemID);
	}
	pClientStatus->nClientIDCount = client_id.validOperatorCount;

	/** CSSN */
	pClientStatus->cssn = ird_get_cssn();

	/** SN */
	UniversalClient_Extended_GetSerialNumber(&serial_number);
	for (index = 0; index < serial_number.validOperatorCount; index++)
	{
		uint32_t decimal_sn = serial_number.serialNumber[index].serialNumberBytes[0] << 24 | \
							  serial_number.serialNumber[index].serialNumberBytes[1] << 16 | \
							  serial_number.serialNumber[index].serialNumberBytes[2] << 8 | \
							  serial_number.serialNumber[index].serialNumberBytes[3];

		snprintf(pClientStatus->sn[index], MAX_CLIENT_STRING_LEN, "%u, 0x%04x", decimal_sn,
								serial_number.serialNumber[index].caSystemID);
	}
	pClientStatus->nSnCount = serial_number.validOperatorCount;

	/** lock ID */
	UniversalClient_GetLockId(&nLockId);
	pClientStatus->lockID = nLockId;

	/** Secure Type */
	UniversalClient_GetSecureType(&nSecureType)	;
	if (nSecureType == 0)
	{
		sprintf(pClientStatus->secureType, "Secure Chipset");
	}
	else
	{
		sprintf(pClientStatus->secureType, "Security ID");
	}

	/** Nationality */
	UniversalClient_Extended_GetNationality(&stNationality);
	for (index = 0; index < stNationality.validOperatorCount; index++)
	{
		snprintf(pClientStatus->nationality[index], MAX_CLIENT_NATIONALITY_LEN, "%c%c%c, 0x%04x", \
					stNationality.nationality[index].nationalityData[0], \
					stNationality.nationality[index].nationalityData[1], \
					stNationality.nationality[index].nationalityData[2], \
					stNationality.nationality[index].caSystemID);
	}
	pClientStatus->nNationalityCount = stNationality.validOperatorCount;

	/** TMS data */
	UniversalClient_Extended_GetTmsData(&stTmsData);
	for (index = 0; index < stTmsData.validOperatorCount; index++)
	{
		for (int idx = 0; idx < UC_TMS_USER_DATA_SIZE; idx++)
		{
			sprintf(&(pClientStatus->tmsData[index][idx*2]), "%02x", stTmsData.tms[index].tmsData[idx]);
		}

		sprintf(&(pClientStatus->tmsData[index][UC_TMS_USER_DATA_SIZE*2]), ", 0x%04x", stTmsData.tms[index].caSystemID);
	}
	pClientStatus->nTmsDataCount = stTmsData.validOperatorCount;

	/** Capabilities */
	uc_buffer_st large_buffer;
	large_buffer.bytes = malloc(MAX_CLIENT_LARGE_BUFFER_SIZE);
	large_buffer.length = MAX_CLIENT_LARGE_BUFFER_SIZE;

	memset(large_buffer.bytes, 0x00, MAX_CLIENT_LARGE_BUFFER_SIZE);
	UniversalClient_GetCapabilities(&large_buffer);
	snprintf(pClientStatus->Capabilities, MAX_CLIENT_LARGE_BUFFER_SIZE, "%s", large_buffer.bytes);
	free(large_buffer.bytes);

	/** ECM/EMM count */
	UniversalClient_Extended_GetEcmEmmCount(&stCaSectionCount);
	for (index = 0; index < stCaSectionCount.validOperatorCount; index++)
	{
		snprintf(pClientStatus->section[index], MAX_CLIENT_STRING_LEN, "EMM: %d, ECM: %d, 0x%04x", \
					stCaSectionCount.caSectionCount[index].emm_count, stCaSectionCount.caSectionCount[index].ecm_count, \
					stCaSectionCount.caSectionCount[index].caSystemID);
	}
	pClientStatus->nSectionCount = stCaSectionCount.validOperatorCount;

	free(_tmpBuffer.bytes);

	/** secure core status */
	snprintf(pClientStatus->secureCore, MAX_SECURECORE_STATUS_SIZE, "%s", SecureCoreStatus);
	snprintf(pClientStatus->downloadStatus, MAX_SECURECORE_STATUS_SIZE, "%s", SecureCoreDownload);

	/** ifcp image status */
	snprintf(pClientStatus->flexiCore, MAX_SECURECORE_STATUS_SIZE, "%s", IFCPImageStatus);
	snprintf(pClientStatus->flexiCoreDownload, MAX_SECURECORE_STATUS_SIZE, "%s", IFCPImageDownload);

	return IRD_NO_ERROR;
}

Ird_status_t AM_APP_ConfigServiceMonitor(uint32_t serviceHandle, int bEnable)
{
	uc_result result = UC_ERROR_SUCCESS;
	uint8_t TLV_buf[4] = {0};
	uint16_t Length = 0;
	uint8_t index = 0;

	if (b_caclient_init_finished == 0)
	{
		CA_DEBUG(0, "ca client not init finnish yet\n");
		return IRD_NOT_READY;
	}

	CA_DEBUG(0, "[%s] get in, serviceHandle: %x, bEnable: %d\n", __FUNCTION__, serviceHandle, bEnable);
	if ((serviceHandle != g_EmmServiceHandle.serviceHandle) && (serviceHandle != g_EcmServiceHandle[0].serviceHandle))
	{
		CA_DEBUG(0, "[%s] invalid service handle: %x\n", __FUNCTION__, serviceHandle);
		return IRD_INVALID_PARAMETER;
	}

	Length = 1;
	TLV_buf[0] = UC_TLV_TAG_FOR_MONITOR_SWITCH;
	TLV_buf[1] = (Length >> 8) & 0xFF;
	TLV_buf[2] = Length & 0xFF;
	TLV_buf[3] = (bEnable == 0)?0x00:0x01;

	for (index = 0; index < sizeof(TLV_buf); index++)
	{
		CA_DEBUG(0, "TLV_buf[%d] = %d\n", index, TLV_buf[index]);
	}

	result = UniversalClient_ConfigService(serviceHandle, sizeof(TLV_buf), TLV_buf);
	if (result != UC_ERROR_SUCCESS)
	{
		CA_DEBUG(0, "[%s] Universal Client config failed\n", __FUNCTION__);
		return IRD_FAILURE;;
	}

	return IRD_NO_ERROR;
}

Ird_status_t AM_APP_GetServiceMonitorList(service_monitor_list_st *pMonitorList)
{
	service_monitor_st *p_del_monitor = AML_NULL;
	int count = 0;
	int index = 0;

	if (b_caclient_init_finished == 0)
	{
		CA_DEBUG(0, "ca client not init finnish yet\n");
		return IRD_NOT_READY;
	}

	CA_DEBUG(0, "[%s] step in, get new monitor from list.\n", __FUNCTION__);

	pMonitorList->monitorStr = malloc (sizeof(char*));
	if (pMonitorList->monitorStr == AML_NULL)
	{
		CA_DEBUG(0, "[%s] pMonitorList->monitorStr malloc memory failed\n", __FUNCTION__);
		return IRD_FAILURE;
	}

	pthread_mutex_lock(&_monitor_lock);

	while (p_monitor_head != AML_NULL)
	{
		p_del_monitor = p_monitor_head;

		CA_DEBUG(0, "[%s] pMonitorList->monitorStr[%d], strlen = %d\n", __FUNCTION__, count, strlen(p_del_monitor->monitorStr));
		// add 1 byte to fill the end of string '\0'
		pMonitorList->monitorStr[count] = (char *)malloc(strlen(p_del_monitor->monitorStr) + 1);
		if (pMonitorList->monitorStr[count] == AML_NULL)
		{
			CA_DEBUG(0, "[%s] pMonitorList->monitorStr[%d] malloc memory failed\n", __FUNCTION__, count);
			break;
		}

		memset(pMonitorList->monitorStr[count], 0x00, strlen(p_del_monitor->monitorStr) + 1);
		memcpy(pMonitorList->monitorStr[count], p_del_monitor->monitorStr, strlen(p_del_monitor->monitorStr));

		p_monitor_head = p_monitor_head->next;

		free(p_del_monitor->monitorStr);
		free(p_del_monitor);

		count++;
	}

	pMonitorList->monitorCount = count;
	if ((count == 0) && (pMonitorList->monitorStr != AML_NULL))
	{
		free(pMonitorList->monitorStr);
	}

	pthread_mutex_unlock(&_monitor_lock);

	return IRD_NO_ERROR;
}

void AM_APP_FreeServiceMonitorList(service_monitor_list_st pMonitorList)
{
	if (b_caclient_init_finished == 0)
	{
		CA_DEBUG(0, "ca client not init finnish yet\n");
		return;
	}

	CA_DEBUG(0, "[%s] step in, free monitor list.\n", __FUNCTION__);

	pthread_mutex_lock(&_monitor_lock);

	if (pMonitorList.monitorStr != AML_NULL)
	{
		_free_memory_list(pMonitorList.monitorCount, pMonitorList.monitorStr);
	}

	pthread_mutex_unlock(&_monitor_lock);

	return;
}

Ird_status_t AM_APP_GetLoaderStatus(loader_status_st *pLoaderStatus)
{
	return ird_get_loader_status(pLoaderStatus);
}

Ird_status_t AM_APP_MailGetByIndex(int index, mail_detail_st *pMailDetail)
{
	return ird_mail_read_by_index(index, pMailDetail, 1);
}

Ird_status_t AM_APP_MailGetAll(int *total, mail_detail_st **ppMailDetail)
{
	return ird_mail_read_all(total, ppMailDetail);
}

Ird_status_t AM_APP_MailFree(mail_detail_st **ppMailDetail)
{
	return ird_mail_read_free(ppMailDetail);
}

Ird_status_t AM_APP_MailDeleteByIndex(int index)
{
	return ird_mail_delete_by_index(index);
}

Ird_status_t AM_APP_MailDeleteAll()
{
	return ird_mail_delete_all();
}

Ird_status_t AM_APP_MailSetReadFlag(int index)
{
	return ird_mail_set_read_flag(index);
}
