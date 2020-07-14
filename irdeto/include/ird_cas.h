/*
 * Copyright (C) 2015 Amlogic, Inc.
 *
 *
 */
#ifndef IRD_CAS_H
#define IRD_CAS_H

#include <linux/dvb/dmx.h>


/* DKI task ID */
typedef pthread_t DKI_tid_t;


#define HAL_MAX(a, b) ((a) > (b) ? (a) : (b))
#define HAL_MIN(a, b) ((a) < (b) ? (a) : (b))
#define HAL_N_ELEM(a) (sizeof(a) / sizeof((a)[0]))


typedef struct HAL_DMX_Channel_s	HAL_DMX_Channel;
typedef struct HAL_DMX_Filter_s		HAL_DMX_Filter;
typedef struct HAL_DESC_Slot_s		HAL_DESC_Slot;



#define	AML_NULL		0
#define INVALID_PID		0x1FFF
#define INVALID_STREAM_TYPE -1

/**cca private data*/
#define CCA_PRIVATE_DATA_PREFIX "Amlogic DVT test"
#define CCA_PRIVATE_DATA_LEN  16

/**Number of demux device.*/
#define HAL_DMX_DEVICE_NUM   3
/**Number of descrambler device.*/
#define HAL_DSC_DEVICE_NUM   2

/**Number of demux channels in one demux device.*/
#define HAL_DMX_CHANNEL_NUM  31
/**Number of demux filters in one demux device.*/
#define HAL_DMX_FILTER_NUM   31

/**Number of descrambler slot in one descrambler device.*/
#define HAL_DESC_SLOT_NUM   8


typedef enum
{
	IRD_NO_ERROR = 0,
	IRD_FAILURE  = 1,
	IRD_NOT_READY  = 2,
	IRD_INVALID_PARAMETER = 3,
} Ird_status_t;

typedef enum
{
	SD_RSA_MODE_SECURE_BOOT_ENABLED              = (1 << 0),
	SD_RSA_MODE_BACKGROUND_BOOT_CHECK_ENABLED    = (1 << 1),
	SD_RSA_MODE_CLEAR_CONTENT_PROTECTION_ENABLED = (1 << 2)
} secure_device_rsa_mode_type_t;

typedef enum
{
	SD_JTAG_OPENED = 0,
	SD_JTAG_PERMANENTLY_CLOSED,
	SD_JTAG_KEYED
} secure_device_jtag_status_t;

typedef enum
{
	SD_SECURE_CW_MODE_ENFORCED                 = (1 << 0),
	SD_SECURE_PVR_MODE_ENFORCED                = (1 << 1),
	SD_SECURE_3_LEVEL_LADDER_CW_MODE_ENFORCED  = (1 << 2),
	SD_SECURE_3_LEVEL_LADDER_PVR_MODE_ENFORCED = (1 << 3)
} secure_device_cw_mode_type_t;

typedef enum
{
	SD_CRYPTO_CW_TDES_SUPPORTED                = (1 << 0),
	SD_CRYPTO_CW_AES_SUPPORTED                 = (1 << 1),
	SD_CRYPTO_CW_3_LEVEL_KEY_LADDER_SUPPORTED  = (1 << 2),
	SD_CRYPTO_PVR_TDES_SUPPORTED               = (1 << 4), /* Bit 3 is reserved for future use. */
	SD_CRYPTO_PVR_AES_SUPPORTED                = (1 << 5),
	SD_CRYPTO_PVR_3_LEVEL_KEY_LADDER_SUPPORTED = (1 << 6), /* Bit 7 is reserved for future use. */
} secure_device_crypto_type_t;

typedef enum
{
	SD_IFCP_MODE_NOT_SUPPORTED            = 0,
	SD_IFCP_MODE_SUPPORTED                = 1
} secure_device_ifcp_mode_type_t;


/**Channel state.*/
typedef enum {
	HAL_DMX_CHANNEL_STATE_IDLE,      /**< Unused.*/
	HAL_DMX_CHANNEL_STATE_ALLOCATED, /**< Allocated.*/
	HAL_DMX_CHANNEL_STATE_STARTED,    /**< Started.*/
	HAL_DMX_CHANNEL_STATE_CLOSED,    /**< Closed.*/
} HAL_DMX_ChannelState;

/**Filter state.*/
typedef enum {
	HAL_DMX_FILTER_STATE_IDLE,      /**< Unused*/
	HAL_DMX_FILTER_STATE_ALLOCATED, /**< Allocated.*/
	HAL_DMX_FILTER_STATE_ENABLED,   /**< Enabled.*/
	HAL_DMX_FILTER_STATE_CLOSED     /**< Closed*/
} HAL_DMX_FilterState;

/**Descrambler state.*/
typedef enum {
	HAL_DESC_STATE_IDLE,      /**< Unused*/
	HAL_DESC_STATE_ALLOCATED, /**< Allocated.*/
	HAL_DESC_STATE_ENABLED,   /**< Enabled.*/
} HAL_DESC_State;

typedef enum
{
	DSC_KEY_TYPE_EVEN,
	DSC_KEY_TYPE_ODD,
} dsc_key_type_t;

typedef enum
{
	DSC_PROTECTION_UNKNOWN,
	DSC_PROTECTION_CLEAR,
	DSC_PROTECTION_TDES,
	DSC_PROTECTION_AES,
	DSC_PROTECTION_AES_SCOT
} dsc_key_protection_t;

typedef enum
{
	DSC_ALGORITHM_DVB_CSA,
	DSC_ALGORITHM_AES_128_CBC
} dsc_algorithm_t;

typedef enum
{
	APP_ERROR_BANNER,
	APP_MESSAGE_TEXT,
	APP_ATTRIBUTE_DISPLAY,
	APP_FINGER_PRINT,
} App_Msg_Type;

typedef enum
{
	MAIL_PRIORITY_FORCED,
	MAIL_PRIORITY_NORMAL,
} mail_priority_t;

typedef enum
{
	MAIL_TYPE_MAILBOX,
	MAIL_TYPE_ANNOUNCEMENT,
	MAIL_TYPE_ATTRIBUTE,
} mail_type_t;


#if 0
/**Demux device.*/
typedef struct {
	int              dev_no;                        /**< Linux demux device number.*/
	int              openned;                       /**< The device is openned.*/
	HAL_DMX_Channel_s  channels[HAL_DMX_CHANNEL_NUM]; /**< Channels in this device.*/
	HAL_DMX_Filter_s   filters[HAL_DMX_FILTER_NUM];   /**< Filters in this device.*/
	pthread_t        sec_thread;                    /**< Section monitor thread.*/
	pthread_mutex_t  lock;                          /**< Lock of the device.*/
} HAL_DMX_Device_s;
#endif

/**Demux channel.*/
struct HAL_DMX_Channel_s{
	//HAL_DMX_Device_s  *dmx;     /**< The demux device contains this channel.*/
	int              id;      /**< The channel's index.*/
	HAL_DMX_ChannelState state; /**< State of the channel.*/
	int              pid;     /**< PID.*/
	int         	stream_type;  /**< Channel's stream type.*/
	HAL_DMX_Filter  *filters; /**< Filters in this channel.*/
	HAL_DESC_Slot	*descramblers;	/**< Descramblers in this channel.*/
	uint32_t           buffer_size; /**< Buffer size.*/
	int              fd;      /**< Linux device file descriptor.*/
	uint32_t           connect; /**< Stream notify connect handle.*/
	void  				*connect_notify;      /**< Connect notify.*/
};

/**Demux filter.*/
struct HAL_DMX_Filter_s{
	//HAL_DMX_Device_s   *dmx;     /**< The demux device contains this filter.*/
	HAL_DMX_Channel  *channel; /**< The channel contains this filter.*/
	HAL_DMX_Filter   *next;    /**< The next filter in the same channel.*/
	HAL_DMX_FilterState state; /**< State of the filter.*/
	int               pid;     /**< PID.*/
	int               id;      /**< The filter's index.*/
	int               fd;      /**< Linux device file descriptor.*/
	int               has_filter; /**< Has set the filter.*/
	int               depth;   /**< Depth of the filter.*/
	dmx_filter_t      filter;  /**< Linux section demux filter.*/
};

/**Descrambler.*/
struct HAL_DESC_Slot_s{
	//HAL_DMX_Device_s   *dmx;     /**< The demux device contains this filter.*/
	HAL_DMX_Channel  *channel; /**< The channel contains this filter.*/
	HAL_DESC_Slot   	*next;    /**< The next filter in the same channel.*/
	HAL_DESC_State		state; /**< State of the desacrambler.*/
	int               pid;     /**< PID.*/
	int               id;      /**< The filter's index.*/
	int               fd;      /**< Linux device file descriptor.*/
};



#define MAX_SEVICE_NUM (3)
#define MAX_SERVICE_NAME_LEN (32)
#define MAX_SERVICE_STATUS_LEN (16)
#define MAX_SERVICE_STREAM_LEN (128)

#define MAX_CLIENT_MALLOC_SIZE (256)
#define MAX_CLIENT_OPERATOR_COUNT (8)
#define MAX_CLIENT_STRING_LEN (128)
#define MAX_CLIENT_LARGE_BUFFER_SIZE (512)
#define MAX_CLIENT_NATIONALITY_LEN (4)

#define MAX_SECURECORE_STATUS_SIZE (128)

#define MAX_MAIL_CONTENT_LENGTH (512)


typedef struct _service_type
{
	uint32_t	count;
	uint32_t	serviceHandle[MAX_SEVICE_NUM];
	char		serviceName[MAX_SEVICE_NUM][MAX_SERVICE_NAME_LEN];
} service_type_st;

typedef struct _service_status
{
	uint32_t	serviceHandle;
	char		serviceStatus[MAX_SERVICE_STATUS_LEN];
	int			streamCount;
	char		**streamMsg;
} service_status_st;

typedef struct _product_status
{
	uint8_t		sectorNumber;
	uint16_t	productID;
	char		startDate[12];
	uint8_t		durationDay;
	char		entitled[8];
	char		productType[32];
	uint32_t	CASystemID;
	char		source[8];
} product_status_st;

typedef struct _client_status
{
	char		agentVersion[32];
	char		build[64];
	uint32_t	cssn;
	uint16_t	lockID;
	char		secureType[16];
	char		Capabilities[MAX_CLIENT_LARGE_BUFFER_SIZE];
	char		secureCore[MAX_SECURECORE_STATUS_SIZE];
	char		downloadStatus[MAX_SECURECORE_STATUS_SIZE];
	char		flexiCore[MAX_SECURECORE_STATUS_SIZE];
	char		flexiCoreDownload[MAX_SECURECORE_STATUS_SIZE];
	uint8_t		nClientIDCount;
	char		clientID[MAX_CLIENT_OPERATOR_COUNT][MAX_CLIENT_STRING_LEN];
	uint8_t		nSnCount;
	char		sn[MAX_CLIENT_OPERATOR_COUNT][MAX_CLIENT_STRING_LEN];
	uint8_t		nNationalityCount;
	char		nationality[MAX_CLIENT_OPERATOR_COUNT][MAX_CLIENT_NATIONALITY_LEN];
	uint8_t		nTmsDataCount;
	char		tmsData[MAX_CLIENT_OPERATOR_COUNT][MAX_CLIENT_STRING_LEN];
	uint8_t		nSectionCount;
	char		section[MAX_CLIENT_OPERATOR_COUNT][MAX_CLIENT_STRING_LEN];
} client_status_st;

typedef struct _loader_status
{
	uint16_t manufacturerId;
	uint16_t hardwareVersion;
	uint16_t variant;
	uint16_t systemId;
	uint16_t keyVersion;
	uint16_t signatureVersion;
	uint16_t loadVersion;
	uint16_t loaderVersion;
} loader_status_st;


#define MAX_MESSAGE_LENGTH (256)
#define MAX_ATTRIBUTE_DISPLAY_LENGTH (512)
#define MAX_FINGER_PRINT_LENGTH (512)

typedef struct _errorcode_text
{
	int index;
	char screen_text[MAX_MESSAGE_LENGTH];
} errorcode_text_st;

typedef struct _message_text
{
	int bForce;
	char content[MAX_MESSAGE_LENGTH];
} message_text_st;

typedef struct _attribute_display
{
	int bForce;
	int bFlash;
	int bBanner;
	uint16_t duration;
	uint8_t coverage_percent;
	char content[MAX_ATTRIBUTE_DISPLAY_LENGTH];
} attribute_display_st;

typedef struct _finger_print
{
	int bFlash;
	uint16_t duration;
	uint8_t coverage_percent;
	uint8_t location_x;
	uint8_t location_y;
	uint8_t bg_transparency;
	uint32_t bg_colour;
	uint8_t font_transparency;
	uint32_t font_colour;
	uint32_t font_type;
	char content[MAX_FINGER_PRINT_LENGTH];
} finger_print_st;

typedef struct _mail_detail
{
	int index;
	int b_read;
	uint16_t year;
	uint8_t month;
	uint8_t day;
	uint8_t hour;
	uint8_t minute;
	uint16_t ca_system_id;
	mail_priority_t priority;
	mail_type_t type;
	char content[MAX_MAIL_CONTENT_LENGTH];
} mail_detail_st;

typedef struct _service_monitor_list
{
	int			monitorCount;
	char		**monitorStr;
} service_monitor_list_st;

int ird_client_init(void);
void ird_client_start(void);
void ird_open_service();
int ird_process_pmt(uint8_t *pdata, uint16_t len);
int ird_process_cat(uint8_t *pdata, uint16_t len);
uint32_t ird_get_cssn(void);


int ird_test(void);

Ird_status_t AM_APP_GetAllService(service_type_st *stAllService);
Ird_status_t AM_APP_GetServiceStatus(uint32_t serviceHandle,  service_status_st *pService);
void AM_APP_FreeServiceStatus(service_status_st pService);
Ird_status_t AM_APP_GetProductStatus(uint32_t *pCount, product_status_st **ppProdcutStatus);
void AM_APP_FreeProductStatus(product_status_st **ppProdcutStatus);
Ird_status_t AM_APP_GetClientStatus(client_status_st *pClientStatus);
Ird_status_t AM_APP_ConfigServiceMonitor(uint32_t serviceHandle, int bEnable);
Ird_status_t AM_APP_GetServiceMonitorList(service_monitor_list_st *pMonitorList);
void AM_APP_FreeServiceMonitorList(service_monitor_list_st pMonitorList);
Ird_status_t AM_APP_GetLoaderStatus(loader_status_st *pLoaderStatus);
Ird_status_t AM_APP_MailGetByIndex(int index, mail_detail_st *pMailDetail);
Ird_status_t AM_APP_MailGetAll(int *total, mail_detail_st **ppMailDetail);
Ird_status_t AM_APP_MailFree(mail_detail_st **ppMailDetail);
Ird_status_t AM_APP_MailDeleteByIndex(int index);
Ird_status_t AM_APP_MailDeleteAll();
Ird_status_t AM_APP_MailSetReadFlag(int index);

#endif // IRD_CAS_H
