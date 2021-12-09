/**
 * \mainpage Amlogic CAS Hal library
 *
 * \section Introduction
 * "libamcas" is a library provides basic CAS functions used by Amlogic platform.
 * It supports:
 * \li Live Descrambling
 * \li Encrypted Record
 * \li Encrypted Playback
 *
 * \file
 * \brief cas hal
 *
 * Cas Hal is upper layer of libcas_*.
 * It is on top of specific cas integration.
 * It supports:
 * \li Load specific cas intergration automatically.
 * \li Run sepecific cas function.
 */
#ifndef _AM_CAS_H_
#define _AM_CAS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <android/log.h>
#ifndef TAG_EXT
#define TAG_EXT
#endif
#define log_print(...) __android_log_print(ANDROID_LOG_INFO, "CA_DEBUG" TAG_EXT, __VA_ARGS__)
#define CA_DEBUG(_level,_fmt...) \
        do { \
        if ((_level)<= (CA_DEBUG_LEVEL))\
        {\
                log_print(_fmt);\
        }\
        } while(0)

#define UNUSED(x) (x=x)
#define CAS_ASSERT(expression)    if (!expression) { \
                                        CA_DEBUG(2, "%s, Null poiter. Line %d\n", __func__, __LINE__); \
                                        return AM_ERROR_GENERAL_ERORR; \
                                  }
#define CAS_FUNC(func)            if (func == NULL) { \
                                        CA_DEBUG(2, "%s, unsupport function. Line %d\n", __func__, __LINE__); \
                                        return AM_ERROR_NOT_SUPPORTED; \
                                  }
#define MAX_CHAN_COUNT (8)
#define MAX_DATA_LEN (8)
#define MAX_LOCATION_SIZE     512

typedef unsigned int uint32_t;
typedef unsigned short int uint16_t;
typedef unsigned char uint8_t;

/**\brief Service Mode of the program*/
typedef enum {
	SERVICE_DVB, /**< DTV live playing.*/
	SERVICE_IPTV /**< IPTV.*/
}CA_SERVICE_MODE_t;

/**\brief Service type of the program*/
typedef enum {
	SERVICE_LIVE_PLAY,     /**< Live playing.*/
	SERVICE_PVR_RECORDING, /**< PVR recording.*/
	SERVICE_PVR_PLAY,      /**< PVR playback.*/
	SERVICE_TYPE_INVALID   /**< Invalid type.*/
}CA_SERVICE_TYPE_t;

/**\brief Work type.*/
typedef enum {
    CRYPTO_TYPE_ENCRYPT, /**< Encrypt.*/
    CRYPTO_TYPE_DECRYPT  /**< Decrypt.*/
} CA_CryptoType_t;

/**\brief Buffer type.*/
typedef enum {
    BUFFER_TYPE_NORMAL, /**< Normal buffer.*/
    BUFFER_TYPE_SECURE  /**< Secure buffer.*/
} CA_DVR_BufferType_t;

/**\brief Stream buffer.*/
typedef struct {
    CA_DVR_BufferType_t type; /**< Buffer type.*/
    size_t           addr; /**< Start address of the buffer.*/
    size_t           size; /**< Size of the buffer.*/ 
} CA_DVR_Buffer_t; 

/**\brief ca dvr pre information*/
typedef struct {
  uint8_t dmx_dev;      /**< The demux device's index.*/
} AM_CA_PreParam_t;


/**\brief Service descrambling information*/
typedef struct {
	uint16_t service_id;  /**< The service's index.*/
	uint8_t fend_dev;     /**< The frontend device's index*/
	uint8_t dmx_dev;      /**< The demux device's index.*/
	uint8_t dsc_dev;      /**< The descrmabler device's index.*/
	uint8_t dvr_dev;      /**< The DVR device's index.*/
	CA_SERVICE_MODE_t service_mode; /**< Service mode.*/
	CA_SERVICE_TYPE_t service_type; /**< Service type.*/
	uint16_t ecm_pid;     /**< ECM's PID.*/
	uint16_t stream_pids[MAX_CHAN_COUNT];  /**< Elementry streams' index.*/
	uint32_t stream_num;  /**< Elementary streams' number.*/
	uint8_t ca_private_data[MAX_DATA_LEN]; /**< Private data.*/
	uint8_t ca_private_data_len;           /**< Private data's length.*/
}AM_CA_ServiceInfo_t;

/**\brief CAS crypto parameters*/
typedef struct AM_CA_CryptoPara_s {
    CA_CryptoType_t type;                       /**< Work type.*/
    char        location[MAX_LOCATION_SIZE];     /**< Location of the record file.*/
    int         segment_id;                      /**< Current segment's index.*/
    loff_t      offset;                          /**< Current offset in the segment file.*/
    CA_DVR_Buffer_t buf_in;                        /**< Input data buffer.*/
    CA_DVR_Buffer_t buf_out;                       /**< Output data buffer.*/
    size_t      buf_len;                         /**< Output data size in bytes.*/
}AM_CA_CryptoPara_t;

/**\brief Section of the table for CAS*/
typedef enum {
	AM_CA_SECTION_PMT,
	AM_CA_SECTION_CAT,
	AM_CA_SECTION_NIT,
}AM_CA_SECTION;

/**\brief CAS section attribute*/
typedef struct AM_CA_SecAttr_s {
    uint8_t dmx_dev;
    uint16_t service_id;
    AM_CA_SECTION section_type;
}AM_CA_SecAttr_t;

/**\brief CAS Storeinfo region*/
typedef struct AM_CA_Store_Region_s {
    loff_t start;
    loff_t end;
}AM_CA_StoreRegion_t;

/**\brief Error code of the CAS-Hal module*/
typedef enum {
	AM_ERROR_SUCCESS,        /**< No error.*/
	AM_ERROR_NOT_LOAD,       /**< Dynamic library is not loaded.*/
	AM_ERROR_NOT_SUPPORTED,  /**< The CAS is not supported.*/
	AM_ERROR_OVERFLOW,       /**< Data overflow.*/
	AM_ERROR_GENERAL_ERORR   /**< General error.*/
}AM_RESULT;

/**Secure memory handle.*/
typedef size_t SecMemHandle;
/**CAS system handle.*/
typedef size_t CasHandle;
/**CAS session handle.*/
typedef size_t CasSession;

/**CAS event callback.*/
typedef AM_RESULT (*CAS_EventFunction_t)(CasSession session, char *json);

/**\brief Wether the specified system id is supported
 * \param[in] CA_system_id The system id of the CA system
 * \retval AM_TRUE or AM_FALSE
 * \return Error code
 */
uint8_t AM_CA_IsSystemIdSupported(int CA_system_id);

/**\brief Instantiate CA system
 * \param[out] handle Return the handle of specified CA system
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_Init(CasHandle* handle);

/**\brief Terminate a CA system
 * \param[in] handle The CasHandle of specified CA system
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_Term(CasHandle handle);

/**\brief Open a session to descramble one or more streams scrambled by the CAS
 * \param[in] handle The handle of specified CA system
 * \param[out] session The newly opened session
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_OpenSession(CasHandle handle, CasSession* session, CA_SERVICE_TYPE_t type);

/**\brief Close the opened descrambling session
 * \param[in] session The opened session
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_CloseSession(CasSession session);

/**\brief Start descrambling for the specified session of the CA system
 * \param[in] session The opened session
 * \param[in] serviceInfo The descrambling parameters
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_StartDescrambling(CasSession session, AM_CA_ServiceInfo_t * serviceInfo);

/**\brief Stop descrambling for the specified session of the CA system
 * \param [in] session The opened session
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_StopDescrambling(CasSession session);

/**\brief Update the descrambling pid
 * \param [in] session The opened session
 * \param[in] oldStreamPid The stream pid already set.
 * \param[in] newStreamPid The stream pid to be set.
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_UpdateDescramblingPid(CasSession session, uint16_t oldStreamPid, uint16_t newStreamPid);

/**\brief Set EMM Pid for the specified CA system
 * \param[in] handle The handle of initialized CA system
 * \param[in] dmx_dev The demux device on which to filter emm
 * \param[in] emmPid The emmPid of current ts
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_SetEmmPid(CasHandle handle, int dmx_dev, uint16_t emmPid);


AM_RESULT AM_CA_DVRSetPreParam(CasSession session, AM_CA_PreParam_t *param);


/**\brief Start DVR for the specified session of the CA system
 * \param[in] session The opened session
 * \param[in] serviceInfo The service information for recording
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DVRStart(CasSession session, AM_CA_ServiceInfo_t *serviceInfo);

/**\brief Stop DVR for the specified session of the CA system
 * \param[in] session The opened session
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DVRStop(CasSession session);

/**\brief Encrypt a buffer described by a AM_CA_CryptoPara_t struct
 * \param[in] session The opened session
 * \param[in] cryptoPara The encrypt parameters
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DVREncrypt(CasSession session, AM_CA_CryptoPara_t *cryptoPara);

/**\brief Decrypt a buffer described by a AM_CA_CryptoPara_t struct
 * \param[in] session The opened session
 * \param[in] cryptoPara The decrypt parameters
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DVRDecrypt(CasSession session, AM_CA_CryptoPara_t *cryptoPara);

/**\brief Play recorded streams
 * \param[in] session The opened session
 * \param[in] cryptoPara The decrypt parameters
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DVRReplay(CasSession session, AM_CA_CryptoPara_t *cryptoPara);

/**\brief Stop DVR replay
 * \param[in] session The opened session
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DVRStopReplay(CasSession session);

/**\brief Create Secmem
 * \param[in] type The binded service type
 * \param[out] pSecbuf The secure buffer address
 * \param[out] size The secure buffer size
 * \retval SecMemHandle On success
 * \return NULL On error
 */
SecMemHandle AM_CA_CreateSecmem(CasSession session, CA_SERVICE_TYPE_t type, void **pSecbuf, uint32_t *size);

/**\brief Destroy Secmem
 * \param[in] handle The SecMem handle
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DestroySecmem(CasSession session, SecMemHandle handle);

/**\brief Register event callback
 * \param handle event_fn
 * \param[in] session The opened session
 * \param[in] event_fn The event callback function
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_RegisterEventCallback(CasSession session, CAS_EventFunction_t event_fn);

/**\brief CAS Ioctl
 * \param handle in_json out_json out_len
 * \param[in] session The opened session
 * \param[in] in_json The input cmd string
 * \param[out] out_json The output string
 * \param[out] out_len The output string length
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_Ioctl(CasSession session, const char *in_json, char *out_json, uint32_t out_len);

/**\brief Wether the specified cas system need whole section data
 * \retval AM_TRUE or AM_FALSE
 * \return Error code
 */
uint8_t AM_CA_IsNeedWholeSection(void);

/**\brief report section
 * \param[in] pattr the attribute of section
 * \param[in] pdata the pointer of section data buffer
 * \param[in] len the length of section data
 * \retval am_success on success
 * \return error code
 */
AM_RESULT AM_CA_ReportSection(AM_CA_SecAttr_t *pAttr, uint8_t *pData, uint16_t len);

/**\brief get all region of store info
 * \param[in] session The opened session
 * \param[out] region region of store info
 * \param[out] reg_cnt region count
 * \retval am_success on success
 * \return error code
 */
AM_RESULT AM_CA_GetStoreRegion(CasSession session, AM_CA_StoreRegion_t *region, uint8_t *reg_cnt);
#ifdef __cplusplus
}
#endif

#endif /*AM_CAS_H_*/
