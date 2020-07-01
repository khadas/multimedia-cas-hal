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

#ifndef ANDROID
#define CA_DEBUG(_level,_fmt...) \
        do { \
        if ((_level)<=(CA_DEBUG_LEVEL))\
        {\
                fprintf(stderr, "CA_DEBUG:");\
                fprintf(stderr, _fmt);\
                fprintf(stderr, "\n");\
        }\
        } while(0)
#else
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
#endif

#define UNUSED(x) (x=x)
#define CAS_ASSERT(expression)    if (!expression) { \
                                        CA_DEBUG(2, "%s, Null poiter. Line %d\n", __func__, __LINE__); \
                                        return AM_ERROR_GENERAL_ERORR; \
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

/**\brief Service descrambling information*/
typedef struct {
	uint16_t service_id;  /**< The service's index.*/
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
AM_RESULT AM_CA_OpenSession(CasHandle handle, CasSession* session);

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
 * \param[in] emmPid The emmPid of current ts
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_SetEmmPid(CasHandle handle, uint16_t emmPid);

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
SecMemHandle AM_CA_CreateSecmem(CA_SERVICE_TYPE_t type, void **pSecbuf, uint32_t *size);

/**\brief Destroy Secmem
 * \param[in] handle The SecMem handle
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DestroySecmem(SecMemHandle handle);
#ifdef __cplusplus
}
#endif

#endif /*AM_CAS_H_*/
