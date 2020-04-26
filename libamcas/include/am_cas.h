#ifndef _AM_CAS_H_
#define _AM_CAS_H_

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
	SERVICE_DVB,
	SERVICE_IPTV
}CA_SERVICE_MODE_t;

/**\brief Service type of the program*/
typedef enum {
	SERVICE_LIVE_PLAY,
	SERVICE_PVR_RECORDING,
    SERVICE_PVR_PLAY,
    SERVICE_TYPE_INVALID
}CA_SERVICE_TYPE_t;

/**Work type.*/
typedef enum {
    CRYPTO_TYPE_ENCRYPT, /**< Encrypt.*/
    CRYPTO_TYPE_DECRYPT  /**< Decrypt.*/
} CA_CryptoType_t;

/**Buffer type.*/
typedef enum {
    BUFFER_TYPE_NORMAL, /**< Normal buffer.*/
    BUFFER_TYPE_SECURE  /**< Secure buffer.*/
} CA_DVR_BufferType_t;

/**Stream buffer.*/
typedef struct {
    CA_DVR_BufferType_t type; /**< Buffer type.*/
    size_t           addr; /**< Start address of the buffer.*/
    size_t           size; /**< Size of the buffer.*/ 
} CA_DVR_Buffer_t; 

/**\brief Service descrambling information*/
typedef struct {
	uint16_t service_id;
	uint8_t dmx_dev;
	uint8_t dsc_dev;
	uint8_t dvr_dev;
	CA_SERVICE_MODE_t service_mode;
	CA_SERVICE_TYPE_t service_type;
	uint16_t ecm_pid;
	uint16_t stream_pids[MAX_CHAN_COUNT];
	uint32_t stream_num;
	uint8_t ca_private_data[MAX_DATA_LEN];
	uint8_t ca_private_data_len;
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
	AM_ERROR_SUCCESS,
	AM_ERROR_NOT_LOAD,
	AM_ERROR_NOT_SUPPORTED,
	AM_ERROR_OVERFLOW,
	AM_ERROR_GENERAL_ERORR
}AM_RESULT;

typedef size_t SecMemHandle;
typedef size_t CasHandle;
typedef size_t CasSession;

/**\brief Wether the specified system id is supported
 * \param CA_system_id
 * \param[in] CA_system_id The system id of the CA system
 * \retval AM_TRUE or AM_FALSE
 * \return Error code
 */
uint8_t AM_CA_IsSystemIdSupported(int CA_system_id);

/**\brief Instantiate a CA system of the specified system id
 * \param CA_system_id handle
 * \param[in] CA_system_id The system id of the CA system
 * \param[out] handle Return the handle of specified CA system
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_Init(int CA_system_id, CasHandle* handle);

/**\brief Terminate a CA system
 * \param handle
 * \param[in] handle The CasHandle of specified CA system
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_Term(CasHandle handle);

/**\brief Open a session to descramble one or more streams scrambled by the CAS
 * \param handle session
 * \param[in] handle The handle of specified CA system
 * \param[out] session The newly opened session
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_OpenSession(CasHandle handle, CasSession* session);

/**\brief Close the opened descrambling session
 * \param session
 * \param[in] session The opened session
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_CloseSession(CasSession session);

/**\brief Start descrambling for the specified session of the CA system
 * \param session serviceInfo
 * \param[in] session The opened session
 * \param[in] serviceInfo The descrambling parameters
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_StartDescrambling(CasSession session, AM_CA_ServiceInfo_t * serviceInfo);

/**\brief Stop descrambling for the specified session of the CA system
 * \param session
 * \param [in] session The opened session
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_StopDescrambling(CasSession session);

/**\brief Update the descrambling pid
 * \param session The opened session
 * \param[in] oldStreamPid The stream pid already set.
 * \param[in] newStreamPid The stream pid to be set.
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_UpdateDescramblingPid(CasSession session, uint16_t oldStreamPid, uint16_t newStreamPid);

/**\brief Set EMM Pid for the specified CA system
 * \param handle emmPid
 * \param[in] handle The handle of initialized CA system
 * \param[in] emmPid The emmPid of current ts
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_SetEmmPid(CasHandle handle, uint16_t emmPid);

/**\brief Start DVR for the specified session of the CA system
 * \param session serviceInfo privateInfo
 * \param[in] session The opened session
 * \param[in] serviceInfo The service information for recording
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DVRStart(CasSession session, AM_CA_ServiceInfo_t *serviceInfo);

/**\brief Stop DVR for the specified session of the CA system
 * \param session
 * \param[in] session The opened session
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DVRStop(CasSession session);

/**\brief Encrypt a buffer described by a AM_CA_CryptoPara_t struct
 * \param session cryptoPara storeInfo
 * \param[in] session The opened session
 * \param[in] cryptoPara The encrypt parameters
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DVREncrypt(CasSession session, AM_CA_CryptoPara_t *cryptoPara);

/**\brief Decrypt a buffer described by a AM_CA_CryptoPara_t struct
 * \param session cryptoPara
 * \param[in] session The opened session
 * \param[in] cryptoPara The decrypt parameters
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DVRDecrypt(CasSession session, AM_CA_CryptoPara_t *cryptoPara);

/**\brief Play recorded streams
 * \param session storeInfo privateInfo
 * \param[in] session The opened session
 * \param[in] cryptoPara The decrypt parameters
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DVRReplay(CasSession session, AM_CA_CryptoPara_t *cryptoPara);

/**\brief Stop DVR replay
 * \param session
 * \param[in] session The opened session
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DVRStopReplay(CasSession session);

/**\brief Create Secmem
 * \param type paddr size
 * \param[in] type The binded service type
 * \param[out] pSecBuf The secure buffer address
 * \param[out] size The secure buffer size
 * \retval SecMemHandle On success
 * \return NULL
 */
SecMemHandle AM_CA_CreateSecmem(CA_SERVICE_TYPE_t type, void **pSecbuf, uint32_t *size);

/**\brief Destroy Secmem
 * \param handle
 * \param[in] handle The SecMem handle
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DestroySecmem(SecMemHandle handle);
#endif
