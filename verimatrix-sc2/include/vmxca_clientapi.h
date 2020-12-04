#ifndef VMXCA_CLIENTAPI_H
#define VMXCA_CLIENTAPI_H

#include <stdint.h>

typedef uint32_t pipeline_handle_t;
typedef uint32_t dsc_session_t;
typedef uint32_t vmxca_result_t;

#define VMXCA_SUCCESS        (0)
#define VMXCA_FAILURE        (0xFFFF0000)

#define MAX_SUBSAMPLE_COUNT  (8)
#define DASH_CENC_MAGIC      (0x636e6361)

typedef enum {
	PIPELINE_SET_M2M_SVC_INDEX = 0,        /* Set M2M service index, used for DVR or OTT case */
	PIPELINE_TEST_SET_CMD = 0xFFFF0000,
	PIPELINE_TEST_GET_CMD = 0xFFFF0001,
	PIPELINE_COMMAND_INVALID,
} pipeline_command_t;

typedef enum {
	PIPELINE_MODE_LIVE = 0,
	PIPELINE_MODE_RECORD,
	PIPELINE_MODE_PLAYBACK,
	PIPELINE_MODE_OTT,
	PIPELINE_MODE_INVALID,
} pipeline_mode_t;

typedef enum {
	DSC_ALGO_CSA2,
	DSC_ALGO_CSA3,
	DSC_ALGO_AES,
	DSC_ALGO_TDES,
	DSC_ALGO_NDL,
	DSC_ALGO_ND,
	DSC_ALGO_HMAC,
	DSC_ALGO_INVALID,
} dsc_algo_t;

typedef enum {
	KEY_TYPE_EVEN,
	KEY_TYPE_ODD,
	KEY_TYPE_EVEN_IV,
	KEY_TYPE_ODD_IV,
	KEY_TYPE_INVALID
} key_type_t;

typedef enum {
	DASH_MODE_CENC_AUDIO,
	DASH_MODE_CENC_VIDEO,
	DASH_MODE_INVALID,
} dash_mode_t;

typedef enum {
	M2M_ENGINE_USAGE_RECORD,
	M2M_ENGINE_USAGE_PLAYBACK,
	M2M_ENGINE_USAGE_HLS,
	M2M_ENGINE_USAGE_DASH_AUDIO,
	M2M_ENGINE_USAGE_DASH_VIDEO,
	M2M_ENGINE_USAGE_INVALID,
} m2m_usage_t;

typedef struct {
	uint32_t svc_index;       /* verimatrix descrambling service index */
	uint32_t ecm_pid;         /* descramble ecm pid */
} dsc_session_open_param_t;

typedef struct {
	dsc_algo_t algo;          /* descramble algorithm */
} dsc_session_info_t;

typedef struct {
	uint32_t engine_id;       /* Unique identification of the VMX Memory-2-Memory engine */
	uint32_t hw_mode;         /* 1 mean using HW ts crypto mode, 0 mean using M2M */
} m2m_info_t;

typedef struct {
	pipeline_mode_t mode;     /* pipeline mode */
} pipeline_create_param_t;

typedef struct {
	uint32_t dmx_id;          /* demux device no */
	uint32_t sid;             /* stream id */
	uint32_t program_num;     /* program number */
} pipeline_info_t;

typedef struct {
	uint8_t *p_in;            /* input buffer. If call encryption, the input buffer must be secure buffer */
	uint8_t *p_out;           /* output buffer. If call decryption, the output buffer must be secure buffer. For dash audio decrypt, p_out can be normal buffer */
	uint32_t in_len;          /* M2M input data length */
	uint32_t out_len;         /* M2M output data length, may NOT equal to input data length */
	uint8_t iv[16];           /* Some algorithms need update newly start IV */
	uint32_t iv_len;          /* IV length, if NOT need, set to 0 */
	m2m_usage_t usage;        /* M2M usage, see m2m_usage_t */
	uint32_t magic;
} m2m_engine_conf_t;

typedef struct {
	uint32_t magic;           /* DASH_CENC_MAGIC */
	uint32_t subsample_count; /* The subsample count, max to MAX_SUBSAMPLE_COUNT */
	uint32_t subsample_map[2 * MAX_SUBSAMPLE_COUNT]; /* Clear-encrypted lengh pair */
} dash_cenc_header_t;

typedef struct {
	uint8_t *p;               /* M2M buffer */
	uint32_t len;             /* M2M buffer length */
	uint8_t is_secure;        /* M2M buffer is secure buffer or not */
} m2m_buffer_t;

/*
 * brief: Initialalize VMX CA client.
 *
 * @retval 0: Success
 *
 * @retval other values: Failed
 */
vmxca_result_t VMXCA_Init(void);

/*
 * brief: Uninitialalize VMX CA client
 *
 * @retval 0: Success
 *
 * @retval other values: Failed
 */
vmxca_result_t VMXCA_UnInit(void);

/*
 * brief: Read 8 bytes Chip ID
 *
 * @param [out] id: 8 bytes buffer to receive chip ID
 *
 * @retval 0: Success
 *
 * @retval other values: Failed
 */
vmxca_result_t VMXCA_GetChipID(uint8_t id[8]);

/*
 * brief: Create a media pipeline that associate the given demux_id, sid and program number
 *
 * @param [in] pparam: Pipeline create paramters
 *
 * @param [out] p_handle: Returns the handle of the newly created pipeline
 *
 * @retval 0: Success
 *
 * @retval other values: Failed
 */
vmxca_result_t VMXCA_PipelineCreate(pipeline_create_param_t *pparam,
	pipeline_handle_t *p_handle);

/*
 * brief: Release a media pipeline
 *
 * @param [in] handle: Pipeline handle.
 *
 * @retval 0: Success
 *
 * @retval other values: Failed
 */
vmxca_result_t VMXCA_PipelineRelease(pipeline_handle_t handle);

/*
 * brief: Allocate secure memory from the corresponding pipeline.
 * It was usually used for PVR or OTT case
 *
 * @param [in] handle: Pipeline handle.
 *
 * @param [in] size: Memory size that aligned to 1MB.
 *
 * @param [out] ppaddr: Returns the allocated secure memory address
 *
 * @retval 0: Success
 *
 * @retval other values: Failed
 */
vmxca_result_t VMXCA_PipelineAllocSecMem(pipeline_handle_t handle,
	uint32_t size,
	void **ppaddr);

/*
 * brief: Free the secure memory that allocated via pipeline_alloc_secmem
 *
 * @param [in] handle: Pipeline handle.
 *
 * @param [in] paddr: Secure memory address
 *
 * @retval 0: Success
 *
 * @retval other values: Failed
 */
vmxca_result_t VMXCA_PipelineFreeSecMem(pipeline_handle_t handle, void *paddr);

/*
 * brief: Open a descrambler session that associate the given pipeline.
 * One pipeline can contain one or more descrambler session. For example,
 * In case of Live pipeline, if video stream and audio stream used different
 * control word to scramble, then you need open two dscrambler session for this
 * live pipeline.
 *
 * @param [in] handle: Pipeline handle.
 *
 * @param [in] pparam: Descrambler session open parameters.
 *
 * @param [out] p_session: Returns the handle of the newly created descrambler session
 *
 * @retval 0: Success
 *
 * @retval other values: Failed
 */
vmxca_result_t VMXCA_PipelineOpenDscSession(pipeline_handle_t handle,
	dsc_session_open_param_t *pparam,
	dsc_session_t *p_session);

/*
 * brief: Close the given descrambler session
 *
 * @param [in] handle: Pipeline handle.
 *
 * @param [in] session: The descrambler session
 *
 * @retval 0: Success
 *
 * @retval other values: Failed
 */
vmxca_result_t VMXCA_PipelineCloseDscSession(pipeline_handle_t handle,
	dsc_session_t session);

/*
 * brief: Set the descrambler session associate information
 *
 * @param [in] handle: Pipeline handle.
 *
 * @param [in] session: The descrambler session
 *
 * @param [in] session: The descrambler session information
 *
 * @retval 0: Success
 *
 * @retval other values: Failed
 */
vmxca_result_t VMXCA_PipelineSetDscSessionInfo(pipeline_handle_t handle,
	dsc_session_t session,
	dsc_session_info_t *p_info);

/*
 * brief: Alloc a keytable entry from the associate descrambler session.
 * One descrambler session can allocate one or more keytable entry.
 *
 * @param [in] handle: Pipeline handle.
 *
 * @param [in] dsc_session: The descrambler session
 *
 * @param [in] type: The key type
 *
 * @param [out] p_keytable: Output keytable index that need set to linux REE descrambler driver.
 *
 * @retval 0: Success
 *
 * @retval other values: Failed
 */
vmxca_result_t VMXCA_PipelineDscSessionAllocKeytable(pipeline_handle_t handle,
	dsc_session_t session,
	key_type_t type,
	uint32_t *p_keytable);

/*
 * brief: Free the given keytable from the associate descrambler session.
 *
 * @param [in] handle: Pipeline handle.
 *
 * @param [in] dsc_session: The descrambler session
 *
 * @param [in] keytable: keytable index that need to free
 *
 * @retval 0: Success
 *
 * @retval other values: Failed
 */
vmxca_result_t VMXCA_PipelineDscSessionFreeKeytable(pipeline_handle_t handle,
	dsc_session_t session,
	uint32_t keytable);

/*
 * brief: Set the M2M information of the pipeline, the pipeline should be Record,
 * Playback or OTT
 *
 * @param [in] handle: Pipeline handle.
 *
 * @param [in] p_info: M2M inforamtion
 *
 * @retval 0: Success
 *
 * @retval other values: Failed
 */
vmxca_result_t VMXCA_PipelineSetM2MInfo(pipeline_handle_t handle,
	m2m_info_t *p_info);

/*
 * brief: Set pipeline specific information, only Live and Record pipeline need
 * call this API
 *
 * @param [in] handle: Pipeline handle.
 *
 * @param [in] p_info: Pipeline inforamtion
 *
 * @retval 0: Success
 *
 * @retval other values: Failed
 */
vmxca_result_t VMXCA_PipelineSetInfo(pipeline_handle_t handle,
	pipeline_info_t *p_info);

/*
 * brief: Update OTT decryption IV data to TA. This API usually used in HLS block
 * mode AES CBC decryption. For example, If HLS encryption  block size is 4 MB,
 * but usually the buffer that the app accepts HLS network data is small, for example
 * 32KB, in this case, the APP need to call this API to update the IV data after
 * decrypting the 32KB data every time.
 *
 * @param [in] ott_handle:OTT Pipeline handle
 *
 * @param [in] iv: iv value
 *
 * @retval 0: Success
 *
 * @retval other values: Failed
 */
vmxca_result_t VMXCA_PipelineUpdateOttIV(pipeline_handle_t ott_handle, uint8_t iv[16]);

/*
 * brief: Update the record secure buffer to TA. Because the VMX M2M API has a limit
 * that it setup the encrypted input buffer and block_size only one time, if the address of the
 * input encryption buffer changes, then the TA can not use the new address for
 * encryption. On Amlogic hardware platform, the size and address of the record
 * data is changed every time when read from Linux-DVB, so the app needs to call
 * this API to update the address and size to the TA after it reads the record
 * data more or equal than block_size
 *
 * @param [in] record_handle:Record pipeline handle
 *
 * @param [in] p_sec_addr: Record secure address read from Linux-DVB
 *
 * @param [in] size: The size of record data
 *
 * @retval 0: Success
 *
 * @retval other values: Failed
 */
vmxca_result_t VMXCA_PipelineUpdateRecordBuffer(pipeline_handle_t record_handle,
	uint8_t *p_addr, uint32_t size);

/*
 * brief: Transfer Audio data from secure memory to normal memory. Because audio
 * driver is in REE side, it's can **NOT** access the secure memory. But OTT pipeline
 * decrypt all data that include audio data to secure memory. So app need call
 * this API to transfer audio data to normal memory after decrypt each times.
 *
 * @param [in] ott_handle:OTT pipeline handle
 *
 * @param [in] p_in: Input audio secure memory. Must be auido data, any other format data would deny.
 *
 * @param [in] in_len: Input audio buffer length
 *
 * @param [out] p_out: Output buffer, it's a normal buffer can be accessed by REE.
 *
 * @param [in/out] p_out_len: Output buffer length, may not equal to input length.
 *
 * @retval 0: Success
 *
 * @retval other values: Failed
 */
vmxca_result_t VMXCA_PipelineTransferAudioData(pipeline_handle_t ott_handle,
	uint8_t *p_in, uint32_t in_len, uint8_t *p_out, uint32_t *p_out_len);

/*
 * breif: Set the Dash mode, the pipeline should be OTT pipeline
 *
 * @param [in] handle: OTT pipeline handle.
 *
 * @param [in] mode: Dash decrypt mode
 *
 * @retval 0: Success
 *
 * @retval other values: Failed
 */
vmxca_result_t VMXCA_PipelineSetDashMode( pipeline_handle_t ott_handle,
	dash_mode_t mode);

/*
 * breif: M2M Crypto function, can be used for record encrypt, playback decrypt,
 * HLS decrypt, dash audio decrypt, dash video decrypt.
 *
 * @param [in] m2m_handle: M2M Pipeline handle
 *
 * @param [in/out] p_conf: M2M engine configuration, see m2m_engine_conf_t.
 *
 * @retval 0: Success
 *
 * @retval other values: Failed
 */
vmxca_result_t VMXCA_PipelineM2MEngineRun(pipeline_handle_t m2m_handle,
	m2m_engine_conf_t *p_conf);

/*
 * brief: Get VirwRight library input padding buffer, used for padding ViewRight M2M crypto
 * function.
 *
 * @param [in] engigne_id: M2M engine ID, for DVR it's channel ID
 *
 * @param [in] p_m2m_buf: M2M input buffer
 *
 * @param [out] p_buffer: The ViewRight input padding buffer
 *
 * @param [out] p_len: The ViewRight pad buffer length
 *
 * @retval 0: Success
 *
 * @retval other values: Failed
 */
vmxca_result_t VMXCA_GetViewRightInputPadBuffer(uint8_t engine_id,
	m2m_buffer_t *p_m2m_buf, uint8_t **p_buffer, uint32_t *p_len);

/*
 * brief: Get VirwRight library output padding buffer, used for padding ViewRight M2M crypto
 * function.
 *
 * @param [in] engigne_id: M2M engine ID, for DVR it's channel ID
 *
 * @param [in] p_m2m_buf: M2M output buffer
 *
 * @param [out] p_buffer: The ViewRight output padding buffer
 *
 * @param [out] p_len: The ViewRight pad buffer length
 *
 * @retval 0: Success
 *
 * @retval other values: Failed
 */
vmxca_result_t VMXCA_GetViewRightOutputPadBuffer(uint8_t engine_id,
	m2m_buffer_t *p_m2m_buf, uint8_t **p_buffer, uint32_t *p_len);

#endif //end VMXCA_CACLIENTAPI_H
