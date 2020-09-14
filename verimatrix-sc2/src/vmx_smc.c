#ifndef CA_DEBUG_LEVEL
#define CA_DEBUG_LEVEL 3
#endif

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bc_main.h"
#include "bc_consts.h"
#include "am_smc.h"
#include "am_cas.h"

#define SMC_DEV_NO (0)
#define AM_SMC_MAX_BUF			512

typedef enum {
	SMC_WRITE_CMD,
	SMC_READ_CMD,
	SMC_INVALID_CMD
} SMC_CMD_t;
typedef enum {
	SMC_RW_INIT,
	SMC_READ_ERROR,
	SMC_WRITE_ERROR,
	SMC_READ_COMPLETED,
	SMC_WRITE_COMPLETED
} SMC_RW_STATUS_t;
typedef struct smc_info_s {
	pthread_t        	i_thread;
	pthread_mutex_t     lock;
	pthread_cond_t 		cond;
	int					i_enable_thread;
	int					i_cmd;
	uint16_t			i_timeout;
	uint8_t				i_atr_buf[AM_SMC_MAX_ATR_LEN];
	int					i_atr_len;
	uint8_t				i_read_buf[AM_SMC_MAX_BUF];
	uint16_t			i_read_len;
	uint8_t				i_write_buf[AM_SMC_MAX_BUF];
	uint16_t			i_write_len;
	int					b_status;

} smc_info_t;
smc_info_t g_smc_info;

static void ( *am_smc_notify )() = NULL ;
static void *am_smc_thread( void *arg );
static void am_smc_cb( int dev_no, AM_SMC_CardStatus_t status, void *data );

int am_smc_init(void)
{
	AM_SMC_OpenPara_t para;

	memset(&para, 0, sizeof(para));
	para.enable_thread = 1;
	AM_SMC_Open(SMC_DEV_NO, &para);
	AM_SMC_SetCallback(SMC_DEV_NO, am_smc_cb, NULL);
	memset(g_smc_info.i_atr_buf, 0, AM_SMC_MAX_ATR_LEN);
	g_smc_info.i_atr_len = 0;
	g_smc_info.i_timeout = 0;
	g_smc_info.b_status = SMC_INVALID_CMD;
	pthread_mutex_init(&g_smc_info.lock, NULL);
	pthread_cond_init(&g_smc_info.cond, NULL);
	g_smc_info.i_enable_thread = 1;
	pthread_create(&g_smc_info.i_thread, NULL, am_smc_thread, NULL);

	return 0;
}

int am_smc_deinit(void)
{
	g_smc_info.i_enable_thread = 0;
	pthread_mutex_lock(&g_smc_info.lock);
	g_smc_info.i_cmd = SMC_INVALID_CMD;
	pthread_cond_signal(&g_smc_info.cond);
	pthread_mutex_unlock(&g_smc_info.lock);
	pthread_join(g_smc_info.i_thread, NULL);
	pthread_cond_destroy(&g_smc_info.cond);
	AM_SMC_Close(SMC_DEV_NO);

	return 0;
}

static void am_smc_cb( int dev_no, AM_SMC_CardStatus_t status, void *data )
{
	UNUSED(dev_no);
	UNUSED(data);
	CA_DEBUG( 1, "in am_smc_cb" );
	if ( status == AM_SMC_CARD_IN ) {
		if ( am_smc_notify )
			am_smc_notify( BC_SC_INSERTED );
		CA_DEBUG( 0, "%s, smartcard in", __FUNCTION__ );
	} else {
		if ( am_smc_notify ) {
			am_smc_notify( BC_SC_REMOVED );
			CA_DEBUG( 2, "%s, smartcard out notif", __FUNCTION__ );
		}
		CA_DEBUG( 0, "%s, smartcard out", __FUNCTION__ );
	}
}

static void *am_smc_thread( void *arg )
{
	int ret;
	int len = 0;
	int index = 0;
	uint8_t rx_buf[512];

	UNUSED(arg);

	while ( g_smc_info.i_enable_thread ) {
		pthread_mutex_lock( &g_smc_info.lock );
		pthread_cond_wait( &g_smc_info.cond, &g_smc_info.lock );

		if ( g_smc_info.i_cmd == SMC_WRITE_CMD ) {
			ret = AM_SMC_Write( SMC_DEV_NO, g_smc_info.i_write_buf, g_smc_info.i_write_len, g_smc_info.i_timeout );
			if (!ret) {
				CA_DEBUG( 2, "@@@write sucess, timeout:%d, notify completed", g_smc_info.i_timeout );
				g_smc_info.b_status = SMC_WRITE_COMPLETED;
				if ( am_smc_notify )
					am_smc_notify( BC_SC_RW_COMPLETED );

				memset( rx_buf, 0, sizeof( rx_buf ) );
				ret = AM_SMC_Read( SMC_DEV_NO, rx_buf, 3, g_smc_info.i_timeout );
				if (!ret) {
					CA_DEBUG( 2, "@@@read step_1 sucess :%#x, %#x, %#x, timeout:%d",
						rx_buf[0], rx_buf[1], rx_buf[2], g_smc_info.i_timeout );
				} else {
					CA_DEBUG( 2, "@@@@@read step_1 error, timeout:%d", g_smc_info.i_timeout );
					g_smc_info.b_status = SMC_READ_ERROR;
					goto final;
				}
				ret = AM_SMC_Read( SMC_DEV_NO, rx_buf + 3, rx_buf[2] + 1, g_smc_info.i_timeout );

				len = rx_buf[2] + 4;
				g_smc_info.i_read_len = rx_buf[2];
				memcpy( g_smc_info.i_read_buf, rx_buf + 3, rx_buf[2] ); //only copy APDU
				if (!ret) {
					CA_DEBUG( 2, "smc thread notify read completed, len:%d, APDU buf:%#x - %#x  ",
						g_smc_info.i_read_len, g_smc_info.i_read_buf[0], g_smc_info.i_read_buf[g_smc_info.i_read_len - 1] );
					index = 0;
					while ( index < len ) {
						//CA_DEBUG( 0, "     %#x", rx_buf[index] );
						index++;
					}
					//edc
					uint8_t edc = rx_buf[0];;
					index = 1;
					while ( index < len - 1 ) {
						edc = edc ^ rx_buf[index];
						index++;
					}
					CA_DEBUG( 2, "###### readData edc :%#x, last_byte:%#x\n", edc, rx_buf[len - 1] );
					g_smc_info.b_status = SMC_READ_COMPLETED;
				} else {
					CA_DEBUG( 2, "@@@read step_2 error, notify error" );
					g_smc_info.b_status = SMC_READ_ERROR;
					goto final;
				}

				CA_DEBUG( 2, "smc thread notify read_write completed" );

				g_smc_info.i_cmd = SMC_INVALID_CMD;
			} else {
				CA_DEBUG( 2, "smc thread  write error" );
				g_smc_info.b_status = SMC_WRITE_ERROR;
				goto final;
			}
		}
final:
		pthread_mutex_unlock( &g_smc_info.lock );
	}
	return NULL;
}

int16_t  MMI_SetSmartcard_State( enScState_t state )
{
	CA_DEBUG( 0, "@@call %s state=%d @@", __FUNCTION__, state );
	return 0;
}

// --- SC ---
int16_t  SC_Write( uint8_t *pabBuffer, uint16_t *pwLen, uint16_t wTimeout )
{
	CA_DEBUG( 3, "===>>in SC_Write, len:%d,timeout:%d buffer is :", *pwLen, wTimeout );
	int len = *pwLen;
	int index = 0;
	int i, edc_len;
	while ( index < len ) {
		//CA_DEBUG( 0, "     %#x", pabBuffer[index] );
		index++;
	}
	pthread_mutex_lock( &g_smc_info.lock );
	memset( g_smc_info.i_write_buf, 0, sizeof( g_smc_info.i_write_buf ) );
	g_smc_info.i_write_buf[0] = 0;
	g_smc_info.i_write_buf[1] = 0;
	g_smc_info.i_write_buf[2] = *pwLen;
	memcpy( g_smc_info.i_write_buf + 3, pabBuffer, *pwLen );

	uint8_t edc = g_smc_info.i_write_buf[0];;
	i = 1;
	edc_len = *pwLen + 3;
	while ( i < edc_len ) {
		edc = edc ^ g_smc_info.i_write_buf[i];
		i++;
	}
	CA_DEBUG( 3, "###### SC_Write edc :%#x\n", edc );
	g_smc_info.i_write_buf[edc_len] = edc;
	g_smc_info.i_write_len = edc_len + 1;

	g_smc_info.i_cmd = SMC_WRITE_CMD;
	g_smc_info.b_status = SMC_RW_INIT;
	g_smc_info.i_timeout = wTimeout;
	pthread_cond_signal( &g_smc_info.cond );
	pthread_mutex_unlock( &g_smc_info.lock );
	CA_DEBUG( 3, "===>>out SC_Write" );
	return k_BcSuccess;
}

int16_t  SC_Read( uint8_t *pabBuffer, uint16_t *pwLen )
{

	if ( pabBuffer == NULL ) {
		CA_DEBUG( 1, "%s, param buf is null", __FUNCTION__ );
		return k_BcError;
	}
	pthread_mutex_lock( &g_smc_info.lock );
	CA_DEBUG( 3, "===>>in SC_Read, smc_status:%d", g_smc_info.b_status );
	if ( g_smc_info.b_status != SMC_READ_COMPLETED ) {
		CA_DEBUG( 3, "===>>out SC_Read, smc read not compelted, return error" );
		pthread_mutex_unlock( &g_smc_info.lock );
		return k_BcError;
	}
	CA_DEBUG( 3, "read completed, copy data, len:%d", g_smc_info.i_read_len );
	memcpy( pabBuffer, g_smc_info.i_read_buf, g_smc_info.i_read_len );
	*pwLen = g_smc_info.i_read_len;
	pthread_mutex_unlock( &g_smc_info.lock );
	CA_DEBUG( 3, "===>>out SC_Read, write is completed ,return sucess len:%d", *pwLen );
	return k_BcSuccess;
}

int16_t  SC_IOCTL( enCmd_t cmd, void_t *pvParams, uint16_t *pwLen )
{

	AM_SMC_CardStatus_t status;
	switch ( cmd ) {
	case k_ConnectSc:
		CA_DEBUG( 2, "@@call %s cmd:k_ConnectSc %p", __FUNCTION__, pvParams);
		am_smc_notify = pvParams;
		AM_SMC_GetCardStatus( SMC_DEV_NO, &status );
		if ( am_smc_notify ) {
			int enable = 1;
			char *SMC = getenv("SMC");
			if (SMC) {
				enable = atoi(SMC);
				if (!enable) {
					CA_DEBUG(0, "disable smartcard\n");
					am_smc_notify( BC_SC_REMOVED);
					break;
				}
			}
			if ( status == AM_SMC_CARD_OUT ) {
				CA_DEBUG( 2, "cmd k_ConnectSc, smc status is : out" );
				am_smc_notify( BC_SC_REMOVED );
			} else if ( status == AM_SMC_CARD_IN ) {
				CA_DEBUG( 2, "cmd k_ConnectSc, smc status is : in" );
				am_smc_notify( BC_SC_INSERTED );
			} else {
				am_smc_notify( BC_SC_REMOVED );
				CA_DEBUG( 2, "cmd k_ConnectSc, smc status %d", status);
			}
		}
		break;
	case k_DisconnectSc:
		CA_DEBUG( 2, "@@call %s cmd:k_DisconnectSc", __FUNCTION__ );
		am_smc_notify = NULL;

		break;
	case k_ResetSc:
		CA_DEBUG( 2, "@@call %s cmd:k_ResetSc", __FUNCTION__ );
		g_smc_info.i_atr_len = 33;
		memset( g_smc_info.i_atr_buf, 0, sizeof( g_smc_info.i_atr_buf ) );
		AM_SMC_Reset( SMC_DEV_NO, g_smc_info.i_atr_buf, &g_smc_info.i_atr_len );
		CA_DEBUG( 3, "smc get reset len:%d, data:", g_smc_info.i_atr_len );
		int i = 0;
		for ( i = 0; i < g_smc_info.i_atr_len; i++ ) {
			CA_DEBUG( 3, "%#x", g_smc_info.i_atr_buf[i] );
		}
		AM_SMC_GetCardStatus( SMC_DEV_NO, &status );
		if ( status == AM_SMC_CARD_IN ) {
			am_smc_notify( BC_SC_RESET );
		}
		break;
	case k_GetATRSc:
		CA_DEBUG( 2, "@@call %s cmd:k_GetATRSc", __FUNCTION__ );
		memcpy( ( uint8_t * ) pvParams, g_smc_info.i_atr_buf, g_smc_info.i_atr_len );
		*pwLen = g_smc_info.i_atr_len;
		break;
	case k_CardDetectSc:
		CA_DEBUG( 2, "@@call %s cmd:k_CardDetectSc", __FUNCTION__ );
		AM_SMC_GetCardStatus( SMC_DEV_NO, &status );

		if ( status == AM_SMC_CARD_OUT ) {
			CA_DEBUG( 2, "cmd k_CardDetectSc, smc status is : out" );
			am_smc_notify( BC_SC_REMOVED );
		} else if ( status == AM_SMC_CARD_IN ) {
			CA_DEBUG( 2, "cmd k_CardDetectSc, smc status is : in" );
			am_smc_notify( BC_SC_INSERTED );
		}

		break;
	default:
		CA_DEBUG( 1, "@@call %s, unsupport cmd", __FUNCTION__ );
		break;
	}
	return k_BcSuccess;
}
