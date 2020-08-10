/***************************************************************************
 * Copyright (c) 2014 Amlogic, Inc. All rights reserved.
 *
 * This source code is subject to the terms and conditions defined in the
 * file 'LICENSE' which is part of this source code package.
 *
 * Description:
 */
/**\file
 * \brief 智能卡模块内部头文件
 *
 * \author Gong Ke <ke.gong@amlogic.com>
 * \date 2010-06-30: create the document
 ***************************************************************************/

#ifndef _AM_SMC_INTERNAL_H
#define _AM_SMC_INTERNAL_H

#include <am_smc.h>

#ifdef __cplusplus
extern "C"
{
#endif

/****************************************************************************
 * Macro definitions
 ***************************************************************************/
#define SMC_FL_RUN_CB    (1)

/****************************************************************************
 * Type definitions
 ***************************************************************************/

typedef struct AM_SMC_Device AM_SMC_Device_t;

/**\brief 智能卡设备驱动*/
typedef struct
{
	int (*open) (AM_SMC_Device_t *dev, const AM_SMC_OpenPara_t *para);
	int (*close) (AM_SMC_Device_t *dev);
	int (*get_status) (AM_SMC_Device_t *dev, AM_SMC_CardStatus_t *status);
	int (*reset) (AM_SMC_Device_t *dev, uint8_t *atr, int *len);
	int (*read) (AM_SMC_Device_t *dev, uint8_t *data, int *len, int timeout);
	int (*write) (AM_SMC_Device_t *dev, const uint8_t *data, int *len, int timeout);
	int (*get_param) (AM_SMC_Device_t *dev, AM_SMC_Param_t *para);
	int (*set_param) (AM_SMC_Device_t *dev, const AM_SMC_Param_t *para);
	int (*active) (AM_SMC_Device_t *dev);
	int (*deactive) (AM_SMC_Device_t *dev);
	int (*parse_atr)(AM_SMC_Device_t *dev, uint8_t *atr, int len);

} AM_SMC_Driver_t;

/**\brief 智能卡设备*/
struct AM_SMC_Device
{
	int              dev_no;        /**< 输入设备号*/
	const AM_SMC_Driver_t *drv;     /**< 驱动指针*/
	void            *drv_data;      /**< 驱动私有数据*/
	uint8_t        openned;       /**< 设备已经打开*/
	uint8_t        enable_thread; /**< 状态检测线程是否已经打开*/
	pthread_t        status_thread; /**< 状态检测线程*/
	pthread_mutex_t  lock;          /**< 设备数据保护互斥体*/
	pthread_cond_t   cond;          /**< 设备状态条件变量*/
	int              flags;         /**< 设备状态*/
	AM_SMC_StatusCb_t cb;           /**< 状态检测回调函数*/
	void            *user_data;     /**< 回调函数用户数据*/
};


/****************************************************************************
 * Function prototypes  
 ***************************************************************************/


#ifdef __cplusplus
}
#endif

#endif

