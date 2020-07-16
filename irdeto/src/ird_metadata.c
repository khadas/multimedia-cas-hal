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
#include <sys/un.h>
#include <list.h>

#include "UniversalClient_Types.h"
#include "am_cas.h"
#include "ird_cas_internal.h"

typedef struct
{
    struct list_head list;
    uint64_t start;
    uint64_t end;
    uint32_t info_len;
    uint8_t *info_data;
} IRD_Metadata_storeinfo_t;

typedef struct
{
	int 					bUsed;
	uc_service_handle		serviceHandle;
    uc_uint32 	length;
    uc_byte 	*pdata;
} IRD_Metadata_Message_st;

typedef struct
{
	int 					bUsed;
	uc_service_handle		serviceHandle;
	IRD_Metadata_PVRCryptoPara_t 	stRecordCryptoPara;
	IRD_Metadata_storeinfo_t 		*pststoreinfolist;
	IRD_Metadata_storeinfo_t 		*pstfirststoreinfo;
} IRD_Metadata_StoreInfoManage_st;

#define METADATA_INFO_LEVEL		0
#define METADATA_ERROR_LEVEL	0
#define MAX_RECORD_HANDLE_NUM (5)
#define IRD_METADATA_MAGIC_NUM           0xFFFFFFFFFFFFFFFF

static int ird_metadata_syncdata = 0x55667788;
static pthread_mutex_t metadata_stroeinfo_lock = PTHREAD_MUTEX_INITIALIZER;
//signal playback
static IRD_Metadata_StoreInfoManage_st g_CurPlaybackCryptoParamHandle;
static uint64_t g_CurMetadataStart = IRD_METADATA_MAGIC_NUM;
static uint64_t g_CurMetadataEnd = IRD_METADATA_MAGIC_NUM;
static uc_service_handle g_hCurServiceHandle = AML_NULL;
//multiple record
static IRD_Metadata_StoreInfoManage_st g_CurRecordCryptoParamHandle[MAX_RECORD_HANDLE_NUM];

//save first metadata
static IRD_Metadata_Message_st g_stFirstMetadataMessage;

#define IRD_Metadata_LOCK() pthread_mutex_lock(&metadata_stroeinfo_lock);
#define IRD_Metadata_UNLOCK()  pthread_mutex_unlock(&metadata_stroeinfo_lock)

static Ird_status_t ird_metadata_GetCurPlaybackStoreInfo(uc_service_handle hServiceHandle,
								IRD_Metadata_PVRCryptoPara_t *pstRecordCryptoPara,
								IRD_Metadata_StoreInfoManage_st **ppstPVRStoreInfoManage);
static Ird_status_t ird_metadata_GetCurRecordCryptoIndex(uc_service_handle hServiceHandle, unsigned int *pIndex);


static Ird_status_t ird_metadata_GetFilename(char *pDestfname, const char *pSrclocation, int segment_id)
{
    int offset;

	if ((pDestfname == AML_NULL) || (pSrclocation == AML_NULL))
	{
		CA_DEBUG(METADATA_ERROR_LEVEL, "[%s]Invaild parameter pDestfname: 0x%p, pSrclocation = 0x%p\n", __FUNCTION__, pDestfname, pSrclocation);
		return IRD_INVALID_PARAMETER;
	}

    memset(pDestfname, 0, MAX_LOCATION_SIZE);
    strncpy(pDestfname, pSrclocation, strlen(pSrclocation));
    offset = strlen(pSrclocation);
    strncpy(pDestfname + offset, "-", 1);
    offset += 1;
    sprintf(pDestfname + offset, "%04d", segment_id);
    offset += 4;
    strncpy(pDestfname + offset, ".ird.dat", 8);

	CA_DEBUG(METADATA_INFO_LEVEL, "[%s]success, pDestfname is %s, pSrclocation=%s, segment_id=%d!\n", __FUNCTION__, pDestfname, pSrclocation, segment_id);
    return IRD_NO_ERROR;
}

static Ird_status_t ird_metadata_AllocCurRecordCryptoIndex(uc_service_handle	hServiceHandle, unsigned int *pIndex)
{
	int i = 0;

	if ((hServiceHandle == AML_NULL) || (pIndex == AML_NULL))
	{
		CA_DEBUG(METADATA_ERROR_LEVEL, "[%s]Invaild parameter hServiceHandle: %d\n", __FUNCTION__, hServiceHandle);
		return IRD_INVALID_PARAMETER;
	}

	for (i = 0; i < MAX_RECORD_HANDLE_NUM; i++)
	{
		if (g_CurRecordCryptoParamHandle[i].bUsed == ird_false)
		{
			g_CurRecordCryptoParamHandle[i].bUsed = ird_true;
			g_CurRecordCryptoParamHandle[i].serviceHandle = hServiceHandle;
			*pIndex = i;
			CA_DEBUG(METADATA_INFO_LEVEL, "[%s]success, serviceHandle:0x%x, index:%d!\n", __FUNCTION__, hServiceHandle, i);
			return IRD_NO_ERROR;
		}
	}

	if (i >= MAX_RECORD_HANDLE_NUM)
	{
		CA_DEBUG(METADATA_ERROR_LEVEL, "[%s]no free Record Crypto Param Handle,hServiceHandle:0x%x!", __FUNCTION__, hServiceHandle);
	}

    return IRD_FAILURE;
}

static Ird_status_t ird_metadata_FreesStoreInfoList(IRD_Metadata_storeinfo_t 		*pststoreinfolist)
{
	struct list_head *pos, *q;
	IRD_Metadata_storeinfo_t *pstoreinfo;

	if (pststoreinfolist == AML_NULL)
	{
		CA_DEBUG(METADATA_ERROR_LEVEL, "[%s] invalid parameter\n", __FUNCTION__);
		return IRD_INVALID_PARAMETER;
	}

	CA_DEBUG(METADATA_INFO_LEVEL, "[%s]free, pststoreinfolist:%p, list = %p!\n", __FUNCTION__, pststoreinfolist, pststoreinfolist->list);
	{
		list_for_each_safe(pos, q, &pststoreinfolist->list) {
			pstoreinfo = list_entry(pos, IRD_Metadata_storeinfo_t, list);
			CA_DEBUG(METADATA_INFO_LEVEL, "[%s]offset:%llu, len:%d", __FUNCTION__, pstoreinfo->start, pstoreinfo->info_len);
			list_del(pos);
			free(pstoreinfo->info_data);
			pstoreinfo->info_data = AML_NULL;
			free(pstoreinfo);
			pstoreinfo = AML_NULL;
		}
	}

	free(pststoreinfolist);
	pststoreinfolist = AML_NULL;
	CA_DEBUG(METADATA_INFO_LEVEL, "[%s]success!\n", __FUNCTION__);
	return IRD_NO_ERROR;
}

static Ird_status_t ird_metadata_GetStoreInfoFromFile(uc_service_handle hServiceHandle, IRD_Metadata_PVRCryptoPara_t *pstRecordCryptoPara)
{
	Ird_status_t	IrdRet = IRD_NO_ERROR;
	FILE *fp = AML_NULL;
	char		fileName[MAX_LOCATION_SIZE];
	IRD_Metadata_storeinfo_t *pstoreinfo;
	int syncdata;
	loff_t offset;
	uc_uint32 metadataLen;
	uc_byte *pMetadataData = AML_NULL;

	if ((pstRecordCryptoPara == AML_NULL) || (hServiceHandle == AML_NULL))
	{
		CA_DEBUG(METADATA_ERROR_LEVEL, "[%s] invalid parameter,pstRecordCryptoPara=%p, hServiceHandle:0x%x\n", __FUNCTION__, pstRecordCryptoPara, hServiceHandle);
		return IRD_INVALID_PARAMETER;
	}

	CA_DEBUG(METADATA_INFO_LEVEL, "[%s]hServiceHandle:0x%x, segment_id = %d, location = %s!", __FUNCTION__, hServiceHandle,
									pstRecordCryptoPara->segment_id, pstRecordCryptoPara->location);

	IrdRet = ird_metadata_GetFilename(fileName, pstRecordCryptoPara->location, pstRecordCryptoPara->segment_id);
	if (IrdRet != IRD_NO_ERROR)
	{
		CA_DEBUG(METADATA_ERROR_LEVEL, "[%s]call ird_metadata_GetFilename error!", __FUNCTION__);
		return IRD_FAILURE;
	}

	pstoreinfo = malloc(sizeof(IRD_Metadata_storeinfo_t));
	if (pstoreinfo == AML_NULL)
	{
		CA_DEBUG(METADATA_ERROR_LEVEL, "[%s]malloc error!", __FUNCTION__);
		return IRD_FAILURE;
	}

	memset(pstoreinfo, 0, sizeof(IRD_Metadata_storeinfo_t));
	g_CurPlaybackCryptoParamHandle.pststoreinfolist = pstoreinfo;

	CA_DEBUG(METADATA_INFO_LEVEL, "[%s]init store list, store info list:0x%p!\n", __FUNCTION__, g_CurPlaybackCryptoParamHandle.pststoreinfolist);
	INIT_LIST_HEAD(&g_CurPlaybackCryptoParamHandle.pststoreinfolist->list);
	g_CurPlaybackCryptoParamHandle.pstfirststoreinfo = AML_NULL;
	g_CurPlaybackCryptoParamHandle.stRecordCryptoPara.segment_id = pstRecordCryptoPara->segment_id;
	memcpy(g_CurPlaybackCryptoParamHandle.stRecordCryptoPara.location, pstRecordCryptoPara->location, MAX_LOCATION_SIZE);
	g_CurPlaybackCryptoParamHandle.serviceHandle = hServiceHandle;
	g_CurPlaybackCryptoParamHandle.bUsed = ird_true;

	CA_DEBUG(METADATA_INFO_LEVEL, "[%s]fileName = %s!\n", __FUNCTION__, fileName);
	fp = fopen(fileName, "rb+");
	if (fp == AML_NULL)
	{
		CA_DEBUG(METADATA_ERROR_LEVEL, "[%s]fopen fileName = %s is error!", __FUNCTION__, fileName);
		return IRD_FAILURE;
	}

	do {
		if (sizeof(ird_metadata_syncdata) != fread(&syncdata, 1, sizeof(ird_metadata_syncdata), fp))
		{
			CA_DEBUG(0, "[%s]read sync data error!", __FUNCTION__);
			break;
		}

		if (ird_metadata_syncdata != syncdata)
		{
			CA_DEBUG(0, "[%s]sync data error!", __FUNCTION__);
			continue;
		}

		if (sizeof(loff_t) != fread(&offset, 1, sizeof(loff_t), fp))
		{
			CA_DEBUG(0, "[%s]read Crypto Para error!", __FUNCTION__);
			break;
		}

		{//Set the end time of the previous metadata
			struct list_head *pos;
			IRD_Metadata_storeinfo_t *pTempstoreinfo;

			list_for_each_prev(pos, &g_CurPlaybackCryptoParamHandle.pststoreinfolist->list) {
				pTempstoreinfo = list_entry(pos, IRD_Metadata_storeinfo_t, list);
				pTempstoreinfo->end = offset;
				CA_DEBUG(METADATA_INFO_LEVEL, "[%s]start:%llu, end:%llu, len:%d", __FUNCTION__, pTempstoreinfo->start, pTempstoreinfo->end, pTempstoreinfo->info_len);
				break;
			}
		}

		if (sizeof(uc_uint32) != fread(&metadataLen, 1, sizeof(uc_uint32), fp))
		{
			CA_DEBUG(0, "[%s]read metadata len error!", __FUNCTION__);
			break;
		}

		pMetadataData = malloc(metadataLen);
		pstoreinfo = malloc(sizeof(IRD_Metadata_storeinfo_t));
		if ((pstoreinfo == AML_NULL) || (pMetadataData == AML_NULL))
		{
			CA_DEBUG(0, "[%s]malloc error!", __FUNCTION__);
			break;
		}

		memset(pMetadataData, 0, sizeof(metadataLen));
		memset(pstoreinfo, 0, sizeof(IRD_Metadata_storeinfo_t));
		pstoreinfo->info_data = pMetadataData;
		pstoreinfo->info_len = metadataLen;
		pstoreinfo->start = offset;
		pstoreinfo->end = IRD_METADATA_MAGIC_NUM;

		if (fread(pMetadataData, 1, metadataLen, fp) != metadataLen) {
			CA_DEBUG(0, "[%s]read metadata data error!", __FUNCTION__);
			break;
		}

		if (g_CurPlaybackCryptoParamHandle.pstfirststoreinfo == AML_NULL)
		{
			g_CurPlaybackCryptoParamHandle.pstfirststoreinfo = pstoreinfo;
		}

		CA_DEBUG(METADATA_INFO_LEVEL, "[%s]find metadata len:%d, offset:%llu", __FUNCTION__, pstoreinfo->info_len, pstoreinfo->start);
		list_add_tail(&pstoreinfo->list, &g_CurPlaybackCryptoParamHandle.pststoreinfolist->list);
	} while(1);

	fclose(fp);
	CA_DEBUG(METADATA_INFO_LEVEL, "[%s]success!\n", __FUNCTION__);
	return IRD_NO_ERROR;
}

static Ird_status_t ird_metadata_GetCurPlaybackStoreInfo(uc_service_handle hServiceHandle,
								IRD_Metadata_PVRCryptoPara_t *pstRecordCryptoPara,
								IRD_Metadata_StoreInfoManage_st **ppstPVRStoreInfoManage)
{
	int i = 0;
	Ird_status_t	IrdRet = IRD_NO_ERROR;

	if ((hServiceHandle == AML_NULL) || (pstRecordCryptoPara == AML_NULL) || (ppstPVRStoreInfoManage == AML_NULL))
	{
		CA_DEBUG(METADATA_ERROR_LEVEL, "[%s]Invaild parameter hServiceHandle: %d\n", __FUNCTION__, hServiceHandle);
		return IRD_INVALID_PARAMETER;
	}

	for (i = 0; i < MAX_RECORD_HANDLE_NUM; i++)
	{
		if ((g_CurRecordCryptoParamHandle[i].bUsed == ird_true)
			&& (g_CurRecordCryptoParamHandle[i].stRecordCryptoPara.segment_id == pstRecordCryptoPara->segment_id)
			&& (!strcmp(g_CurRecordCryptoParamHandle[i].stRecordCryptoPara.location, pstRecordCryptoPara->location)))
		{
			CA_DEBUG(METADATA_INFO_LEVEL, "[%s]success, from record get metadata, hServiceHandle:0x%x, index:%d!\n", __FUNCTION__, hServiceHandle, i);
			*ppstPVRStoreInfoManage = &g_CurRecordCryptoParamHandle[i];
			return IRD_NO_ERROR;
		}
	}

	if (g_CurPlaybackCryptoParamHandle.bUsed == ird_true)
	{
		if ((g_CurPlaybackCryptoParamHandle.serviceHandle == hServiceHandle)
			&& (g_CurPlaybackCryptoParamHandle.stRecordCryptoPara.segment_id == pstRecordCryptoPara->segment_id)
				&& (!strcmp(g_CurPlaybackCryptoParamHandle.stRecordCryptoPara.location, pstRecordCryptoPara->location)))
		{
			CA_DEBUG(METADATA_INFO_LEVEL, "[%s]success, from playback get metadata, hServiceHandle:0x%x!\n", __FUNCTION__, hServiceHandle);
			*ppstPVRStoreInfoManage = &g_CurPlaybackCryptoParamHandle;
			return IRD_NO_ERROR;
		}
		else
		{
			CA_DEBUG(METADATA_INFO_LEVEL, "[%s]reset Previously obtained metadata info!", __FUNCTION__);
			if (g_CurPlaybackCryptoParamHandle.pststoreinfolist != AML_NULL)
			{
				IrdRet = ird_metadata_FreesStoreInfoList(g_CurPlaybackCryptoParamHandle.pststoreinfolist);
				if (IrdRet != IRD_NO_ERROR)
				{
					CA_DEBUG(METADATA_ERROR_LEVEL, "[%s]call ird_metadata_FreesStoreInfoList is error!", __FUNCTION__);
				}
			}

			memset(&g_CurPlaybackCryptoParamHandle, 0, sizeof(IRD_Metadata_StoreInfoManage_st));
		}
	}

	CA_DEBUG(METADATA_INFO_LEVEL, "[%s]get matched info from file!\n", __FUNCTION__);
	IrdRet = ird_metadata_GetStoreInfoFromFile(hServiceHandle, pstRecordCryptoPara);
	if (IrdRet != IRD_NO_ERROR)
	{
		CA_DEBUG(METADATA_ERROR_LEVEL, "[%s]call ird_metadata_GetStoreInfoFromFile is error!", __FUNCTION__);
		return IRD_FAILURE;
	}

	*ppstPVRStoreInfoManage = &g_CurPlaybackCryptoParamHandle;

	CA_DEBUG(METADATA_INFO_LEVEL, "[%s]success!\n", __FUNCTION__);
	return IRD_NO_ERROR;
}

static Ird_status_t ird_metadata_GetCurRecordCryptoIndex(uc_service_handle hServiceHandle, unsigned int *pIndex)
{
	int i = 0;

	for (i = 0; i < MAX_RECORD_HANDLE_NUM; i++)
	{
		if ((g_CurRecordCryptoParamHandle[i].serviceHandle == hServiceHandle) && (g_CurRecordCryptoParamHandle[i].bUsed == ird_true))
		{
			*pIndex = i;
			CA_DEBUG(METADATA_INFO_LEVEL, "[%s]success, serviceHandle:0x%x, index:%d!\n", __FUNCTION__, hServiceHandle, i);
			return IRD_NO_ERROR;
		}
	}

	if (i >= MAX_RECORD_HANDLE_NUM)
	{
		CA_DEBUG(METADATA_ERROR_LEVEL, "[%s]no matched Handle, hServiceHandle:0x%x!", __FUNCTION__, hServiceHandle);
	}

	return IRD_FAILURE;
}

Ird_status_t ird_metadata_ResetPVRStoreInfo(uc_service_handle hServiceHandle)
{
	Ird_status_t	IrdRet = IRD_NO_ERROR;
	unsigned int u32index = 0;
	IRD_Metadata_StoreInfoManage_st *pstPVRStoreInfoManage = AML_NULL;

	if (hServiceHandle == AML_NULL)
	{
		CA_DEBUG(METADATA_ERROR_LEVEL, "[%s]Invaild parameter\n", __FUNCTION__);
		return IRD_INVALID_PARAMETER;
	}

	IrdRet = ird_metadata_GetCurRecordCryptoIndex(hServiceHandle, &u32index);
	if (IrdRet == IRD_NO_ERROR)
	{
		pstPVRStoreInfoManage = &g_CurRecordCryptoParamHandle[u32index];
	}
	else
	{
		if (g_CurPlaybackCryptoParamHandle.serviceHandle == hServiceHandle)
		{
			pstPVRStoreInfoManage = &g_CurPlaybackCryptoParamHandle;
		}
	}

	if (AML_NULL != pstPVRStoreInfoManage)
	{
		if (AML_NULL != pstPVRStoreInfoManage->pststoreinfolist)
		{
			IrdRet = ird_metadata_FreesStoreInfoList(pstPVRStoreInfoManage->pststoreinfolist);
			if (IrdRet != IRD_NO_ERROR)
			{
				CA_DEBUG(METADATA_ERROR_LEVEL, "[%s]call ird_metadata_FreesStoreInfoList is error!", __FUNCTION__);
			}
		}

		memset(pstPVRStoreInfoManage, 0, sizeof(IRD_Metadata_StoreInfoManage_st));
	}

	if (g_hCurServiceHandle == hServiceHandle)
	{
		g_CurMetadataStart = IRD_METADATA_MAGIC_NUM;
		g_CurMetadataEnd = IRD_METADATA_MAGIC_NUM;
	}

	CA_DEBUG(METADATA_INFO_LEVEL, "[%s]success!\n", __FUNCTION__);
	return IRD_NO_ERROR;
}

Ird_status_t ird_metadata_SaveStoreInfoToFile(uc_service_handle	hServiceHandle, uc_uint32 u32Len, uc_byte *pData)
{
	Ird_status_t	IrdRet = IRD_NO_ERROR;
	unsigned int index = 0;
	char		fileName[MAX_LOCATION_SIZE];
	FILE *fp = AML_NULL;
	IRD_Metadata_storeinfo_t *pstoreinfo;
	uc_byte *pMetadataData = AML_NULL;

	CA_DEBUG(METADATA_INFO_LEVEL, "[%s]hServiceHandle:0x%x, u32Len:%d!\n", __FUNCTION__, hServiceHandle, u32Len);

	if ((hServiceHandle == AML_NULL) || (u32Len == 0) || (pData == AML_NULL))
	{
		CA_DEBUG(METADATA_ERROR_LEVEL, "[%s]Invaild parameter hServiceHandle: 0x%xï¼?u32Len = %d, pData = 0x%p\n", __FUNCTION__, hServiceHandle, u32Len, pData);
		return IRD_FAILURE;
	}

	IRD_Metadata_LOCK();
	IrdRet = ird_metadata_GetCurRecordCryptoIndex(hServiceHandle, &index);
	if (IrdRet != IRD_NO_ERROR)
	{
		CA_DEBUG(METADATA_INFO_LEVEL, "[%s]hServiceHandle = %d no matched service handle!", __FUNCTION__, hServiceHandle);
		if (g_stFirstMetadataMessage.bUsed == ird_true)
		{
			if (g_stFirstMetadataMessage.pdata != AML_NULL)
			{
				free(g_stFirstMetadataMessage.pdata);
				g_stFirstMetadataMessage.pdata = AML_NULL;
				CA_DEBUG(METADATA_ERROR_LEVEL, "[%s]error, lost metadata info!", __FUNCTION__);
			}
		}

		{
			g_stFirstMetadataMessage.bUsed = ird_true;
			g_stFirstMetadataMessage.serviceHandle = hServiceHandle;
			g_stFirstMetadataMessage.length = u32Len;
			g_stFirstMetadataMessage.pdata = malloc(u32Len);
			if (g_stFirstMetadataMessage.pdata == AML_NULL)
			{
				CA_DEBUG(METADATA_ERROR_LEVEL, "[%s]malloc error!", __FUNCTION__);
				IRD_Metadata_UNLOCK();
				return IRD_FAILURE;
			}
			memset(g_stFirstMetadataMessage.pdata, 0, sizeof(u32Len));
			memcpy(g_stFirstMetadataMessage.pdata, pData, u32Len);
		}

		IRD_Metadata_UNLOCK();
		return IRD_FAILURE;
	}

	//add metadata info to list
	if (g_CurRecordCryptoParamHandle[index].pststoreinfolist == AML_NULL)
	{
		pstoreinfo = malloc(sizeof(IRD_Metadata_storeinfo_t));
		if (pstoreinfo == AML_NULL)
		{
			CA_DEBUG(METADATA_ERROR_LEVEL, "[%s]malloc error!", __FUNCTION__);
			IRD_Metadata_UNLOCK();
			return IRD_FAILURE;
		}
		memset(pstoreinfo, 0, sizeof(IRD_Metadata_storeinfo_t));
		g_CurRecordCryptoParamHandle[index].pststoreinfolist = pstoreinfo;
		g_CurRecordCryptoParamHandle[index].pstfirststoreinfo = AML_NULL;
		CA_DEBUG(METADATA_INFO_LEVEL, "[%s]init store list, store info list:%p!\n", __FUNCTION__, g_CurRecordCryptoParamHandle[index].pststoreinfolist);
		INIT_LIST_HEAD(&g_CurRecordCryptoParamHandle[index].pststoreinfolist->list);
	}

	{//Set the end time of the previous metadata
		struct list_head *pos;
		IRD_Metadata_storeinfo_t *pTempstoreinfo;

		list_for_each_prev(pos, &g_CurRecordCryptoParamHandle[index].pststoreinfolist->list) {
			pTempstoreinfo = list_entry(pos, IRD_Metadata_storeinfo_t, list);
			pTempstoreinfo->end = g_CurRecordCryptoParamHandle[index].stRecordCryptoPara.offset;
			CA_DEBUG(METADATA_INFO_LEVEL, "[%s]start:%llu, end:%llu, len:%d", __FUNCTION__, pTempstoreinfo->start, pTempstoreinfo->end, pTempstoreinfo->info_len);
			break;
		}
	}

	pstoreinfo = malloc(sizeof(IRD_Metadata_storeinfo_t));
	if (pstoreinfo == AML_NULL)
	{
		CA_DEBUG(METADATA_ERROR_LEVEL, "[%s]malloc error!", __FUNCTION__);
		IRD_Metadata_UNLOCK();
		return IRD_FAILURE;
	}
	memset(pstoreinfo, 0, sizeof(IRD_Metadata_storeinfo_t));
	pMetadataData = malloc(u32Len);
	if (pMetadataData == AML_NULL)
	{
		CA_DEBUG(METADATA_ERROR_LEVEL, "[%s]malloc error!", __FUNCTION__);
		free(pstoreinfo);
		pstoreinfo = AML_NULL;
		IRD_Metadata_UNLOCK();
		return IRD_FAILURE;
	}
	memset(pMetadataData, 0, u32Len);
	pstoreinfo->info_len = u32Len;
	pstoreinfo->info_data = pMetadataData;
	memcpy(pMetadataData, pData, u32Len);
	pstoreinfo->start = g_CurRecordCryptoParamHandle[index].stRecordCryptoPara.offset;
	pstoreinfo->end = IRD_METADATA_MAGIC_NUM;

	if (g_CurRecordCryptoParamHandle[index].pstfirststoreinfo == AML_NULL)
	{
		g_CurRecordCryptoParamHandle[index].pstfirststoreinfo = pstoreinfo;
	}

	CA_DEBUG(METADATA_INFO_LEVEL, "[%s]add metadata len:%#x, offset:%llu, list = %p", __FUNCTION__, pstoreinfo->info_len,
				pstoreinfo->start, g_CurRecordCryptoParamHandle[index].pststoreinfolist->list);
	list_add_tail(&pstoreinfo->list, &g_CurRecordCryptoParamHandle[index].pststoreinfolist->list);

	//save metadata info to file.
	IrdRet = ird_metadata_GetFilename(fileName, g_CurRecordCryptoParamHandle[index].stRecordCryptoPara.location,
										g_CurRecordCryptoParamHandle[index].stRecordCryptoPara.segment_id);
	if (IrdRet != IRD_NO_ERROR)
	{
		CA_DEBUG(METADATA_ERROR_LEVEL, "[%s]call ird_metadata_GetFilename is error!", __FUNCTION__);
		return IRD_FAILURE;
	}

	CA_DEBUG(METADATA_INFO_LEVEL, "[%s]open file fileName = %s", __FUNCTION__, fileName);
	fp = fopen(fileName, "ab+");
	if (fp == AML_NULL)
	{
		CA_DEBUG(METADATA_ERROR_LEVEL, "fopen fileName = %s is error!", fileName);
		IRD_Metadata_UNLOCK();
		return IRD_FAILURE;
	}

	//sync data + offset + metadata len + metadata
	if (fwrite(&ird_metadata_syncdata, 1, sizeof(ird_metadata_syncdata), fp) != sizeof(ird_metadata_syncdata))
	{
		CA_DEBUG(METADATA_ERROR_LEVEL, "fwrite fail!!");
		fclose(fp);
		IRD_Metadata_UNLOCK();
		return IRD_FAILURE;
	}

	if (fwrite(&g_CurRecordCryptoParamHandle[index].stRecordCryptoPara.offset, 1, sizeof(loff_t), fp) != sizeof(loff_t))
	{
		CA_DEBUG(METADATA_ERROR_LEVEL, "fwrite fail!!");
		fclose(fp);
		IRD_Metadata_UNLOCK();
		return IRD_FAILURE;
	}

	if (fwrite(&u32Len, 1, sizeof(uc_uint32), fp) != sizeof(uc_uint32))
	{
		CA_DEBUG(METADATA_ERROR_LEVEL, "fwrite fail!!");
		fclose(fp);
		IRD_Metadata_UNLOCK();
		return IRD_FAILURE;
	}

	if (fwrite(pData, 1, u32Len, fp) != u32Len)
	{
		CA_DEBUG(METADATA_ERROR_LEVEL, "fwrite fail!!");
		fclose(fp);
		IRD_Metadata_UNLOCK();
		return IRD_FAILURE;
	}

	fflush(fp);
	fclose(fp);

	IRD_Metadata_UNLOCK();

	CA_DEBUG(METADATA_INFO_LEVEL, "[%s]success!\n", __FUNCTION__);
	return IRD_NO_ERROR;
}

Ird_status_t ird_metadata_SetRecordCryptoPara(uc_service_handle hServiceHandle, IRD_Metadata_PVRCryptoPara_t *pstRecordCryptoPara)
{
	unsigned int index = 0;
	Ird_status_t	IrdRet = IRD_NO_ERROR;

	if ((pstRecordCryptoPara == AML_NULL) || (hServiceHandle == AML_NULL))
	{
		CA_DEBUG(METADATA_ERROR_LEVEL, "[%s]Invaild parameter pstRecordCryptoPara: 0x%p, hServiceHandle = 0x%x\n", __FUNCTION__, pstRecordCryptoPara, hServiceHandle);
		return IRD_INVALID_PARAMETER;
	}

	CA_DEBUG(METADATA_INFO_LEVEL, "[%s]hServiceHandle:0x%x, segment_id:%d, offset = %llu!\n", __FUNCTION__, hServiceHandle, pstRecordCryptoPara->segment_id, pstRecordCryptoPara->offset);
	IRD_Metadata_LOCK();

	IrdRet = ird_metadata_GetCurRecordCryptoIndex(hServiceHandle, &index);
	if (IrdRet != IRD_NO_ERROR)
	{
		IrdRet = ird_metadata_AllocCurRecordCryptoIndex(hServiceHandle, &index);
		if (IrdRet != IRD_NO_ERROR)
		{
			CA_DEBUG(METADATA_ERROR_LEVEL, "hServiceHandle = %d has no matched service index!", hServiceHandle);
			IRD_Metadata_UNLOCK();
			return IRD_FAILURE;
		}
	}
	else
	{
		if ((g_CurRecordCryptoParamHandle[index].stRecordCryptoPara.segment_id != pstRecordCryptoPara->segment_id)
				|| (strcmp(g_CurRecordCryptoParamHandle[index].stRecordCryptoPara.location, pstRecordCryptoPara->location)))
		{
			CA_DEBUG(METADATA_INFO_LEVEL, "[%s]record param has changed, old segment_id:%d, new segment_id:%d!", __FUNCTION__,
						g_CurRecordCryptoParamHandle[index].stRecordCryptoPara.segment_id, pstRecordCryptoPara->segment_id);
			if (g_CurRecordCryptoParamHandle[index].pststoreinfolist != AML_NULL)
			{
				IrdRet = ird_metadata_FreesStoreInfoList(g_CurRecordCryptoParamHandle[index].pststoreinfolist);
				if (IrdRet != IRD_NO_ERROR)
				{
					CA_DEBUG(METADATA_ERROR_LEVEL, "[%s]call ird_metadata_FreesStoreInfoList is error!", __FUNCTION__);
				}
			}
			g_CurRecordCryptoParamHandle[index].pstfirststoreinfo = AML_NULL;
			g_CurRecordCryptoParamHandle[index].pststoreinfolist = AML_NULL;
		}
	}

	memcpy(&g_CurRecordCryptoParamHandle[index].stRecordCryptoPara, pstRecordCryptoPara, sizeof(IRD_Metadata_PVRCryptoPara_t));

	IRD_Metadata_UNLOCK();

	if ((g_stFirstMetadataMessage.bUsed == ird_true) && (hServiceHandle == g_stFirstMetadataMessage.serviceHandle))
	{
		IrdRet = ird_metadata_SaveStoreInfoToFile(hServiceHandle, g_stFirstMetadataMessage.length, g_stFirstMetadataMessage.pdata);
		if (IrdRet != IRD_NO_ERROR)
		{
			CA_DEBUG(METADATA_ERROR_LEVEL, "[%s]call ird_metadata_SaveStoreInfoToFile is error!", __FUNCTION__);
			return IRD_FAILURE;
		}

		if (g_stFirstMetadataMessage.pdata != AML_NULL)
		{
			free(g_stFirstMetadataMessage.pdata);
		}
		memset(&g_stFirstMetadataMessage, 0, sizeof(IRD_Metadata_Message_st));
	}

	CA_DEBUG(METADATA_INFO_LEVEL, "[%s]success, index = %d!\n", __FUNCTION__, index);
	return IRD_NO_ERROR;
}

Ird_status_t ird_metadata_SubmitPVRCryptoInfo(uc_service_handle hServiceHandle, IRD_Metadata_PVRCryptoPara_t *pstRecordCryptoPara)
{
	Ird_status_t	IrdRet = IRD_NO_ERROR;
	uc_buffer_st stPVRSessionMetadata;
	uc_result ucRet = UC_ERROR_SUCCESS;
	struct list_head *pos, *q;
	IRD_Metadata_storeinfo_t *pstoreinfo;
	IRD_Metadata_StoreInfoManage_st *pstPVRStoreInfoManage;

	if ((hServiceHandle == AML_NULL) || (pstRecordCryptoPara == AML_NULL))
	{
		CA_DEBUG(METADATA_ERROR_LEVEL, "[%s]Invaild parameter hServiceHandle: %d\n", __FUNCTION__, hServiceHandle);
		return IRD_INVALID_PARAMETER;
	}

	CA_DEBUG(METADATA_INFO_LEVEL, "[%s]hServiceHandle:0x%x, segment_id:%d!\n", __FUNCTION__, hServiceHandle, pstRecordCryptoPara->segment_id);
	IRD_Metadata_LOCK();
	CA_DEBUG(METADATA_INFO_LEVEL, "[%s]offset = %llu, g_CurMetadataStart = %llu, g_CurMetadataEnd = %llu!\n", __FUNCTION__, pstRecordCryptoPara->offset, g_CurMetadataStart, g_CurMetadataEnd);
	if ((hServiceHandle == g_hCurServiceHandle) && (pstRecordCryptoPara->offset >= g_CurMetadataStart)
			&& (pstRecordCryptoPara->offset < g_CurMetadataEnd) && (g_CurMetadataEnd != IRD_METADATA_MAGIC_NUM))
	{
		CA_DEBUG(METADATA_INFO_LEVEL, "[%s]This time interval has submitted metadata!\n", __FUNCTION__, hServiceHandle, pstRecordCryptoPara->segment_id);
		IRD_Metadata_UNLOCK();
		return IRD_NO_ERROR;
	}

	IrdRet = ird_metadata_GetCurPlaybackStoreInfo(hServiceHandle, pstRecordCryptoPara, &pstPVRStoreInfoManage);
	if (IrdRet != IRD_NO_ERROR)
	{
		CA_DEBUG(METADATA_ERROR_LEVEL, "[%s]call ird_metadata_GetCurPlaybackStoreInfo is error!", __FUNCTION__);
		IRD_Metadata_UNLOCK();
		return IRD_FAILURE;
	}

	if ((pstPVRStoreInfoManage != AML_NULL) && (pstPVRStoreInfoManage->pststoreinfolist != AML_NULL))
	{
		list_for_each_safe(pos, q, &pstPVRStoreInfoManage->pststoreinfolist->list) {
			pstoreinfo = list_entry(pos, IRD_Metadata_storeinfo_t, list);
				CA_DEBUG(METADATA_INFO_LEVEL, "[%s]offset:%llu, len:%d", __FUNCTION__, pstoreinfo->start, pstoreinfo->info_len);
				if (g_CurMetadataStart == pstoreinfo->start)
				{
					continue;
				}
				if ((pstRecordCryptoPara->offset >= pstoreinfo->start) && (pstRecordCryptoPara->offset < pstoreinfo->end)) {
					stPVRSessionMetadata.bytes = pstoreinfo->info_data;
					stPVRSessionMetadata.length = pstoreinfo->info_len;
					g_hCurServiceHandle = hServiceHandle;
					g_CurMetadataStart = pstoreinfo->start;
					g_CurMetadataEnd = pstoreinfo->end;
					CA_DEBUG(METADATA_INFO_LEVEL, "[%s]found metadata info, offset:%llu, len:%d", __FUNCTION__, pstoreinfo->start, pstoreinfo->info_len);
					ucRet = UniversalClient_SubmitPVRSessionMetadata(hServiceHandle, &stPVRSessionMetadata);
					if (ucRet != UC_ERROR_SUCCESS)
					{
						CA_DEBUG(METADATA_ERROR_LEVEL, "[%s]call UniversalClient_SubmitPVRSessionMetadata is error!", __FUNCTION__);
						IRD_Metadata_UNLOCK();
						return IRD_FAILURE;
					}
				}
		}
	}

	IRD_Metadata_UNLOCK();
	CA_DEBUG(METADATA_INFO_LEVEL, "[%s]success!\n", __FUNCTION__);
	return IRD_NO_ERROR;
}

Ird_status_t ird_metadata_SubmitFirstPVRCryptoInfo(uc_service_handle hServiceHandle, IRD_Metadata_PVRCryptoPara_t *pstRecordCryptoPara)
{
	Ird_status_t	IrdRet = IRD_NO_ERROR;
	uc_buffer_st stPVRSessionMetadata;
	uc_result ucRet = UC_ERROR_SUCCESS;
	struct list_head *pos, *q;
	IRD_Metadata_StoreInfoManage_st *pstPVRStoreInfoManage;

	if ((hServiceHandle == AML_NULL) || (pstRecordCryptoPara == AML_NULL))
	{
		CA_DEBUG(METADATA_ERROR_LEVEL, "[%s]Invaild parameter hServiceHandle: %d\n", __FUNCTION__, hServiceHandle);
		return IRD_INVALID_PARAMETER;
	}

	CA_DEBUG(METADATA_INFO_LEVEL, "[%s]hServiceHandle:0x%x, segment_id:%d!\n", __FUNCTION__, hServiceHandle, pstRecordCryptoPara->segment_id);
	IRD_Metadata_LOCK();
	IrdRet = ird_metadata_GetCurPlaybackStoreInfo(hServiceHandle, pstRecordCryptoPara, &pstPVRStoreInfoManage);
	if (IrdRet != IRD_NO_ERROR)
	{
		CA_DEBUG(METADATA_ERROR_LEVEL, "[%s]call ird_metadata_GetCurPlaybackStoreInfo is error!", __FUNCTION__);
		IRD_Metadata_UNLOCK();
		return IRD_FAILURE;
	}

	if ((pstPVRStoreInfoManage != AML_NULL) && (pstPVRStoreInfoManage->pstfirststoreinfo != AML_NULL))
	{
		memset(&stPVRSessionMetadata, 0, sizeof(uc_buffer_st));
		stPVRSessionMetadata.bytes = pstPVRStoreInfoManage->pstfirststoreinfo->info_data;
		stPVRSessionMetadata.length = pstPVRStoreInfoManage->pstfirststoreinfo->info_len;
		g_hCurServiceHandle = hServiceHandle;
		g_CurMetadataStart = pstPVRStoreInfoManage->pstfirststoreinfo->start;
		g_CurMetadataEnd = pstPVRStoreInfoManage->pstfirststoreinfo->end;
		CA_DEBUG(METADATA_INFO_LEVEL, "[%s]found first metadata info, offset:%llu, len:%d", __FUNCTION__, pstPVRStoreInfoManage->pstfirststoreinfo->start, pstPVRStoreInfoManage->pstfirststoreinfo->info_len);
		ucRet = UniversalClient_SubmitPVRSessionMetadata(hServiceHandle, &stPVRSessionMetadata);
		if (ucRet != UC_ERROR_SUCCESS)
		{
			CA_DEBUG(METADATA_ERROR_LEVEL, "[%s]call UniversalClient_SubmitPVRSessionMetadata is error!", __FUNCTION__);
			IRD_Metadata_UNLOCK();
			return IRD_FAILURE;
		}
	}

	IRD_Metadata_UNLOCK();
	CA_DEBUG(METADATA_INFO_LEVEL, "[%s]success!\n", __FUNCTION__);
	return IRD_NO_ERROR;
}

