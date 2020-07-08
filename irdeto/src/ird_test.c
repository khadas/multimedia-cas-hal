#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

#include "ird_cas.h"


static uint8_t g_SampleCat[] = {0x01,0xB0,0x0F,0xFF,0xFF,0xC1,0x00,0x00,0x09,0x04,0x06,0x25,0xE5,0x00,0x4A,0x71,0x21,0x4B};
static uint8_t g_SamplePmt[] = {0x02,0xB0,0x1D,0x01,0x02,0xC1,0x00,0x00,0xE2,0x10,0xF0,0x06,0x09,0x04,0x06,0x25,0xE2,0x12,0x02,0xE2,0x10,0xF0,0x00,0x04,0xE2,0x11,0xF0,0x00,0x75,0x29,0xC9,0x1D};

int main(int argc, char* argv[])
{
	Ird_status_t result = IRD_NO_ERROR;
	int index = 0;

	char test_msg[64];


	for (index = 0; index < 10; index++)
	{
		memset(test_msg, 0x00, 64);
		sprintf(test_msg, "This is test message%d", index);
		result = ird_mail_save(MAIL_TYPE_MAILBOX, MAIL_PRIORITY_FORCED, test_msg, strlen(test_msg));
		printf("ird_mail_save(%d), result = %d\n", index, result);
	}


	int count = 0;
	mail_detail_st *p_mail_list = NULL;

	ird_mail_read_all(&count, &p_mail_list);
	for (index = 0; index < count; index++)
	{
		printf("content: %s\n", p_mail_list[index].content);
	}

	ird_mail_read_free(&p_mail_list);

#if 0

	mail_detail_st read;
	ird_mail_read_by_index(4, &read, 1);

	printf("content: %d\n", read.index);
	printf("content: %s\n", read.content);

	ird_mail_delete_by_index(5);


	ird_mail_delete_all();
#endif



#if 0

    ird_client_init();
	ird_client_start();

	sleep(5);

	ird_open_service();
	ird_process_cat(g_SampleCat, sizeof(g_SampleCat));
	ird_process_pmt(g_SamplePmt, sizeof(g_SamplePmt));

	sleep(5);

	while (1)
	{
		service_type_st stService;
		int index = 0;

		AM_APP_GetAllService(&stService);
		for (index = 0; index < stService.count; index++)
		{
			service_status_st service_status;

			printf("Service handle: 0x%08x, name: %s\n", stService.item[index].serviceHandle, stService.item[index].serviceName);
			AM_APP_GetServiceStatus(stService.item[index].serviceHandle, &service_status);
			printf("Service handle: 0x%08x, status: %s\n", service_status.serviceHandle, service_status.serviceStatus);
			for (int idx = 0; idx < service_status.streamCount ; idx++)
			{
				printf("%s\n", service_status.streamMsg[idx]);
			}

			AM_APP_FreeServiceStatus(service_status);

			printf("\n");
		}

		printf("\n\n");

		uint32_t nCount;
		product_status_st *pProdcutStatus;
		AM_APP_GetProductStatus(&nCount, &pProdcutStatus);
		printf("count: %d\n", nCount);
		for (index = 0; index < nCount; index++)
		{
			printf("%d  %04d  %s  %d  %s  %s  0x%04x  %s\n", pProdcutStatus[index].sectorNumber, pProdcutStatus[index].productID, \
						pProdcutStatus[index].startDate, pProdcutStatus[index].durationDay, pProdcutStatus[index].entitled, \
						pProdcutStatus[index].productType, pProdcutStatus[index].CASystemID, pProdcutStatus[index].source);
		}

		printf("\n\n");

		client_status_st stClientStatus;
		AM_APP_GetClientStatus(&stClientStatus);

		printf("Cloaked CA Agent version: %s\nBuild: %s\n", stClientStatus.agentVersion, stClientStatus.build);
		printf("CSSN: 0x%08x, Lock ID: %x, Secure Type: %s\n", stClientStatus.cssn, stClientStatus.lockID, stClientStatus.secureType);
		printf("\nClinet ID:\n");
		for (index = 0; index < stClientStatus.nClientIDCount; index++)
		{
			printf("%s\n", stClientStatus.clientID[index]);
		}

		printf("\nSN:\n");
		for (index = 0; index < stClientStatus.nSnCount; index++)
		{
			printf("%s\n", stClientStatus.sn[index]);
		}

		printf("\nNationality:\n");
		for (index = 0; index < stClientStatus.nNationalityCount; index++)
		{
			printf("%s\n", stClientStatus.nationality[index]);
		}

		printf("\nTMS Data:\n");
		for (index = 0; index < stClientStatus.nTmsDataCount; index++)
		{
			printf("%s\n", stClientStatus.tmsData[index]);
		}

		printf("\nSection Count:\n");
		for (index = 0; index < stClientStatus.nSectionCount; index++)
		{
			printf("%s\n", stClientStatus.section[index]);
		}

		printf("\n");
		printf("Secure Core: %s\n", stClientStatus.secureCore);
		printf("Download Status: %s\n", stClientStatus.downloadStatus);
		printf("FlexiCore: %s\n", stClientStatus.flexiCore);
		printf("FlexiCore Download Status: %s\n", stClientStatus.flexiCoreDownload);

		printf("\nCapabilities:\n%s\n", stClientStatus.Capabilities);

		sleep(3);
	}
#endif
	sleep(10000);

    return 0;
}
