#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/dvb/frontend.h>
#include "fend.h"

#define INVALID_FD        -1

static int dmd_set_prop(int fe_fd, const struct dtv_properties *prop)
{
  if (ioctl(fe_fd, FE_SET_PROPERTY, prop) == -1) {
     printf("set prop failed>>>>>>>>>>>>.\n");
     return -1;
  }
  return 0;
}

int dmd_lock_t(int fe_fd, const dmd_delivery_t * pDelivery)
{
   int tmp = 0;
   int cmd_num = 0;
   struct dtv_properties props;
   struct dtv_property p[DTV_IOCTL_MAX_MSGS];

   p[cmd_num].cmd = DTV_DELIVERY_SYSTEM;
   if (pDelivery->delivery.terrestrial.dvb_type == DMD_DVBTYPE_DVBT)
	 p[cmd_num].u.data = SYS_DVBT;
   else
	 p[cmd_num].u.data = SYS_DVBT2;
   cmd_num++;

   if (pDelivery->delivery.terrestrial.dvb_type == DMD_DVBTYPE_DVBT)
	 p[cmd_num].u.data = pDelivery->delivery.terrestrial.desc.dvbt.frequency * 1000;
   else
	 p[cmd_num].u.data = pDelivery->delivery.terrestrial.desc.dvbt2.frequency * 1000;

   p[cmd_num].cmd = DTV_FREQUENCY;
   cmd_num++;

   if (pDelivery->delivery.terrestrial.dvb_type == DMD_DVBTYPE_DVBT)
	 tmp = pDelivery->delivery.terrestrial.desc.dvbt.bandwidth;
   else
	 tmp = pDelivery->delivery.terrestrial.desc.dvbt2.bandwidth;
   p[cmd_num].cmd = DTV_BANDWIDTH_HZ;
   switch (tmp) {
   case DMD_BANDWIDTH_10M:
	 p[cmd_num].u.data = 10000000;
	 break;
   case DMD_BANDWIDTH_8M:
	 p[cmd_num].u.data = 8000000;
	 break;
   case DMD_BANDWIDTH_7M:
	 p[cmd_num].u.data = 7000000;
	 break;
   case DMD_BANDWIDTH_6M:
	 p[cmd_num].u.data = 6000000;
	 break;
   case DMD_BANDWIDTH_5M:
	 p[cmd_num].u.data = 5000000;
	 break;
   case DMD_BANDWIDTH_17M:
	 p[cmd_num].u.data = 1712000;
	 break;
   }
   cmd_num++;

   p[cmd_num].cmd = DTV_CODE_RATE_HP;
   p[cmd_num].u.data = FEC_AUTO;
   cmd_num++;

   p[cmd_num].cmd = DTV_CODE_RATE_LP;
   p[cmd_num].u.data = FEC_AUTO;
   cmd_num++;

   if (pDelivery->delivery.terrestrial.dvb_type == DMD_DVBTYPE_DVBT)
	 tmp = pDelivery->delivery.terrestrial.desc.dvbt.transmission_mode;
   else
	 tmp = pDelivery->delivery.terrestrial.desc.dvbt2.transmission_mode;
   if (tmp <= DMD_TRANSMISSION_8K)
	 tmp += -1;
   p[cmd_num].cmd = DTV_TRANSMISSION_MODE;
   p[cmd_num].u.data = tmp;
   cmd_num++;

   if (pDelivery->delivery.terrestrial.dvb_type == DMD_DVBTYPE_DVBT)
	 tmp = pDelivery->delivery.terrestrial.desc.dvbt.guard_interval;
   else
	 tmp = pDelivery->delivery.terrestrial.desc.dvbt2.guard_interval;
   if (tmp <= DMD_GUARD_INTERVAL_1_4)
	 tmp += -1;
   p[cmd_num].cmd = DTV_GUARD_INTERVAL;
   p[cmd_num].u.data = tmp;
   cmd_num++;

   if (pDelivery->delivery.terrestrial.dvb_type == DMD_DVBTYPE_DVBT) {
	 p[cmd_num].cmd = DTV_HIERARCHY;
	 p[cmd_num].u.data = HIERARCHY_AUTO;
	 cmd_num++;
   }
   if (pDelivery->delivery.terrestrial.dvb_type == DMD_DVBTYPE_DVBT2) {
	 p[cmd_num].cmd = DTV_DVBT2_PLP_ID_LEGACY;
	 p[cmd_num].u.data = pDelivery->delivery.terrestrial.desc.dvbt2.plp_id;
	 cmd_num++;
   }

   p[cmd_num].cmd = DTV_TUNE;
   cmd_num++;
   props.num = cmd_num;
   props.props = (struct dtv_property *)&p;

   return dmd_set_prop(fe_fd, &props);
}

int dmd_lock_c(int fe_fd, const dmd_delivery_t * pDelivery)
{
   int tmp = 0;
   int cmd_num = 0;
   struct dtv_properties props;
   struct dtv_property p[DTV_IOCTL_MAX_MSGS];

   p[cmd_num].cmd = DTV_DELIVERY_SYSTEM;
   p[cmd_num].u.data = SYS_DVBC_ANNEX_A;
   cmd_num++;
   p[cmd_num].cmd = DTV_FREQUENCY;
   p[cmd_num].u.data = pDelivery->delivery.cable.frequency * 1000;
   cmd_num++;

   p[cmd_num].cmd = DTV_SYMBOL_RATE;
   p[cmd_num].u.data = pDelivery->delivery.cable.symbol_rate * 1000;
   cmd_num++;

   tmp = pDelivery->delivery.cable.modulation;
   switch (tmp) {
   case DMD_MOD_NONE:
	 tmp = QAM_AUTO;
	 break;
   case DMD_MOD_QPSK:
	 tmp = QPSK;
	 break;
   case DMD_MOD_8PSK:
	 tmp = PSK_8;
	 break;
   case DMD_MOD_QAM:
	 tmp = QAM_AUTO;
	 break;
   case DMD_MOD_4QAM:
	 tmp = QAM_AUTO;
	 break;
   case DMD_MOD_16QAM:
	 tmp = QAM_16;
	 break;
   case DMD_MOD_32QAM:
	 tmp = QAM_32;
	 break;
   case DMD_MOD_64QAM:
	 tmp = QAM_64;
	 break;
   case DMD_MOD_128QAM:
	 tmp = QAM_128;
	 break;
   case DMD_MOD_256QAM:
	 tmp = QAM_256;
	 break;
   case DMD_MOD_BPSK:
   case DMD_MOD_ALL:
	 tmp = QAM_AUTO;
	 break;
   }
   p[cmd_num].cmd = DTV_MODULATION;
   p[cmd_num].u.data = tmp;
   cmd_num++;

   p[cmd_num].cmd = DTV_TUNE;
   cmd_num++;
   props.num = cmd_num;
   props.props = (struct dtv_property *)&p;

   return dmd_set_prop(fe_fd, &props);
}

int dmd_lock_s(int fe_fd, const dmd_delivery_t * pDelivery, dmd_lnb_tone_state_t tone_state, dmd_lnb_voltage_t vol)
{
   int cmd_num = 0;
   int code_rate = 0;
   fe_sec_tone_mode_t tone;
   fe_sec_voltage_t voltage;
   struct dtv_properties props;
   struct dtv_property p[DTV_IOCTL_MAX_MSGS];

   /*printf("lock S, freq:%d, symbol rate:%d, band start:%d Khz, end:%d Khz, LO:%d Khz, dowlink:%d\n",
	   pDelivery->delivery.satellite.frequency, pDelivery->delivery.satellite.symbol_rate,
	   pDelivery->delivery.satellite.band.band_start, pDelivery->delivery.satellite.band.band_end,
	   pDelivery->delivery.satellite.band.lo, pDelivery->delivery.satellite.band.downlink);*/

   switch (vol)
   {
      case DMD_LNB_VOLTAGE_14V:
        voltage = SEC_VOLTAGE_13;
        break;
      case DMD_LNB_VOLTAGE_18V:
        voltage = SEC_VOLTAGE_18;
        break;
      case DMD_LNB_VOLTAGE_OFF:
      default:
        voltage = SEC_VOLTAGE_OFF;
        break;
   }
   if (ioctl(fe_fd, FE_SET_VOLTAGE, voltage) == -1)
   {
       printf("ioctl FE_SET_VOLTAGE failed, fd:%d error:%d", fe_fd, errno);
   }

   /*Diseqc start*/
   printf("Diseqc, LNB tone:%d, port:%d\n",
	   pDelivery->delivery.satellite.lnb_tone_state,
	   pDelivery->delivery.satellite.diseqc_port);
   /*Diseqc end*/

   /*LNB TONE*/
   switch (pDelivery->delivery.satellite.lnb_tone_state) {
	 case DMD_LNB_TONE_DEFAULT:
	   tone = (tone_state == DMD_LNB_TONE_22KHZ) ? SEC_TONE_ON : SEC_TONE_OFF;
	   break;
	 case DMD_LNB_TONE_OFF:
	   tone = SEC_TONE_OFF;
	   break;
	 case DMD_LNB_TONE_22KHZ:
	   tone = SEC_TONE_ON;
	   break;
	 default:
	   tone = SEC_TONE_OFF;
	   break;
   }
   if (ioctl(fe_fd, FE_SET_TONE, tone) == -1) {
	  printf("set TONE failed, %d\n", tone);
   }

   p[cmd_num].cmd = DTV_DELIVERY_SYSTEM;
   p[cmd_num].u.data = pDelivery->delivery.satellite.modulation_system == DMD_MODSYS_DVBS2 ? SYS_DVBS2 : SYS_DVBS;
   cmd_num++;
   p[cmd_num].cmd = DTV_FREQUENCY;
   p[cmd_num].u.data = pDelivery->delivery.satellite.frequency - pDelivery->delivery.satellite.band.lo;
   printf("tune to %d\n", p[cmd_num].u.data);
   cmd_num++;

   p[cmd_num].cmd = DTV_SYMBOL_RATE;
   p[cmd_num].u.data = pDelivery->delivery.satellite.symbol_rate * 1000;
   cmd_num++;

   code_rate = pDelivery->delivery.satellite.fec_rate;
   switch (code_rate) {
   case DMD_FEC_NONE:
	 code_rate = FEC_NONE;
	 break;
   case DMD_FEC_1_2:
	 code_rate = FEC_1_2;
	 break;
   case DMD_FEC_2_3:
	 code_rate = FEC_2_3;
	 break;
   case DMD_FEC_3_4:
	 code_rate = FEC_3_4;
	 break;
   case DMD_FEC_4_5:
	 code_rate = FEC_4_5;
	 break;
   case DMD_FEC_5_6:
	 code_rate = FEC_5_6;
	 break;
   case DMD_FEC_6_7:
	 code_rate = FEC_6_7;
	 break;
   case DMD_FEC_7_8:
	 code_rate = FEC_7_8;
	 break;
   case DMD_FEC_8_9:
	 code_rate = FEC_8_9;
	 break;
   case DMD_FEC_3_5:
	 code_rate = FEC_3_5;
	 break;
   case DMD_FEC_9_10:
	 code_rate = FEC_9_10;
	 break;
   default:
	 code_rate = FEC_AUTO;
	 break;
   }
   p[cmd_num].cmd = DTV_INNER_FEC;
   p[cmd_num].u.data = code_rate;
   cmd_num++;

   p[cmd_num].cmd = DTV_TUNE;
   cmd_num++;
   props.num = cmd_num;
   props.props = (struct dtv_property *)&p;

   return dmd_set_prop(fe_fd, &props);
}


int open_fend(int fe_idx, int *fe_id)
{
   char fe_name[24];
   struct stat file_status;

   snprintf(fe_name, sizeof(fe_name), "/dev/dvb0.frontend%u", fe_idx);
   if (stat(fe_name, &file_status) == 0)
   {
       printf("Found FE[%s]\n", fe_name);
   }
   else
   {
       printf("No FE found [%s]!", fe_name);
	   return -1;
   }

   if ((*fe_id = open(fe_name, O_RDWR | O_NONBLOCK)) < 0)
   {
      printf("Failed to open [%s], errno %d\n", fe_name, errno);
      return -2;
   }
   else
   {
      printf("Open %s frontend_fd:%d \n", fe_name, *fe_id);
   }

   return 0;
}

int close_fend(int fe_id)
{
	if (fe_id != INVALID_FD)
	{
	   printf("close frontend_fd:%d \n", fe_id);
	   close(fe_id);
	   return 0;
	}
	return -1;
}

dmd_tuner_event_t get_dmd_lock_status(int frontend_fd)
{
    struct dvb_frontend_event fe_event;
    dmd_tuner_event_t tune_event = TUNER_STATE_UNKNOW;
    if (ioctl(frontend_fd, FE_READ_STATUS, &fe_event.status) >= 0)
    {
       printf("current tuner status=0x%02x \n", fe_event.status);
       if ((fe_event.status & FE_HAS_LOCK) != 0)
       {
           tune_event = TUNER_STATE_LOCKED;
		   printf("current tuner status [locked]\n");
       }
       else if ((fe_event.status & FE_TIMEDOUT) != 0)
       {
           tune_event = TUNER_STATE_TIMEOUT;
		   printf("current tuner status [unlocked]\n");
       }
    }
	else
    {
        printf("frontend_fd:%d FE_READ_STATUS errno:%d \n" ,frontend_fd, errno);
    }
    return tune_event;
}
