/*****************************************************************************
******************************************************************************
*
*         File : bc_types.h
*
*  Description : type definitions used by the betacrypt library
*
*    Copyright : COMVENIENT  2008 (c)
*    Copyright : Verimatrix  2011-2017 (c)
*
******************************************************************************
*****************************************************************************/

/**************************** CVS Infos ****************************************
*
*  $Source: /home/boxop/cvsroot/bc2_cam_src/bc_types.h,v $
*  $Date: 2017/10/05 09:18:24 $
*  $Revision: 1.2.1.2 $
*
***************************** CVS Infos ***************************************/

#ifndef _BC_TYPES_H_
#define _BC_TYPES_H_

// Types used by the betacrypt library
#if 0
typedef  signed char    int8_t;     /*  range :  -128 to 127               */
typedef  unsigned char  uint8_t;    /*  range :  0 to 255                  */
typedef  signed short   int16_t;    /*  range :  -32768 to 32767           */
typedef  unsigned short uint16_t;   /*  range :  0 to 65535                */
typedef  signed int     int32_t;    /*  range :  -2147483648 to 2147483647 */
typedef  unsigned int   uint32_t;   /*  range :  0 to 4294967295           */
typedef  signed long long    int64_t;    /*  range :  -2^63 to 2^63-1      */
typedef  unsigned long long  uint64_t;   /*  range :  0 to 2^64-1          */
typedef  unsigned short bool_t;     /*  range :  0 to 1 (false, true)      */
typedef  float          float32_t;  /*  -1.175494E-38 to +3.402823E+38     */
#endif
typedef  void           void_t;     /*  range :  n.a.                      */

#ifndef true
#define true  (1 == 1)
#endif
#ifndef false
#define false (1 == 0)
#endif

#endif
 //_BC_TYPES_H_
