

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 8.01.0628 */
/* at Tue Jan 19 06:14:07 2038
 */
/* Compiler settings for int.idl:
    Oicf, W1, Zp8, env=Win32 (32b run), target_arch=X86 8.01.0628 
    protocol : dce , ms_ext, app_config, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */



/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 500
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif /* __RPCNDR_H_VERSION__ */


#ifndef __int_h_h__
#define __int_h_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#ifndef DECLSPEC_XFGVIRT
#if defined(_CONTROL_FLOW_GUARD_XFG)
#define DECLSPEC_XFGVIRT(base, func) __declspec(xfg_virtual(base, func))
#else
#define DECLSPEC_XFGVIRT(base, func)
#endif
#endif

/* Forward Declarations */ 

/* header files for imported files */
#include "oaidl.h"
#include "ocidl.h"

#ifdef __cplusplus
extern "C"{
#endif 


#ifndef __Example1_INTERFACE_DEFINED__
#define __Example1_INTERFACE_DEFINED__

/* interface Example1 */
/* [implicit_handle][version][uuid] */ 

#define	cMaxBuf	( 65534 )

void Output( 
    /* [string][in] */ const unsigned char *szOutput);

int CopyOnClient( 
    /* [in][string] */ const unsigned char *path,
    /* [out] */ int buf[ 65534 ],
    /* [out] */ unsigned int *length_buf,
    /* [in] */ int index,
    /* [out] */ int *check_eof);

int MakeFileOnServer( 
    /* [in][string] */ const unsigned char *FileName,
    /* [in] */ int buf[ 65534 ],
    /* [in] */ int length_buf,
    /* [in] */ int index,
    /* [in] */ int check_eof);

int DeleteFileOnServer( 
    /* [in][string] */ const unsigned char *path,
    /* [in] */ int index);

int MakeClientOnServer( 
    /* [in][string] */ const unsigned char *login,
    /* [in][string] */ const unsigned char *password,
    /* [out] */ int *index);

int ClientOut( 
    /* [in] */ int index);


extern handle_t hExample1Binding;


extern RPC_IF_HANDLE Example1_v1_0_c_ifspec;
extern RPC_IF_HANDLE Example1_v1_0_s_ifspec;
#endif /* __Example1_INTERFACE_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


