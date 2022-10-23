#include "headers.h"
/*
 1 byte       2 bytes           2 bytes     |←—————ParameterLength bytes——————→|
________________________________________________________________________________
| PDU ID | Transaction ID | ParameterLength | Parameter 1 | ···· | Parameter N |
￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣
*/ 

//PDU ID

#define Reserved (0x00) //保留

#define SDP_ErrorResponse (0x01) //错误响应
//Parameters:
//ErrorCode:
        #define Invalid_or_unsupported_SDP_version (0x0001)
        #define Invalid_Service_Record_Handle (0x0002)
        #define lnvalid_request_syntax (0x0003)
        #define Invalid_PDU_Size (0x0004)
        #define lnvalid_Continuation_State (0x0005)
        #define Insufficient_Resources_to_satisfy_Request (0x0006)

#define SDP_ServiceSearchRequest (0x02) //服务搜索请求
/*
Parameters:
ServiceSearchPattern,
MaximumServiceRecordCount,
ContinuationState
*/
#define SDP_ServiceSearchResponse (0x03) //服务搜索响应
/*
TotalServiceRecordCount,
CurrentServiceRecordCount,
ServiceRecordHandleList,
ContinuationState
*/

#define SDP_ServiceAttributeRequest (0x04) //服务属性请求

#define SDP_ServiceAttributeResponse (0x05) //服务属性响应

#define SDP_ServiceSearchAttributeRequest (0x06) //服务搜索属性请求
/*
Parameters:
ServiceSearchPattern,这个匹配模式是由一串UUID组成的，一次最多包含12个UUID，UUID的表现形式是data element
MaximumAttributeByteCount,从response中返回的最大的PDU
AttributelDList,这个参数包含的是一串attribute ID或者是attribute ID的范围，也可以是两者的组合。
ContinuationState:这个参数的第一个字节代表长度，然后后面跟该长度个字节。这个state 是从reponse中返回的。
                  然后再一次请求的时候放在参数里面。如何没有剩余的字节需要读取，那么设置为0
*/
#define SDP_ServiceSearchAttributeResponse (0x07) //服务搜索属性响应
/*
Parameters:
AttributeListsByteCount,这里是count就是AttributeLists这里的字节数。
AttributeLists,这里的元素都是data element sequence，它是由attribute IDs和attribute values 来组成的pair
ContinuationState
*/
//0x08-0xff Reserved 保留
typedef unsigned char uuid_tg[16];
typedef struct
{
    unsigned char PID;
    unsigned short ErrorCode;
}SDP_ERROR_RSP_PKG;

int setSDP_ERROR_RSP(char* sendbuff,unsigned char code)
{
    SDP_ERROR_RSP_PKG* sdpbuff=(SDP_ERROR_RSP_PKG*)sendbuff;
    sdpbuff->PID=SDP_ErrorResponse;
    sdpbuff->ErrorCode=code;
    return 1;
}

typedef struct
{
    unsigned char PID;
    unsigned short Transaction_ID;
    unsigned short ParameterLength;
    unsigned char Parameters[0];
}SDP_SERVICE_SEARCH_REQ; 

int  setSDP_SERVICE_SEARCH_REQ(char* sendbuff,unsigned short Tid, unsigned short Plen,uuid_tg* in_uuids,unsigned short maxcount,int *totalsize)
{
    SDP_SERVICE_SEARCH_REQ* sdpbuff= (SDP_SERVICE_SEARCH_REQ*)sendbuff;
    sdpbuff->PID=SDP_ServiceSearchRequest;
    sdpbuff->Transaction_ID=Tid;
    for (int i = 0; i < Plen; i++)
    {
        for (int j = 0; j < 16; j++)
        {
            *(sdpbuff->Parameters+i*16+j)=in_uuids[i][j];
        }
        
    }
    sdpbuff->Parameters[Plen*16]=maxcount;
    sdpbuff->Parameters[Plen*16+sizeof(unsigned short)]=0x00;
    sdpbuff->ParameterLength=Plen*16+sizeof(unsigned short)+1;
    *totalsize=sdpbuff->ParameterLength+5;
    return 1;
}

typedef struct
{
    unsigned char  PID;
    unsigned short Transaction_ID;
    unsigned short ParameterLength;
    unsigned short TotalServiceRecordCount;
    unsigned short CurrentServiceRecordCount;
    unsigned int  ServiceRecordHandleList[0];
}SDP_SERVICE_SEARCH_RSP;
int setSDP_SERVICE_SEARCH_RSP(char* sendbuff,unsigned short Tid,unsigned short Tcout,unsigned short Ccout,unsigned int list[])
{
    SDP_SERVICE_SEARCH_RSP* sdpbuff=(SDP_SERVICE_SEARCH_RSP*)sendbuff;
    sdpbuff->PID=SDP_ServiceSearchResponse;
    sdpbuff->Transaction_ID=Tid;
    sdpbuff->ParameterLength=2+2+Ccout*4;
    sdpbuff->TotalServiceRecordCount=Tcout;
    sdpbuff->CurrentServiceRecordCount=Ccout;
    for (int i = 0; i < Ccout; i++)
    {
        *(sdpbuff->ServiceRecordHandleList+i)=list[i];
    }
    return 1;
}

typedef struct
{
    unsigned char PID;
    unsigned short Transaction_ID;
    unsigned short ParameterLength;
    unsigned int ServiceRecordHandle;
    unsigned short MaximumAttributeByteCount;
    unsigned int AttributeIDList[0];
}SDP_SERVICE_ATTR_REQ;

int setSDP_SERVICE_ATTR_REQ(char *sendbuff,unsigned short Tid,unsigned int srh,unsigned short maxABcout,unsigned int list[],int* totalsize)
{
    SDP_SERVICE_ATTR_REQ *sdpbuff=(SDP_SERVICE_ATTR_REQ*)sendbuff;
    sdpbuff->PID=SDP_ServiceAttributeRequest;
    sdpbuff->Transaction_ID=Tid;
    sdpbuff->ParameterLength=4+2+maxABcout*4;
    sdpbuff->ServiceRecordHandle=srh;
    sdpbuff->MaximumAttributeByteCount=maxABcout;
    for (int i = 0; i < maxABcout; i++)
    {
        *(sdpbuff->AttributeIDList+i)=list[i];
    }

    *totalsize=sdpbuff->ParameterLength+5;
    return 1;
}

typedef struct
{
    unsigned char PID;
    unsigned short Transaction_ID;
    unsigned short ParameterLength;
    unsigned short AttributeListByteCount;
    unsigned char AttributeList[0];
}SDP_SERVICE_ATTR_RSP;

int setSDP_SERVICE_ATTR_RSP(char *sendbuff,unsigned short Tid,unsigned short ABcout,unsigned char list[])
{
    SDP_SERVICE_ATTR_RSP *sdpbuff=(SDP_SERVICE_ATTR_RSP*)sendbuff;
    sdpbuff->PID=SDP_ServiceAttributeResponse;
    sdpbuff->Transaction_ID=Tid;
    sdpbuff->ParameterLength=2+ABcout;
    sdpbuff->AttributeListByteCount=ABcout;
    for (int i = 0; i <ABcout; i++)
    {
        *(sdpbuff->AttributeList+i)=list[i];
    }
    
    return 1;
}


