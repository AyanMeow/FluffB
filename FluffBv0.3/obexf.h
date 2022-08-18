#include "headers.h"

#define OBEX_PACKET_MAX_LEN (1024)

//----------------------------------------------------Request--------------------------------------------------//
#define OBEX_OP_CONNECT (0x80)
#define OBEX_OP_DISCONNECT (0x81)
#define OBEX_OP_PUT (0x02)
#define OBEX_OP_GET (0x03)
#define OBEX_ROWPACKET_SIZE (7)
#define OBEX_FLAG_FINAL (0x80)
//len指整个Request的大小,包括可选头
//固定大小
typedef struct
{
    unsigned char op;
    unsigned char lenH;
    unsigned char lenL;
    unsigned char version;
    unsigned char _unused;
    unsigned char maxLenH;
    unsigned char maxLenL;
}ObexRowPacket;

typedef struct
{
    unsigned char op;
    unsigned char lenH;
    unsigned char lenL;
}ObexRequestPacket;

#define OBEX_HEADER_COUNT (0xc0)
#define OBEX_HEADER_CONNECTIONID (0xcb)
#define OBEX_HEADER_LENGTH (0xc3)
//固定大小
typedef struct 
{
    unsigned char op;
    unsigned char c3;
    unsigned char c2;
    unsigned char c1;
    unsigned char c0;
}ObexCountHeader,ObexConnectionIdHeader,ObexLengthHeader;

#define OBEX_HEADER_NAME (0x01)
#define OBEX_HEADER_BODY (0x48)
#define OBEX_HEADER_ENDOFBODE (0x49)
#define OBEX_HEADER_TYPE (0x42)
#define OBEX_HEADER_DATA_LEN (3)
//len指整个可选头的大小,包括op和len的大小
//非固定大小
typedef struct
{
    unsigned char op;
    unsigned char len1;
    unsigned char len0;
    char buf[OBEX_PACKET_MAX_LEN];
}ObexNameHeader,ObexBodyHeader,ObexEndOfBodyHeader,ObexTypeHeader;

#define OBEX_HEADER_SINGLERESPONSEMODE (0x97)
typedef struct
{
    unsigned char op;
    unsigned char isEnable;
}ObexSingleResponseModeHeader;

//----------------------------------------------------Request End--------------------------------------------------//

//----------------------------------------------------Response--------------------------------------------------//
#define OBEX_OP_SUCCESS (0x20)
#define OBEX_OP_SUCCESS2 (0xa0)
#define OBEX_OP_CONTINUE (0x90)
//固定大小
typedef struct
{
    unsigned char op;
    unsigned char len1;
    unsigned char len2;
}ObexSuccessPacket;

//----------------------------------------------------Response End--------------------------------------------------//


//----------------------------------------------------Functions--------------------------------------------------//

int ObexSetRowPacket(char*sendBuf,unsigned maxLen,unsigned*realLen,int op)
{
    ObexRowPacket*rowPacket=(ObexRowPacket*)sendBuf;
    rowPacket->op=op;
    rowPacket->version=0x10;
    rowPacket->maxLenH=(maxLen&0xff00)>>8;
    rowPacket->maxLenL=maxLen&0x00ff;
    (*realLen)+=sizeof(ObexRowPacket);
    return 1;
}

int ObexSetCountHeader(char*sendBuf,unsigned count,unsigned*realLen)
{
    ObexCountHeader*countHeader=(ObexCountHeader*)sendBuf;
    countHeader->op=OBEX_HEADER_COUNT;
    countHeader->c3=(count&0xff000000)>>24;
    countHeader->c2=(count&0x00ff0000)>>16;
    countHeader->c1=(count&0x0000ff00)>>8;
    countHeader->c0=count&0x000000ff;
    (*realLen)+=sizeof(ObexCountHeader);
    return 1;
}

int ObexSetRowPacketLen(char*sendBuf,unsigned len)
{
    ObexRowPacket*rowPacket=(ObexRowPacket*)sendBuf;
    rowPacket->lenH=(len&0xff00)>>8;
    rowPacket->lenL=len&0x00ff;
    return 1;
}

int ObexSetRequestPacket(char*sendBuf,unsigned*realLen,int op)
{
    ObexRequestPacket*requestPacket=(ObexRequestPacket*)sendBuf;
    requestPacket->op=op;
    (*realLen)+=sizeof(ObexRequestPacket);
    return 1;
}

int ObexSetConnectionIdHeader(char*sendBuf,unsigned id,unsigned*realLen)
{
    ObexConnectionIdHeader*connectionIdHeader=(ObexConnectionIdHeader*)sendBuf;
    connectionIdHeader->op=OBEX_HEADER_CONNECTIONID;
    connectionIdHeader->c3=(id&0xff000000)>>24;
    connectionIdHeader->c2=(id&0x00ff0000)>>16;
    connectionIdHeader->c1=(id&0x0000ff00)>>8;
    connectionIdHeader->c0=id&0x000000ff;
    (*realLen)+=sizeof(ObexConnectionIdHeader);
    return 1;
}

int ObexSetNameHeader(char*sendBuf,char*name,unsigned nameLen,unsigned*realLen)
{
    unsigned tarNameLen=nameLen*2+1;
    char fileName[tarNameLen];
    memset(fileName,0,tarNameLen);
    for(int i=0;i<nameLen;i++)
    {
        fileName[2*i+1]=name[i];
    }
    ObexNameHeader*nameHeader=(ObexNameHeader*)sendBuf;
    nameHeader->op=OBEX_HEADER_NAME;
    memcpy(nameHeader->buf,fileName,tarNameLen);
    (*realLen)+=(tarNameLen+OBEX_HEADER_DATA_LEN+1);

    //4.实际name长度小于len，访问越界----------------------
    #pragma region 
    //tarNameLen*=1024;
    #pragma endregion
    //-----------------------------------------------------------------

    nameHeader->len1=((tarNameLen+OBEX_HEADER_DATA_LEN+1)&0xff00)>>8;
    nameHeader->len0=(tarNameLen+OBEX_HEADER_DATA_LEN+1)&0x00ff;
    
    return 1;
}

int ObexSetlLengthHeader(char*sendBuf,unsigned length,unsigned*realLen)
{
    ObexLengthHeader*lengthHeader=(ObexLengthHeader*)sendBuf;
    lengthHeader->op=OBEX_HEADER_LENGTH;
    lengthHeader->c3=(length&0xff000000)>>24;
    lengthHeader->c2=(length&0x00ff0000)>>16;
    lengthHeader->c1=(length&0x0000ff00)>>8;
    lengthHeader->c0=length&0x000000ff;
    (*realLen)+=sizeof(ObexLengthHeader);
    return 1;
}

int ObexSetSingleResponseModeHeader(char*sendBuf,unsigned char isEnable,unsigned*realLen)
{
    ObexSingleResponseModeHeader*singleResponseModeHeader=(ObexSingleResponseModeHeader*)sendBuf;
    singleResponseModeHeader->op=OBEX_HEADER_SINGLERESPONSEMODE;
    singleResponseModeHeader->isEnable=isEnable;
    (*realLen)+=sizeof(ObexSingleResponseModeHeader);
    return 1;
}

int ObexSetBodyHeader(char*sendBuf,char*body,unsigned bodyLen,unsigned*realLen)
{
    ObexBodyHeader*bodyHeader=(ObexBodyHeader*)sendBuf;
    bodyHeader->op=OBEX_HEADER_BODY;
    bodyHeader->len1=((bodyLen+OBEX_HEADER_DATA_LEN)&0xff00)>>8;
    bodyHeader->len0=(bodyLen+OBEX_HEADER_DATA_LEN)&0x00ff;
    memcpy(bodyHeader->buf,body,bodyLen);
    (*realLen)+=(bodyLen+OBEX_HEADER_DATA_LEN);
    return 1;
}

int ObexSetRequestPacketLen(char*sendBuf,unsigned len)
{
    ObexRequestPacket*requestPacket=(ObexRequestPacket*)sendBuf;
    requestPacket->lenH=(len&0xff00)>>8;
    requestPacket->lenL=len&0x00ff;
    return 1;
}

int ObexSetEndOfBodeHeader(char*sendBuf,char*body,unsigned bodyLen,unsigned*realLen)
{
    ObexEndOfBodyHeader*endOfBodeHeader=(ObexEndOfBodyHeader*)sendBuf;
    endOfBodeHeader->op=OBEX_HEADER_ENDOFBODE;
    endOfBodeHeader->len1=((bodyLen+OBEX_HEADER_DATA_LEN)&0xff00)>>8;
    endOfBodeHeader->len0=(bodyLen+OBEX_HEADER_DATA_LEN)&0x00ff;
    memcpy(endOfBodeHeader->buf,body,bodyLen);
    (*realLen)+=(bodyLen+OBEX_HEADER_DATA_LEN);
    return 1;
}

int getChannel(char srvName[][NAME_MAX_LEN],int srvChannel[],unsigned maxLen)
{
    for(int i=0;i<maxLen;i++)
    {
        if(strstr(srvName[i],"OBEX Object Push"))
        {
            return srvChannel[i];
        }
    }
    return -1;
}

unsigned int getUint32FromChar(unsigned char c3,unsigned char c2,unsigned char c1,unsigned char c0)
{
    unsigned int x=0;
    x=x|(c3<<24);
    x=x|(c2<<16);
    x=x|(c1<<8);
    x=x|(c0<<0);
    return x;
}
//----------------------------------------------------Functions End--------------------------------------------------//
