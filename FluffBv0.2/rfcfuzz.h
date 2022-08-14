#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hidp.h>
#include <bluetooth/rfcomm.h>
#include <asm/byteorder.h>

#define MAXSIZE		4096
#define IT		512
#define LENGTH		20
#define	BUFCODE		100

void rfcfuzz(char *bdstr_addr, int maxsize, int maxcrash)
{
	char *buf, *savedbuf;
	//struct hidp_conndel_req addr;
	int sock, i, size;
	int crash_count=0, savedsize;
	sock = socket(PF_BLUETOOTH,SOCK_STREAM,BTPROTO_L2CAP);
	if (sock<=0)
	{
		perror("socket");
		exit(EXIT_FAILURE);
	}

	struct sockaddr_l2 addr_remote;
    memset(&addr_remote,0,sizeof(addr_remote));
    addr_remote.l2_family=PF_BLUETOOTH;
    addr_remote.l2_psm=RFCOMM_PSM;
    str2ba(bdstr_addr,(bdaddr_t*)&addr_remote.l2_bdaddr);

    if(0!=connect(sock,(struct sockaddr*)&addr_remote,sizeof(addr_remote)))
    {
        perror("connect");
		exit(EXIT_FAILURE);
    }

	if(!(savedbuf = (char *) malloc ((int) maxsize + 1))) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	while(1)		// Initite loop (ctrl-c to stop...)
	{	
		size=rand() % maxsize;
		if(size == 0) 
			size=1;
		if(!(buf = (char *) malloc ((int) size + 1))) {
			perror("malloc");
			exit(EXIT_FAILURE);
		}

		bzero(buf, size);
		for(i=0 ; i<size ; i++)	
			buf[i] = (char) rand();
		
		putchar('.');
		fflush(stdout);
		
		if(send(sock, buf, size, 0) <= 0)
		{
			crash_count++;
			fprintf(stdout, "\n%s BT stack may have crashed. This device seems to be vulnerable to buggy packets.\n", bdstr_addr);
			fprintf(stdout, "Please, ensure that the device has really crashed doing a bt scan for instance.\n");
			fprintf(stdout, "\t----------------------------------------------------\n");
			fprintf(stdout, "\tHost\t\t%s\n", bdstr_addr);
			fprintf(stdout, "\tPacket size\t%d\n", savedsize);
			fprintf(stdout, "\t----------------------------------------------------\n");
			fprintf(stdout, "\tPacket dump\n\t");
			for(i=0 ; i<savedsize ; i++)
			{
				fprintf(stdout, "0x%.2X ", (unsigned char) savedbuf[i]);
				if( (i%30) == 29)
					fprintf(stdout, "\n\t");
			}
			fprintf(stdout, "\n\t----------------------------------------------------\n");

			fprintf(stdout, "char replay_buggy_packet[]=\"");
			for(i=0 ; i<savedsize ; i++)
			{
				fprintf(stdout, "\\x%.2X", (unsigned char) savedbuf[i]);
			}
			fprintf(stdout, "\";\n");

			if((crash_count == maxcrash) && (maxcrash != 0) && (maxcrash >= 0))
			{
				free(buf);
				free(savedbuf);
				exit(EXIT_SUCCESS);
			}
			
		}
		memcpy(savedbuf, buf, size);	// Get the previous packet, not this one...
		savedsize = size;
		free(buf);
	}
}  