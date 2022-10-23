#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "lib/bluetooth.h"
#include "lib/hci.h"
#include "lib/hci_lib.h"
#include "lib/l2cap.h"
#include "lib/sdp.h"

#include "variation.h"

#define BDADDR_ANY   (&(bdaddr_t) {{0, 0, 0, 0, 0, 0}})

#if __BYTE_ORDER == __LITTLE_ENDIAN

char VERSION[]="test";

struct avctp_header {
	uint8_t ipid:1;
	uint8_t cr:1;
	uint8_t packet_type:2;
	uint8_t transaction:4;
	uint16_t pid;
} __attribute__ ((packed));
#define AVCTP_HEADER_LENGTH 3

#elif __BYTE_ORDER == __BIG_ENDIAN

struct avctp_header {
	uint8_t transaction:4;
	uint8_t packet_type:2;
	uint8_t cr:1;
	uint8_t ipid:1;
	uint16_t pid;
} __attribute__ ((packed));
#define AVCTP_HEADER_LENGTH 3

#else
#error "Unknown byte order"
#endif
#define AVCTP_COMMAND		0
#define AVCTP_RESPONSE		1

#define AVCTP_PACKET_SINGLE	0

static void dump_avctp_header(struct avctp_header *hdr)
{
	printf("TL %d PT %d CR %d IPID %d PID 0x%04x\n", hdr->transaction,
			hdr->packet_type, hdr->cr, hdr->ipid, ntohs(hdr->pid));
}

static void dump_buffer(const unsigned char *buf, int len)
{
	int i;

	for (i = 0; i < len; i++)
		printf("%02x ", buf[i]);
	printf("\n");
}

static int do_connect(const bdaddr_t *src, const bdaddr_t *dst)
{
	struct sockaddr_l2 addr;
	int sk, err;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sk < 0) {
		perror("Can't create socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, src);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Can't bind socket");
		goto error;
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, dst);
	addr.l2_psm = htobs(23);

	err = connect(sk, (struct sockaddr *) &addr, sizeof(addr));
	if (err < 0) {
		perror("Unable to connect");
		goto error;
	}
	return sk;

error:
	close(sk);
	return -1;
}

void do_avctp_send(int sk)
{
	unsigned char buf[10];
    unsigned char sendbuf[10];
    unsigned char oldsbuf[10];
    unsigned char oldrbuf[10];
	struct avctp_header *hdr = (void *) buf;
	unsigned char play_pressed[] = { 0x01, 0x23, 0x45, 0x67, 0x00 };
	ssize_t len;

	memset(buf, 0, sizeof(buf));

	hdr->packet_type = AVCTP_PACKET_SINGLE;
	hdr->cr = AVCTP_COMMAND;
	hdr->pid = htons(AV_REMOTE_SVCLASS_ID);

	memcpy(&buf[AVCTP_HEADER_LENGTH], play_pressed, sizeof(play_pressed));
    // while(1)
    // {
        len=RandomVariation(buf,10);
        memcpy(sendbuf,buf,10);
	    len = write(sk, buf, AVCTP_HEADER_LENGTH + sizeof(play_pressed));
	    len = read(sk, buf, sizeof(buf));
        fuzzlogSR(sendbuf,buf,4);
        memcpy(oldsbuf,sendbuf,10);
        memcpy(oldrbuf,buf,10);
	    dump_buffer(buf, len);
	    if (len >= AVCTP_HEADER_LENGTH)
		    dump_avctp_header(hdr);
    // }
    
}

int main(int argc,char *argv[])
{
    bdaddr_t src,dst;
    int sk;
    bacpy(&src, BDADDR_ANY);
	bacpy(&dst, BDADDR_ANY);
    str2ba(argv[optind], &dst);
    sk = do_connect(BDADDR_ANY,&dst);
        if (sk < 0)
			exit(1);
    do_avctp_send(sk);

}