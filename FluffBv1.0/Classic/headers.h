#ifndef HEADERS_H
#define HEADERS_H
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

#include <sys/un.h>
#include<uuid/uuid.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <poll.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>

#include "loghelper.h"

#define ADDR_MAX_LEN 19
#define NAME_MAX_LEN 255
#define PATH_MAX_LEN 1024
#endif
