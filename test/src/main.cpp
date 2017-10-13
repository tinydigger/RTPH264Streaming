#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <memory.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <rtpcommon.h>
#include <rtpencoder.h>

#define DEST_PORT_DEFAULT 5004

int main(int argc, char *argv[])
{
    char *testfile = argv[1];
    char *destaddr = argv[2];
    int port = atoi(argv[3]);

    rtpencoder rtp_encoder(testfile, destaddr, port, RTP_PAYLOAD_H264);
    rtp_encoder.start();

    while(rtp_encoder.rtp_get_state() == RTP_STATE_EXECUTING) {
        sleep(1);
    }

    return 0;
}
