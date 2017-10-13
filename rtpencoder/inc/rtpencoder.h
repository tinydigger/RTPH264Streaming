#ifndef RTPENCODER_H
#define RTPENCODER_H

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h> 

#include <rtpcommon.h>

class rtpencoder
{
public:
    rtpencoder(char *filename, char *addr, uint32_t dest_port, RTP_PAYLOAD_TYPE payload_type);

    ~rtpencoder();

    RTP_RETCODE init(char *filename, char *addr, uint32_t dest_port, RTP_PAYLOAD_TYPE payload_type);

    RTP_RETCODE start();

    RTP_RETCODE stop();


    RTP_STATE rtp_get_state() { return m_rtp_state; };

    void rtp_set_state(RTP_STATE state) { m_rtp_state = state; };

    uint32_t make_rtp_pkt(const uint8_t* data, uint32_t len,
        RTPH264_MODE mode, uint8_t cu_pack_num, uint8_t fu_pack_num);

    uint32_t encode_stream_pkt(uint8_t *buf, uint32_t len);

    uint32_t read_packet(uint8_t *buf, bool *eof);

    uint32_t send_packet(uint8_t *rtp_pkt, uint32_t len);

private:
    FILE *m_file;
    int m_socket;
    uint8_t *m_rtp_pkt;
    unsigned long m_base_time;
    unsigned long m_cur_time;

    pthread_t m_rtpencoder_tid;
    RTP_STATE m_rtp_state;
    RTP_SETUP_INFO *m_setup_info;
    RTP_PKT_INFO *m_pkt_info;

    sockaddr_in m_faraddr;
};

#endif
