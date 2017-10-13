#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <memory.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <pthread.h> 
#include <rtpcommon.h>
#include <rtpencoder.h>

#define RTP_INPUT_BUF_SIZE (1920 * 1080) 
#define RTP_READ_FILE_BYTES (1024 * 1024)

rtpencoder::rtpencoder(char *filename, char *addr, uint32_t port, RTP_PAYLOAD_TYPE payload_type)
    : m_socket(0),
    m_file(NULL), 
    m_rtp_pkt(NULL),
    m_base_time(0),
    m_cur_time(0),
    m_rtp_state(RTP_STATE_INIT),
    m_setup_info(new RTP_SETUP_INFO),
    m_pkt_info(new RTP_PKT_INFO)
{
    init(filename, addr, port, payload_type);
    m_rtp_pkt = new uint8_t[RTP_H264_MAX_PKT_SIZE];
}

rtpencoder::~rtpencoder()
{
    if (m_setup_info) {
        delete m_setup_info;
        m_setup_info = NULL;
    }

    if (m_pkt_info) {
        delete m_pkt_info;
        m_pkt_info = NULL;
    }

    if (m_file) {
        fclose(m_file);
        m_file = NULL;
    }

    if (m_rtp_pkt) {
        delete [] m_rtp_pkt;
        m_rtp_pkt = NULL;
    }
}

RTP_RETCODE rtpencoder::init(char *filename, char *addr, uint32_t port, RTP_PAYLOAD_TYPE payload_type)
{
    RTP_RETCODE ret = RTP_SUCCESS;
    uint8_t optval = 255;
    uint32_t buffer_size = 1024 * 1024;
    struct timeval tval;
    tval.tv_sec = 2;
    tval.tv_usec = 0;

    if (NULL != filename && NULL != addr && port > 0) {
        m_file = fopen(filename, "r");
        if (m_file == NULL) {
            printf ("input file open failed\n");
            return RTP_ERROR; 
        }

        m_setup_info->addr = inet_addr(addr);
        m_setup_info->destport = port;
        m_setup_info->payloadtype = payload_type;

        memset(&m_faraddr, 0, sizeof(sockaddr_in));
        m_faraddr.sin_addr.s_addr = m_setup_info->addr;
        m_faraddr.sin_family = AF_INET;
        m_faraddr.sin_port = htons((uint16_t)m_setup_info->destport);

        //socket configuration
        m_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        setsockopt(m_socket, IPPROTO_IP,IP_TTL, (const char*)&optval, 1);
        setsockopt(m_socket, SOL_SOCKET,SO_SNDBUF, (const char*)&buffer_size, 4);
        setsockopt(m_socket, SOL_SOCKET, SO_SNDTIMEO, (struct timeval *)&tval, (socklen_t)sizeof(struct timeval));

        //synchronization source (SSRC) identifier
        m_pkt_info->ssrc = 0;
        m_pkt_info->sequenceno = 0;
        m_pkt_info->payloadtype = uint32_t(payload_type);

        rtp_set_state(RTP_STATE_READY);
        printf ("rtp init success\n");
    }
    else {
        ret = RTP_ERROR;
        printf ("rtp init failed\n");
    }

    return ret;
}

bool find_nal_startcode(uint8_t *buf, uint32_t len)
{
    bool bFound = false;

    // The start code could be 3 or 4 bytes
    if(len == 3) {
        if(*buf == 0x0 && *(buf + 1) == 0x0 && *(buf + 2) == 0x1)
            bFound = true; 
    }
    else if(len == 4) {
        if(*buf == 0x0 && *(buf + 1) == 0x0 && *(buf + 2) == 0x0 && *(buf + 3) == 0x1) 
            bFound = true; 
    }
    else {
        printf("Invalid start code len\n");
    }

    return bFound;
}

//get current time (millsecond)
unsigned long get_cur_time()
{
    unsigned long msec;
    struct timeval tv;

    gettimeofday(&tv, NULL);
    msec = ((unsigned long)tv.tv_sec * 1000) + ((unsigned long)tv.tv_usec / 1000);

    return msec;
}

/* function to read a complete
 *
 * return valve:
 * -1   -  invalid bufffer or start code
 *  0   -  need more data to complete a nal
 *  >0  -  nal length
*/
uint32_t parse_nal(uint8_t * buf, uint32_t len, uint32_t *startcode_len)
{
    uint32_t ret_len = 0;

    if (NULL == buf || len <= 3) {
        printf ("invalid input buffer, size: %d\n", len); 
        return -1;
    }

    if (true == find_nal_startcode(buf, 3)) {
        *startcode_len = 3;
    }
    else if (true == find_nal_startcode(buf, 4)) {
        *startcode_len = 4;
    }
    else {
        printf ("error: cannot find start code\n"); 
        return -1;
    }


    // If we find the next start code, then we are done
    for (uint32_t i = 0; i < len - *startcode_len; i ++) {
        if (true == find_nal_startcode(buf + *startcode_len + i, *startcode_len)) {
            ret_len = i + *startcode_len;
            break;
        }
    }

    return ret_len;
}

void* worker_func(void *arg)
{
    rtpencoder *rtpenc = (rtpencoder *)arg;
    uint8_t *inbuf = new uint8_t[RTP_INPUT_BUF_SIZE];
    uint32_t read_len = 0;
    uint32_t send_len = 0;
    bool eof = false;

    while (RTP_STATE_EXECUTING == rtpenc->rtp_get_state()) {
        //read, packetise and send
        read_len = rtpenc->read_packet(inbuf, &eof);

        if (read_len > 0 && false == eof) {
            // framerate control
            usleep(1000 * 30);
            send_len = rtpenc->encode_stream_pkt(inbuf, read_len);
            printf("rtp send %d bytes\n", send_len);
        }
        else {
            break; 
        }
    }

finished:
    printf("rtp encoder work func finished\n");
    rtpenc->rtp_set_state(RTP_STATE_READY);
    delete [] inbuf;
}

uint32_t rtpencoder::make_rtp_pkt(const uint8_t* data, uint32_t len,
        RTPH264_MODE mode, uint8_t cu_pack_num, uint8_t fu_pack_num)
{
    uint8_t marker_bit = 0;
    uint32_t last_pkt_size = 0;
    nalu_header_t *nalu_hdr;
    fu_header_t *fu_hdr;
    fu_indicator_t *fu_ind;

    if(!data  || !len) {
        printf("Encode Invalid params or no Data to encode");
        return -1;
    }

    // RTP timestamp with 90000 scale
    m_cur_time = (get_cur_time() - m_base_time) * 90;

    int index = 0;

    // version = 2
    m_rtp_pkt[index++] = (uint8_t)(2 << 6);

    marker_bit = (FU_A_MODE == mode && cu_pack_num == fu_pack_num - 1) ? 1 : 0;

    // marker bit
    m_rtp_pkt[index] = (uint8_t)(marker_bit << 7);             

    m_rtp_pkt[index++] |= (uint8_t)m_pkt_info->payloadtype;

    m_rtp_pkt[index++] = (uint8_t)(m_pkt_info->sequenceno >> 8);

    m_rtp_pkt[index++] = (uint8_t)(m_pkt_info->sequenceno);

    m_pkt_info->sequenceno += 1;

    //Timestamp
    m_rtp_pkt[index++]  = (uint8_t)(m_cur_time >> 24);
    m_rtp_pkt[index++]  = (uint8_t)(m_cur_time >> 16);
    m_rtp_pkt[index++]  = (uint8_t)(m_cur_time >> 8 );
    m_rtp_pkt[index++]  = (uint8_t)(m_cur_time >> 0 );

    //TX SSRC
    m_rtp_pkt[index++]  = (uint8_t)(m_pkt_info->ssrc >> 24);
    m_rtp_pkt[index++]  = (uint8_t)(m_pkt_info->ssrc >> 16);
    m_rtp_pkt[index++] = (uint8_t)(m_pkt_info->ssrc >> 8);
    m_rtp_pkt[index++] = (uint8_t)(m_pkt_info->ssrc >> 0);

    //NALU header.
    switch (mode)
    {
        case SINGLE_NAL_MODE:
            nalu_hdr = (nalu_header_t *) &m_rtp_pkt[index];
            nalu_hdr->f = (data[0] & 0x80) >> 7;        /* bit0 */
            nalu_hdr->nri = (data[0] & 0x60) >> 5;      /* bit1~2 */
            nalu_hdr->type = (data[0] & 0x1f);
            index ++;
            memcpy(m_rtp_pkt + index, data + 1, len - 1); /* skip the first byte */
            return len + index - 1;
        case FU_A_MODE:
            fu_ind = (fu_indicator_t *) &m_rtp_pkt[index];
            fu_ind->f = (data[0] & 0x80) >> 7;
            fu_ind->nri = (data[0] & 0x60) >> 5;
            fu_ind->type = 28;
            index ++;
            // first FU-A package
            if (cu_pack_num == 0)
            {
                fu_hdr = (fu_header_t *) &m_rtp_pkt[index];
                fu_hdr->s = 1;
                fu_hdr->e = 0;
                fu_hdr->r = 0;
                fu_hdr->type = data[0] & 0x1f;
                index ++;
                memcpy(m_rtp_pkt + index, data + 1, RTP_H264_MAX_NAL_DATA_SIZE - 1);
                return index + RTP_H264_MAX_NAL_DATA_SIZE - 1;
            }
            // between FU-A package
            else if (cu_pack_num < fu_pack_num - 1)
            {
                fu_hdr = (fu_header_t *) &m_rtp_pkt[index];
                fu_hdr->s = 0;
                fu_hdr->e = 0;
                fu_hdr->r = 0;
                fu_hdr->type = data[0] & 0x1f;
                index ++;
                memcpy(m_rtp_pkt + index, data + cu_pack_num * RTP_H264_MAX_NAL_DATA_SIZE,
                        RTP_H264_MAX_NAL_DATA_SIZE);
                return index + RTP_H264_MAX_NAL_DATA_SIZE;
            }
            // last FU-A package
            else
            {
                fu_hdr = (fu_header_t *) &m_rtp_pkt[index];
                fu_hdr->s = 0;
                fu_hdr->e = 1;
                fu_hdr->r = 0;
                fu_hdr->type = data[0] & 0x1f;
                index ++;
                last_pkt_size = len % RTP_H264_MAX_NAL_DATA_SIZE ?
                    len % RTP_H264_MAX_NAL_DATA_SIZE : RTP_H264_MAX_NAL_DATA_SIZE;
                memcpy(m_rtp_pkt + index, data + cu_pack_num * RTP_H264_MAX_NAL_DATA_SIZE,
                        last_pkt_size);
                return index + last_pkt_size;
            }
    }
}

uint32_t rtpencoder::encode_stream_pkt(uint8_t *buf, uint32_t len)
{
    uint8_t fu_pack_num; // FU-A total package number
    uint8_t cu_pack_num; // FU-A current package number for processing
    uint32_t pkt_offset = RTP_HDR_SIZE; // RTP pkt header offset
    uint32_t pkt_size = 0;
    uint32_t bytes_sent = 0; // total sent bytes
    uint32_t bytes_sent_cu = 0; // current package sent bytes

    RTPH264_MODE mode = (len < RTP_H264_MAX_NAL_DATA_SIZE) ? SINGLE_NAL_MODE : FU_A_MODE; 

    if (SINGLE_NAL_MODE == mode) {
        pkt_size = make_rtp_pkt(buf, len, mode, 0, 0);
        bytes_sent = send_packet(m_rtp_pkt, pkt_size);
    }
    else if (FU_A_MODE == mode) {
        fu_pack_num = len % RTP_H264_MAX_NAL_DATA_SIZE ?
            (len / RTP_H264_MAX_NAL_DATA_SIZE + 1) : len / RTP_H264_MAX_NAL_DATA_SIZE;

        cu_pack_num = 0;
        while (cu_pack_num < fu_pack_num) {
            pkt_size = make_rtp_pkt(buf, len, mode, cu_pack_num, fu_pack_num);
            bytes_sent_cu = send_packet(m_rtp_pkt, pkt_size);
            bytes_sent += bytes_sent_cu;
            cu_pack_num ++;
        }
    }

    return bytes_sent;
}

uint32_t rtpencoder::send_packet(uint8_t *rtp_pkt, uint32_t len)
{
    uint32_t bytes_sned = 0;

    if (NULL != rtp_pkt && len > 0) {
        bytes_sned = sendto(m_socket, rtp_pkt, len, 0,
                (struct sockaddr*)&m_faraddr, (socklen_t)sizeof(m_faraddr));
        if (bytes_sned == 0 || bytes_sned == -1) {
            printf("rtpencoder failed to send packet, error:%d\n", errno);
            return -1; 
        }
    }
    else {
        printf("Invalid rtp packet\n");
        return -1; 
    }

    return bytes_sned;
}

//read payload data from file. for h264/avc, it's a nal without start code.
uint32_t rtpencoder::read_packet(uint8_t *buf, bool *eof)
{
    uint32_t read_len = 0, parse_len = 0, startcode_len = 0;
    static uint32_t offset = 0;
    static uint8_t *buf_read = NULL;
    *eof = false;
    RTP_PAYLOAD_TYPE payload_type = m_setup_info->payloadtype;

    if (NULL == buf_read)
        buf_read = new uint8_t[RTP_READ_FILE_BYTES * 10]; //Max buffer size is 10M bytes

    if (payload_type == RTP_PAYLOAD_H264) {
        if (offset > 0) {
            // We still have remaining data in buf_read, parse it
            parse_len = parse_nal(buf_read, offset, &startcode_len);
            if (parse_len > startcode_len) {
                memcpy(buf, buf_read + startcode_len, parse_len - startcode_len);
                offset =  offset - parse_len;
                memcpy(buf_read, buf_read + parse_len, offset);
                return parse_len; 
            }
        }

        while (parse_len <= 0) {
            read_len = fread(buf_read + offset, 1, RTP_READ_FILE_BYTES, m_file);
            if (read_len <= 0) {
                if (offset > 0) {
                    //last nal cannot be parsed, just return remaining bytes
                    memcpy(buf, buf_read, offset);
                    parse_len = offset;
                    offset = 0;
                    return parse_len;
                }
                else {
                    //reach EOF or error happened, finish reading
                    goto finished;
                }
            }
            else {
                parse_len = parse_nal(buf_read, offset + read_len, &startcode_len);
                if (parse_len > startcode_len) {
                    memcpy(buf, buf_read + startcode_len, parse_len - startcode_len);
                    offset =  offset + read_len - parse_len;
                    memcpy(buf_read, buf_read + parse_len, offset);
                }
                else if (parse_len == 0) {
                    offset += read_len;
                }
                else {
                    //Invalid buffer or buffer length
                    return -1;
                }
            }
        }
    }
    else {
        printf ("unsupport payload type: %d\n", payload_type);
        return -1;
    }

    return parse_len - startcode_len;

finished:
    *eof = true;
    delete []buf_read;
    return 0;
}

RTP_RETCODE rtpencoder::start()
{
    if (rtp_get_state() != RTP_STATE_READY) {
        printf("Invalid state\n"); 
        return RTP_ERROR;
    }

    rtp_set_state(RTP_STATE_EXECUTING);

    pthread_create(&m_rtpencoder_tid, NULL, &worker_func, this);
    pthread_detach(m_rtpencoder_tid);

    //mark start time
    m_base_time = get_cur_time();

    return RTP_SUCCESS;
}

RTP_RETCODE rtpencoder::stop()
{
    rtp_set_state(RTP_STATE_READY);

    return RTP_SUCCESS;
}
