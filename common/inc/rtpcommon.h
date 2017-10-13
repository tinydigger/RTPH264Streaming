#ifndef _RTPCOMMON_H
#define _RTPCOMMON_H

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

#define MTU_SIZE 1500
#define RTP_H264_MAX_PKT_SIZE MTU_SIZE
#define RTP_HDR_SIZE 12
#define RTP_H264_MAX_NAL_DATA_SIZE (RTP_H264_MAX_PKT_SIZE - RTP_HDR_SIZE)


//only support H264 payload now
typedef enum RTP_PAYLOAD_TYPE
{
    RTP_PAYLOAD_MPEG2_TS = 33,
    RTP_PAYLOAD_H264 = 96
} RTP_PAYLOAD_TYPE;

//parameters to setup rtp streaming
typedef struct RTP_SETUP_INFO
{
    uint32_t addr;
    uint32_t localport;
    uint32_t destport;
    RTP_PAYLOAD_TYPE payloadtype;
} RTP_SETUP_INFO;

typedef struct RTP_PKT_INFO
{
    uint32_t payloadtype;
    uint32_t ssrc;
    uint16_t sequenceno;
} RTP_PKT_INFO;

typedef enum RTP_RETCODE
{
    RTP_SUCCESS = 0,
    RTP_ERROR,
    RTP_BUSY
} RTP_RETCODE;

typedef enum RTP_STATE
{
    RTP_STATE_INIT,
    RTP_STATE_READY,
    RTP_STATE_PAUSE,
    RTP_STATE_EXECUTING
} RTP_STATE;

typedef enum RTPH264_MODE
{
    SINGLE_NAL_MODE,
    FU_A_MODE
} RTPH264_MODE;

typedef enum RTPH264_HEADER_TYPE
{
    STAP_A = 24,
    STAP_B = 25,
    MTAP16 = 26,
    MTAP24 = 27,
    FU_A = 28,
    FU_B = 29
} RTPH264_HEADER_TYPE;

typedef struct nalu_header
{
    uint8_t type:   5;
    uint8_t nri:    2;
    uint8_t f:      1;
} __attribute__ ((packed)) nalu_header_t;

typedef struct nalu
{
    int startcodeprefix_len;
    unsigned len;
    unsigned max_size;
    int forbidden_bit;
    int nal_reference_idc;
    int nal_unit_type;
    char *buf;
    unsigned short lost_packets;
} nalu_t;

typedef struct fu_indicator
{
    uint8_t type:   5;
    uint8_t nri:    2; 
    uint8_t f:      1;    
} __attribute__ ((packed)) fu_indicator_t;

typedef struct fu_header
{
    uint8_t type:   5;
    uint8_t r:      1;
    uint8_t e:      1;
    uint8_t s:      1;    
} __attribute__ ((packed)) fu_header_t;

#endif
