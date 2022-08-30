/*
 * BPF TEST 1
 * THIS PROGRAM TESTS THE BPF VIRTUAL DEVICE
 *
 * BASED ON BASTIAN RIECK POST (https://bastian.rieck.me/blog/posts/2009/bpf/) 
 */

#include <stdlib.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <unistd.h>

/* FUNCTION DECLARATION */
void open_bpf(void);
void associate_device(const char *interface);
void activate_immediate_mode();
void request_buffer_length();

/* ETHERNET FRAME STRUCT */
struct ethernet_frame
{
  unsigned char dest_addr[6];
  unsigned char src_addr[6];
  unsigned char type[2];
};

/* GLOBAL VARIABLES */
int             bpf = 0;        /* BPF DEVICE NUMBER */
struct ifreq    bound_if;       /* INTERFACE STRUCT */
int             buf_len = 1;    /* BUFFER LENGTH */

/* OPEN BPF */
void open_bpf(void) {
        int i;
        char buf[11] = {0};

        for(i=0; i<99; i++) {
                sprintf(buf, "/dev/bpf%i", i);
                bpf = open(buf, O_RDWR);
                if(bpf!=-1)
                        break;
        }
}

/* ASSOCIATE BPF WITH DEVICE */
void associate_device(const char *interface) {

        struct ifreq    bound_if;

        strcpy(bound_if.ifr_name, interface);
        if( ioctl( bpf, BIOCSETIF,  &bound_if ) > 0 ) {
                fprintf(stderr, "ERROR: Can not bound BPF to interface\n");
                exit(1);
        }

}

/* ACTIVATE IMMEDIATE MODE */
void activate_immediate_mode() {

        if( ioctl( bpf, BIOCIMMEDIATE, &buf_len ) == -1 ) {
                fprintf(stderr, "ERROR: Can not activate immediate mode\n");
                exit(1);
        }

}

/* REQUEST BUFFER LENGTH */
void request_buffer_length() {

        if( ioctl( bpf, BIOCGBLEN, &buf_len ) == -1 ) {
                fprintf(stderr, "ERROR: Can not request buffer length\n");
                exit(1);
        }

}

/* MAIN SUBROUTINE */
int main() {

        int read_bytes = 0;
        struct ethernet_frame* frame;
        struct bpf_hdr* bpf_buf = malloc(sizeof(struct bpf_hdr)*buf_len);
        struct bpf_hdr* bpf_packet;

        /* OPEN BPF */
        open_bpf();

        /* ASSOCIATE WITH INTERFACE */
        associate_device("em0");

        /* ACTIVATE IMMEDIATE MODE */
        activate_immediate_mode();

        /* REQUEST BUFFER LENGTH */
        request_buffer_length();

        /* READ DATA */
        while(1) {
                memset(bpf_buf, 0, buf_len);

                if((read_bytes = read(bpf, bpf_buf, buf_len)) > 0) {
                        int i = 0;

                        // read all packets that are included in bpf_buf. BPF_WORDALIGN is used
                        // to proceed to the next BPF packet that is available in the buffer.

                        char* ptr = (char*)(bpf_buf);
                        while(ptr < (char*)(bpf_buf) + read_bytes) {
                                bpf_packet = (struct bpf_hdr*)(ptr);
                                frame = (struct ethernet_frame*)((char*) bpf_packet + bpf_packet->bh_hdrlen);

                                printf("RX %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %02X%02X\n", 
                                        frame->dest_addr[0], 
                                        frame->dest_addr[1], 
                                        frame->dest_addr[2], 
                                        frame->dest_addr[3], 
                                        frame->dest_addr[4], 
                                        frame->dest_addr[5],
                                        frame->src_addr[0], 
                                        frame->src_addr[1], 
                                        frame->src_addr[2], 
                                        frame->src_addr[3], 
                                        frame->src_addr[4], 
                                        frame->src_addr[5],
                                        frame->type[0],
                                        frame->type[1]
                                );

                                ptr += BPF_WORDALIGN(bpf_packet->bh_hdrlen + bpf_packet->bh_caplen);
                        }
                }
        }
}
