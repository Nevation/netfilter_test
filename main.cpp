#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#define true 	1
#define false 	0
char* host = NULL;
int host_size = -1;

struct PKT_TYPE{
	u_int32_t id;
	int type;
};


int check_host(const unsigned char* data){
	for (int i=0; i < host_size; i++){
		if (data[i] != host[i]){
			return false;
		}
	}
	return true;
}

/* returns packet id */
static PKT_TYPE get_packet_type (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;
	
	ph = nfq_get_msg_packet_hdr(tb);
	
	if (ph) id = ntohl(ph->packet_id);
	hwph = nfq_get_packet_hw(tb);
	ret = nfq_get_payload(tb, &data);

	int IPHEADER_SIZE = (data[0] & 0x0f) * 4;
	data += IPHEADER_SIZE;

	PKT_TYPE type;
	type.id = id;
	type.type = true;

	// Check Dest Port 80
	if (data[2] == 0x00 && data[3] == 0x50){
		int TCPHEADER_SIZE = ((data[12] & 0xf0) >> 4) * 4;
		data += TCPHEADER_SIZE;

		// for loop find host
		for (int i=0; i < ret - IPHEADER_SIZE - TCPHEADER_SIZE; i++){
			if (data[i] == host[0]){
				if (check_host(&data[i])){
					type.type = false;
					break;
				}
			}
		}	
	} 

	return type;
}
	
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	PKT_TYPE type = get_packet_type(nfa);

	printf("\nPacket received\n");
	if (type.type == true){
		printf("[Accept]\n");
		printf("Accept Packet\n\n");
		return nfq_set_verdict(qh, type.id, NF_ACCEPT, 0, NULL);
	} else {
		printf("[Drop]\n");
		printf("Drop Packet Host: %s\n\n", host);
		return nfq_set_verdict(qh, type.id, NF_DROP, 0, NULL);
	}
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));
	
	if (argc != 2){
		printf("Usage: %s <host>\n", argv[0]);
		return -1;
	}
	
	host = argv[1];
	host_size = sizeof(host);
	
	if (host_size == -1){
		printf("Error Host size : %s\n", host);
		return -1;
	}


	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

