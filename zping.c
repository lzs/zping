#include <libnet.h>
#include <stdio.h>
#include <math.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <netdb.h>


#define bcopy(s,d,l)    memcpy(d,s,l)
#define bzero(d,l)      memset(d,0,l)

#define SIZE_ICMP_HDR 8
#define IPHDRSIZE     sizeof (struct ip)
#define PKTBUF_SIZE   4096

    typedef struct host_entry {
        struct sockaddr_in  saddr;
	struct sockaddr_in  iaddr;
	int                 iprobed;
        int                 done;
        int                 seq;
        int                 num_packets_sent;
        int                 num_packets_received;
        struct host_entry   *prev, *next;
        struct timeval      last_time_sent;
        double              rtt_min, rtt_max;
        double              rtt_sum, rtt_ssq;
        unsigned char       mac[6];
    } HOST_ENTRY;

    extern char *optarg;
    extern int  optind, opterr;

    /* commandline things */
    char        *argv0;
    int         arp_flag = 0;
    int         debug_flag = 0;
    int         fast_flag = 0;
    int         quiet_flag = 0;
    int         summarize_flag = 0;
    int         verbose_flag = 1;
    char        *opt_filename = NULL;
    int         opt_interval = 1000;
    int         opt_pktlen = 64;
    int         opt_timeout = 2000; /* 2000 milliseconds */
    int         opt_count = -1;

    int         ident;
    int         nbase;
    int         num_hosts = 0;
    int         signal_break = 0;
    struct timeval break_time;
    HOST_ENTRY  **table=NULL;
    HOST_ENTRY  *rrlist=NULL;
    char        *pkt_buffer;

int send_ping (int s, HOST_ENTRY *h);
HOST_ENTRY* recv_arping (int s, int interval, int *timeout);
int recvfrom_wto (int s, char *buf, int len, struct sockaddr *saddr, int timo);
double timeval_diff (struct timeval *a, struct timeval *b);
int in_cksum (u_short *p, int n);
void add_host (char *host);
void parse_host (struct sockaddr_in *dst, const char *src);
int dot_count (const char *src);
void die (char *msg);
void die_with_errno (char *msg);
void usage (void);
int signalbreak (int sig);


int main (int argc, char *argv[])
{
    int  rs, s, i, c, send_interval;
    struct protoent *proto;
    struct timeval  current_time;
    HOST_ENTRY *cursor, *h;

    argv0 = argv[0];

    if (argc == 1) usage();

    if ((proto = getprotobyname ("icmp")) == NULL)
        die ("icmp: unknown protocol");

    /* socket created with root privileges */
    if ((s = socket (AF_INET, SOCK_RAW, proto->p_proto)) < 0)
        die ("socket(): cannot create inet raw socket");
    if ((rs = socket (PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
        die ("socket(): cannot create packet dgram socket");

    /* setuid back to the real user */
    setuid (getuid ());

    ident = getpid() & 0xFFFF;
    srandom(ident);
    nbase = random() % 256;

    verbose_flag = 0; /* not verbose by default, but verbose first so the
                         2 die() calls above will produce output */

    while ((c = getopt (argc, argv, "ac:dF:fhi:qSs:t:v")) != EOF) {
        switch (c) {
        case 'a':
            arp_flag = 1; break;
        case 'c':
            if ((opt_count = atoi (optarg)) == -1) usage (); break;
        case 'd':
            debug_flag = 1; break;
        case 'F':
            opt_filename = optarg; break;
        case 'f':
            fast_flag = 1; break;
        case 'h':
            usage (); break;
        case 'i':
            if ((opt_interval = atoi (optarg)) == -1) usage (); break;
        case 'q':
            quiet_flag = 1; break;
        case 'S':
            summarize_flag = 1; break;
        case 's':
            if ((opt_pktlen = atoi (optarg)) == -1) usage (); break;
        case 't':
            if ((opt_timeout = atoi (optarg)) == -1) usage (); break;
        case 'v':
            verbose_flag = 1; break;
        default:
            fprintf (stderr, "%s: unknown option -%c\n", argv0, c);
            usage (); break;
        }
    }

    /* check options are sane */
    if (opt_interval < 10) opt_interval = 10;
    if (opt_pktlen < 64) opt_pktlen = 64;
    if (opt_timeout < 100) opt_timeout = 100;
    if (opt_timeout > 10000) opt_timeout = 10000;

    opt_pktlen -= IPHDRSIZE;

    /* read list of hosts to ping */
    if (optind < argc) {
        /* host list is on command line */
        while (optind < argc)
            add_host (argv[optind++]);
    }
    if (opt_filename) {
        /* host list in file */
        FILE *fp;
        char line[132];
        int len;

        if (strcmp (opt_filename, "-") == 0)
            fp = fdopen (0, "r");
        else
            fp = fopen (opt_filename, "r");
        if (!fp) die_with_errno ("cannot open input file");
        while (fgets (line, sizeof (line), fp)) {
            len = strlen(line);
            if (len > 0) {
                if (line[len-1] == '\n')
                    line[len-1] = 0;
            }
            if ((line[0] == 0) || (line[0] == '#')) continue;
            add_host (line);
        }
        fclose (fp);
    }

    if (!num_hosts) usage ();

    if ((table = (HOST_ENTRY**) malloc (sizeof (HOST_ENTRY *) * num_hosts))
      == NULL)
        die ("cannot malloc host table");

    cursor = rrlist;
    for (i = 0; i < num_hosts; i++) {
        table[i] = cursor;
        cursor->seq = i;
        cursor = cursor->next;
    }

    (void) signal (SIGINT, (void (*)()) signalbreak);
    if ((pkt_buffer = malloc (PKTBUF_SIZE)) == NULL)
        die ("cannot malloc packet buffer");

    while (1) {
        gettimeofday (&current_time, NULL);

        if (signal_break) {
            /* user wants to abort, check if if we're past the timeout or
               if there is any outstanding ICMP_REPLY to receive */
            if (timeval_diff (&current_time, &break_time) > opt_timeout)
                break;
            else {
                for (i = 0, c = 0; i < num_hosts; i++) {
                    if (cursor->num_packets_sent ==
                      cursor->num_packets_received)
                        c++;
                    cursor = cursor->next;
                }
                if (c == num_hosts) break;
            }
        }
        else {
            /* user has not aborted, try to send some ping packets */
            for (i = 0, c = 0; i < num_hosts; i++) {
                /* cycle through ring, looking for work to do */
                if (cursor->done)
                    c++;
                else if (opt_count == -1 ||
                  cursor->num_packets_sent < opt_count) {
                    if (timeval_diff (&current_time, &cursor->last_time_sent) >
                      opt_interval) {
                        if (arp_flag)
                            send_arp (s, cursor);
                        send_ping (s, cursor);
                        break;
                    }
                }
                else {
                    if (timeval_diff (&current_time, &cursor->last_time_sent) >
                      opt_timeout) {
                        cursor->done = 1;
                        c++;
                    }
                }
                cursor = cursor->next;
            }
            if (c == num_hosts) break;
        }

	while (1) {
	    int timeout = 0;

	    h = recv_arping(rs, 10, &timeout);

	    if (h != NULL) {
                if (opt_count == -1 ||
		    (h != NULL && h->num_packets_sent < opt_count)) {
                    if (fast_flag && !signal_break) {
                        if (arp_flag)
                            send_arp (s, cursor);
                        send_ping (s, h);
                    }
		}
                else h->done = 1;
            }
	    else if (timeout == 1) {
	        break;
	    }
        }
    }
    free (pkt_buffer);

    close(s);
    close(rs);

    for (i=0; i < num_hosts; i++) {
        char *str;
        double avg, std;

        h = table[i];
        avg = h->num_packets_received ?
              h->rtt_sum / h->num_packets_received : 0.0;
        std = h->rtt_ssq - (avg * h->rtt_sum);
        std = h->num_packets_received ?
              sqrt (std / h->num_packets_received) : 0.0;

        if (arp_flag) {
            if (!summarize_flag)
                str =
                  "--- %s ping statistics ---\n"
                  "%d packets transmitted, %d packets received, %.1lf%% packet loss\n"
                  "round-trip (ms) min/avg/max = %.2lf/%.2lf/%.2lf (std = %.1lf)\n"
                  "ethernet = %02x:%02x:%02x:%02x:%02x:%02x\n";
            else
                str = "%s %d %d %.1lf %.2lf %.2lf %.2lf %.1lf %02x:%02x:%02x:%02x:%02x:%02x\n";
            printf (str,
              inet_ntoa (h->saddr.sin_addr),
              h->num_packets_sent, h->num_packets_received,
              (double)(1 - (double)h->num_packets_received/h->num_packets_sent)*100,
              h->rtt_min, avg, h->rtt_max, std, h->mac[0], h->mac[1], h->mac[2], h->mac[3], h->mac[4], h->mac[5]);
        }
	else {
            if (!summarize_flag)
                str =
                  "--- %s ping statistics ---\n"
                  "%d packets transmitted, %d packets received, %.1lf%% packet loss\n"
                  "round-trip (ms) min/avg/max = %.2lf/%.2lf/%.2lf (std = %.1lf)\n";
            else
                str = "%s %d %d %.1lf %.2lf %.2lf %.2lf %.1lf\n";
            printf (str,
              inet_ntoa (h->saddr.sin_addr),
              h->num_packets_sent, h->num_packets_received,
              (double)(1 - (double)h->num_packets_received/h->num_packets_sent)*100,
              h->rtt_min, avg, h->rtt_max, std);
        }
    }
    return (0);
}


int send_ping (int s, HOST_ENTRY *h)
{
    struct icmp *icp;
    int    n, len;

//    printf ("send ping to: %s\n", inet_ntoa (h->saddr.sin_addr));

    icp = (struct icmp *) pkt_buffer;
    icp->icmp_type = ICMP_ECHO;
    icp->icmp_code = 0;
    icp->icmp_cksum = 0;

    // Note that this is NOT used as the ICMP sequence number, but
    // rather an index into our table of hosts to ping.
    icp->icmp_seq = h->seq + nbase;;
    
    icp->icmp_id = ident;
    gettimeofday (&h->last_time_sent, NULL);
    bcopy(&h->last_time_sent,&pkt_buffer[SIZE_ICMP_HDR],
          sizeof (h->last_time_sent));
    bcopy(&h->num_packets_sent,
          &pkt_buffer[SIZE_ICMP_HDR+sizeof (h->last_time_sent)],
          sizeof (h->num_packets_sent));

    len = SIZE_ICMP_HDR + sizeof (h->last_time_sent) +
          sizeof (h->num_packets_sent);

    icp->icmp_cksum = in_cksum( (u_short *)icp, opt_pktlen);

    n = sendto( s, pkt_buffer, opt_pktlen, 0,
        (struct sockaddr *)&h->saddr, sizeof(struct sockaddr_in) );
    if( n < 0 || n != opt_pktlen ) {
        /* report error with this host */
    }
    else {
        h->num_packets_sent++;
    }

    return (0);
}

int send_arp (int s, HOST_ENTRY *h)
{
    int err;
    u_char enet_bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    u_char enet_src[6];
    int c;
    u_long i;
    libnet_t *l;
    libnet_ptag_t t;
    char *device = NULL;
    char errbuf[LIBNET_ERRBUF_SIZE];
    int probe_fd;
    struct sockaddr_in saddr;
    int one = 1;
    int alen = sizeof(saddr);
    struct ifreq ifr;
    int ifindex, ss;
    struct sockaddr_ll me, he;
    unsigned char buf[256];
    struct arphdr *ah = (struct arphdr *) buf;
    unsigned char *p = (unsigned char *) (ah+1);

    ss = socket(PF_PACKET, SOCK_DGRAM, 0);

    if (h->iprobed == 0) {
	    
        probe_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (probe_fd < 0) {
            perror("socket()");
            exit;
        }
        memset(&saddr, 0, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_port = htons(1025);
        saddr.sin_addr = h->saddr.sin_addr;
        if (setsockopt(probe_fd, SOL_SOCKET, SO_DONTROUTE, (char *) &one, sizeof(one)) == -1)
            perror("WARNING: setsockopt(SO_DONTROUTE)");
        if (connect(probe_fd, (struct sockaddr *) &saddr, sizeof(saddr)) == -1) {
            perror("connect");
            return;
        }
        if (getsockname(probe_fd, (struct sockaddr *) &saddr, &alen) == -1) {
            perror("getsockname");
            exit(2);
        }
        close(probe_fd);
	h->iaddr.sin_addr = saddr.sin_addr;
	h->iprobed = 1;
    }

    l = libnet_init(
            LIBNET_LINK_ADV,                            /* injection type */
            inet_ntoa(h->iaddr.sin_addr),               /* network interface */
            errbuf);                                /* errbuf */
    if (l == NULL)
    {
        fprintf(stderr, "libnet_init() failed: %s", errbuf);
        exit(EXIT_FAILURE);
    }
        
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, l->device, IFNAMSIZ - 1);
    if (ioctl(ss, SIOCGIFINDEX, &ifr) < 0) {
        printf("Interface %s not found", l->device);
        exit(2);
    }
    ifindex = ifr.ifr_ifindex;
    me.sll_family = AF_PACKET;
    me.sll_ifindex = ifindex;
    me.sll_protocol = htons(ETH_P_ARP);
    if (bind(ss, (struct sockaddr *) &me, sizeof(me)) == -1) {
        perror("bind");
	close(ss);
        exit(2);
    }
    alen = sizeof(me);
    if (getsockname(ss, (struct sockaddr *) &me, &alen) == -1) {
        perror("getsockname()");
	close(ss);
        exit(2);
    }
    ah->ar_hrd = htons(me.sll_hatype);
    ah->ar_hrd = htons(ARPHRD_ETHER);
    ah->ar_pro = htons(ETH_P_IP);
    ah->ar_hln = me.sll_halen;
    ah->ar_pln = 4;
    ah->ar_op = htons(ARPOP_REQUEST);
    memcpy(p, &me.sll_addr, ah->ar_hln);
    p += me.sll_halen;
    memcpy(p, &saddr.sin_addr, 4);
    p += 4;
    memcpy(p, enet_bcast, ah->ar_hln);
    p += ah->ar_hln;
    memcpy(p, &h->saddr.sin_addr, 4);
    p += 4;
    he = me;
    memcpy(&he.sll_addr, enet_bcast, sizeof(he.sll_addr));
//for (i = 0; i < p-buf; i++) {
//    printf("%02x ", (unsigned char) buf[i]);
//}
//printf("\n");
    err = sendto(ss, buf, p-buf, 0, (struct sockaddr *) &he, sizeof(me));
    close(ss);

    libnet_destroy(l);

    return (EXIT_SUCCESS);
}

HOST_ENTRY* recv_arping (int s, int interval, int *timeout)
{
    int result, n, i;
    int hlen, seq;
    struct arphdr *ah;
    struct sockaddr_ll response_addr;
    struct ip *ip;
    struct icmp *icp;
    HOST_ENTRY *h;
    double rtt;
    struct timeval sent_time, current_time;

    result = recvfrom_wto (s, (void *) pkt_buffer, PKTBUF_SIZE,
               (struct sockaddr *) &response_addr, interval);
    if (result < 0) {
	*timeout = 1;
	return (NULL); /* timeout */
    }

    gettimeofday (&current_time, NULL);

    if (pkt_buffer[12] == 8 && pkt_buffer[13] == 0) {
        ip = (struct ip*) (pkt_buffer + 14);
#if defined(__alpha__) && __STDC__
      /* The alpha headers are decidedly broken.
       * Using an ANSI compiler, it provides ip_vhl instead of ip_hl and
       * ip_v.  So, to get ip_hl, we mask off the bottom four bits.
       */
      hlen = (ip->ip_vhl & 0x0F) << 2;
#else
      hlen = ip->ip_hl << 2;
#endif
        /*hlen = ip->ip_hl;
        hlen <<= 2;*/
        if (result < hlen+ICMP_MINLEN) {
            printf("DEBUG: Discarding ICMP packet too short.\n");
	    return (NULL); /* too short */
	}

        icp = (struct icmp*) ((void *) ip + hlen);

        if (icp->icmp_type != ICMP_ECHOREPLY) {
	    return NULL;
	}
	if (icp->icmp_id != ident) {
            return NULL; /* not our ping packet */
        }

        n = icp->icmp_seq - nbase;
	if (n < 0 || n >= num_hosts)
            return;
        h = table[n];

        bcopy (&icp->icmp_data[0], &sent_time, sizeof (sent_time));
        bcopy (&icp->icmp_data[sizeof (h->last_time_sent)], &seq,
          sizeof (h->num_packets_sent));
        /* one more item in icmp_data, no use for it? */

        h->num_packets_received++;
        rtt = timeval_diff (&current_time, &sent_time);
        if (rtt > h->rtt_max) h->rtt_max = rtt;
        if (rtt < h->rtt_min) h->rtt_min = rtt;
        h->rtt_sum += (double) rtt;
        h->rtt_ssq += (double) rtt * (double) rtt;
        if (!quiet_flag)
            printf ("%d bytes from %s: icmp_seq=%d ttl=%d time=%.1lf ms\n", 
              result, inet_ntoa (h->saddr.sin_addr), seq, ip->ip_ttl, rtt);

        return h;
    }
    else if (pkt_buffer[12] == 8 && pkt_buffer[13] == 6) {
        struct in_addr src_ip;
        unsigned char *p;

        ah = (struct arphdr*) (pkt_buffer + 14);
        if (ah->ar_op != htons(ARPOP_REPLY)) {
            return NULL;
        }
        if (ah->ar_pro != htons(ETH_P_IP))
                return NULL;
        if (ah->ar_pln != 4)
                return NULL;
        p = (unsigned char*) (ah + 1);
        memcpy(&src_ip, (unsigned char *) p + ah->ar_hln, 4);

        for (i = 0; i < num_hosts; i++) {
            if (memcmp(&table[i]->saddr.sin_addr,  &src_ip, sizeof(src_ip)) == 0) {
                memcpy(table[i]->mac, p, 6);
                break;
            }
        }
        if (i == num_hosts) return NULL;
        return NULL;
    }
}


int recvfrom_wto (int s, char *buf, int len, struct sockaddr *saddr, int timo)
{
    int nfound, slen, n;
    struct timeval to;
    fd_set readset, writeset;

    to.tv_sec = timo/1000;
    to.tv_usec = (timo - (to.tv_sec * 1000)) * 1000;

    FD_ZERO (&readset);
    FD_ZERO (&writeset);
    FD_SET (s, &readset);

    nfound = select (s+1, &readset, &writeset, NULL, &to);
//    if (nfound < 0) die_with_errno ("select()");
    if (nfound < 0) return -1;
    if (nfound == 0) return -1; /* timeout */
    slen = sizeof (struct sockaddr);
    n = recvfrom (s, buf, len, 0, saddr, &slen);
    if (n < 0) die_with_errno ("recvfrom()");
    return n;
}


double timeval_diff (struct timeval *a, struct timeval *b)
{
    double temp;

    /* calculate difference in milliseconds */
    temp = ((((double)a->tv_sec*1000000) + (double)a->tv_usec) -
            (((double)b->tv_sec*1000000) + (double)b->tv_usec)) / 1000;

    return (double) temp;
}


int in_cksum (u_short *p, int n)
{
    register u_short answer;
    register long sum = 0;
    u_short odd_byte = 0;

    while (n > 1) {
        sum += *p++;
        n -= 2;
    }

    /* mop up an odd byte, if necessary */
    if( n == 1 ) {
        *(u_char *)(&odd_byte) = *(u_char *)p;
        sum += odd_byte;
    }

    sum = (sum >> 16) + (sum & 0xffff);   /* add hi 16 to low 16 */
    sum += (sum >> 16);                   /* add carry */
    answer = ~sum;                        /* ones-complement, truncate*/
    return (answer);
}


void add_host (char *host)
{
    HOST_ENTRY *h;
    struct hostent *host_ent;

    if ((h = malloc (sizeof (HOST_ENTRY))) == NULL)
        die ("cannot allocate host entry");

    bzero (h, sizeof (*h));

    parse_host (&h->saddr, host);
    h->rtt_min = opt_timeout + 1;

    if (!rrlist) {
        rrlist = h;
        h->next = h->prev = h;
    }
    else {
        h->next = rrlist;
        h->prev = rrlist->prev;
        h->prev->next = h;
        h->next->prev = h;
        rrlist = h;
    }
    num_hosts++;
}


void parse_host (struct sockaddr_in *dst, const char *src)
{
    unsigned long   ip;

    memset (dst, 0, sizeof (*dst));

    ip = inet_addr (src);
    if (ip != -1 && dot_count (src) == 3) {
        dst->sin_family = AF_INET;
        dst->sin_addr.s_addr = ip;
    }
    else {
        struct hostent *host;

        host = gethostbyname (src);
        if (host == NULL) {
            perror ("gethostbyname()");
            exit (1);
        }
        dst->sin_family = host->h_addrtype;
        memcpy (&dst->sin_addr, host->h_addr, host->h_length);
    }
}


int dot_count (const char *src)
{
    int n;

    n = 0;
    while (*src != 0)
        if (*src++ == '.') ++n;
    return (n);
}


void die (char *msg)
{
    if (verbose_flag) fprintf(stderr,"%s: %s\n", argv0, msg);
    exit (1);
}


void die_with_errno (char *msg)
{
    if (verbose_flag)
        fprintf (stderr, "%s, %s: %s\n", argv0, msg, strerror(errno));
    exit (1);
}


void usage (void)
{
    fprintf (stderr, "Usage: %s [options] [hosts...]\n", argv0);
    fprintf (stderr,
"  -a        send and report ARP information\n"
"  -c count  number of ping packets to send per host\n"
"  -F file   read host list from file\n"
"  -f        fast ping, send next packet as soon as reply is received\n"
"  -h        print this help\n"
"  -i        interval between ping packets sent in milliseconds\n"
"  -q        quiet mode, do not print individual replies\n"
"  -S        summarize results, one host per line\n"
"  -s        size of packet\n"
"  -t        individual host timeout in milliseconds\n"
"  -v        verbose mode\n"
    );
    exit (3);

}


int signalbreak (int sig)
{
    int save_errno = errno;

    gettimeofday (&break_time, NULL);
    signal_break = 1;

    (void) signal (SIGINT, SIG_DFL);

    errno = save_errno;
    return (0);
}


