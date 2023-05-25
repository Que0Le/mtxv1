// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2017 - 2022 Intel Corporation. */
#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <linux/bpf.h>
#include <linux/err.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/limits.h>
#include <linux/udp.h>
#include <arpa/inet.h>
#include <locale.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <sched.h>

#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xdpsock.h"
#include "helpers.h"

int use_opt_file = 0;
char *hostname = "";

static struct option long_options[] = {
	{"rxdrop", no_argument, 0, 'r'},
	{"txonly", no_argument, 0, 't'},
	{"l2fwd", no_argument, 0, 'l'},
	{"interface", required_argument, 0, 'i'},
	{"queue", required_argument, 0, 'q'},
	{"poll", no_argument, 0, 'p'},
	{"xdp-skb", no_argument, 0, 'S'},
	{"xdp-native", no_argument, 0, 'N'},
	{"interval", required_argument, 0, 'n'},
	{"retries", required_argument, 0, 'O'},
	{"zero-copy", no_argument, 0, 'z'},
	{"copy", no_argument, 0, 'c'},
	{"frame-size", required_argument, 0, 'f'},
	{"no-need-wakeup", no_argument, 0, 'm'},
	{"unaligned", no_argument, 0, 'u'},
	{"shared-umem", no_argument, 0, 'M'},
	{"force", no_argument, 0, 'F'},
	{"duration", required_argument, 0, 'd'},
	{"clock", required_argument, 0, 'w'},
	{"batch-size", required_argument, 0, 'b'},
	{"tx-pkt-count", required_argument, 0, 'C'},
	{"tx-pkt-size", required_argument, 0, 's'},
	{"tx-pkt-pattern", required_argument, 0, 'P'},
	{"tx-vlan", no_argument, 0, 'V'},
	{"tx-vlan-id", required_argument, 0, 'J'},
	{"tx-vlan-pri", required_argument, 0, 'K'},
	{"tx-dmac", required_argument, 0, 'G'},
	{"tx-smac", required_argument, 0, 'H'},
	{"tx-cycle", required_argument, 0, 'T'},
	{"tstamp", no_argument, 0, 'y'},
	{"policy", required_argument, 0, 'W'},
	{"schpri", required_argument, 0, 'U'},
	{"extra-stats", no_argument, 0, 'x'},
	{"quiet", no_argument, 0, 'Q'},
	{"app-stats", no_argument, 0, 'a'},
	{"irq-string", no_argument, 0, 'I'},
	{"busy-poll", no_argument, 0, 'B'},
	{"reduce-cap", no_argument, 0, 'R'},
	{0, 0, 0, 0}
};

static void usage(const char *prog)
{
	const char *str =
		"  Usage: %s [OPTIONS]\n"
		"  Options:\n"
		"  -h, --hostname	Host name. This is used to append to the env file (default empty)\n"
		"  -r, --rxdrop		Discard all incoming packets (default)\n"
		"  -t, --txonly		Only send packets\n"
		"  -l, --l2fwd		MAC swap L2 forwarding\n"
		"  -i, --interface=n	Run on interface n\n"
		"  -q, --queue=n	Use queue n (default 0)\n"
		"  -p, --poll		Use poll syscall\n"
		"  -S, --xdp-skb=n	Use XDP skb-mod\n"
		"  -N, --xdp-native=n	Enforce XDP native mode\n"
		"  -n, --interval=n	Specify statistics update interval (default 1 sec).\n"
		"  -O, --retries=n	Specify time-out retries (1s interval) attempt (default 3).\n"
		"  -z, --zero-copy      Force zero-copy mode.\n"
		"  -c, --copy           Force copy mode.\n"
		"  -m, --no-need-wakeup Turn off use of driver need wakeup flag.\n"
		"  -f, --frame-size=n   Set the frame size (must be a power of two in aligned mode, default is %d).\n"
		"  -u, --unaligned	Enable unaligned chunk placement\n"
		"  -M, --shared-umem	Enable XDP_SHARED_UMEM (cannot be used with -R)\n"
		"  -d, --duration=n	Duration in secs to run command.\n"
		"			Default: forever.\n"
		"  -w, --clock=CLOCK	Clock NAME (default MONOTONIC).\n"
		"  -b, --batch-size=n	Batch size for sending or receiving\n"
		"			packets. Default: %d\n"
		"  -C, --tx-pkt-count=n	Number of packets to send.\n"
		"			Default: Continuous packets.\n"
		"  -s, --tx-pkt-size=n	Transmit packet size.\n"
		"			(Default: %d bytes)\n"
		"			Min size: %d, Max size %d.\n"
		"  -P, --tx-pkt-pattern=nPacket fill pattern. Default: 0x%x\n"
		"  -V, --tx-vlan        Send VLAN tagged  packets (For -t|--txonly)\n"
		"  -J, --tx-vlan-id=n   Tx VLAN ID [1-4095]. Default: %d (For -V|--tx-vlan)\n"
		"  -K, --tx-vlan-pri=n  Tx VLAN Priority [0-7]. Default: %d (For -V|--tx-vlan)\n"
		"  -G, --tx-dmac=<MAC>  Dest MAC addr of TX frame in aa:bb:cc:dd:ee:ff format (For -V|--tx-vlan)\n"
		"  -H, --tx-smac=<MAC>  Src MAC addr of TX frame in aa:bb:cc:dd:ee:ff format (For -V|--tx-vlan)\n"
		"  -T, --tx-cycle=n     Tx cycle time in micro-seconds (For -t|--txonly).\n"
		"  -y, --tstamp         Add time-stamp to packet (For -t|--txonly).\n"
		"  -W, --policy=POLICY  Schedule policy. Default: SCHED_OTHER\n"
		"  -U, --schpri=n       Schedule priority. Default: %d\n"
		"  -x, --extra-stats	Display extra statistics.\n"
		"  -Q, --quiet          Do not display any stats.\n"
		"  -a, --app-stats	Display application (syscall) statistics.\n"
		"  -I, --irq-string	Display driver interrupt statistics for interface associated with irq-string.\n"
		"  -B, --busy-poll      Busy poll.\n"
		"  -R, --reduce-cap	Use reduced capabilities (cannot be used with -M)\n"
		"\n";
	fprintf(stderr, str, prog, XSK_UMEM__DEFAULT_FRAME_SIZE,
		opt_batch_size, MIN_PKT_SIZE, MIN_PKT_SIZE,
		XSK_UMEM__DEFAULT_FRAME_SIZE, opt_pkt_fill_pattern,
		VLAN_VID__DEFAULT, VLAN_PRI__DEFAULT,
		SCHED_PRI__DEFAULT);

	exit(EXIT_FAILURE);
}

static void parse_command_line(int argc, char **argv)
{
	int option_index, c;

	opterr = 0;

	for (;;) {
		c = getopt_long(argc, argv,
				"h:rtli:q:pSNn:w:O:czf:muMd:b:C:s:P:VJ:K:G:H:T:yW:U:xQaI:BR",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			hostname = optarg;
		case 'r':
			opt_bench = BENCH_RXDROP;
			break;
		case 't':
			opt_bench = BENCH_TXONLY;
			break;
		case 'l':
			opt_bench = BENCH_L2FWD;
			break;
		case 'i':
			opt_if = optarg;
			break;
		case 'q':
			opt_queue = atoi(optarg);
			break;
		case 'p':
			opt_poll = 1;
			break;
		case 'S':
			opt_attach_mode = XDP_MODE_SKB;
			opt_xdp_bind_flags |= XDP_COPY;
			break;
		case 'N':
			/* default, set below */
			break;
		case 'n':
			opt_interval = atoi(optarg);
			break;
		case 'w':
			if (get_clockid(&opt_clock, optarg)) {
				fprintf(stderr,
					"ERROR: Invalid clock %s. Default to CLOCK_MONOTONIC.\n",
					optarg);
				opt_clock = CLOCK_MONOTONIC;
			}
			break;
		case 'O':
			opt_retries = atoi(optarg);
			break;
		case 'z':
			opt_xdp_bind_flags |= XDP_ZEROCOPY;
			break;
		case 'c':
			opt_xdp_bind_flags |= XDP_COPY;
			break;
		case 'u':
			opt_umem_flags |= XDP_UMEM_UNALIGNED_CHUNK_FLAG;
			opt_unaligned_chunks = 1;
			opt_mmap_flags = MAP_HUGETLB;
			break;
		case 'f':
			opt_xsk_frame_size = atoi(optarg);
			break;
		case 'm':
			opt_need_wakeup = false;
			opt_xdp_bind_flags &= ~XDP_USE_NEED_WAKEUP;
			break;
		case 'M':
			opt_num_xsks = MAX_SOCKS;
			break;
		case 'd':
			opt_duration = atoi(optarg);
			opt_duration *= 1000000000;
			break;
		case 'b':
			opt_batch_size = atoi(optarg);
			break;
		case 'C':
			opt_pkt_count = atoi(optarg);
			break;
		case 's':
			opt_pkt_size = atoi(optarg);
			if (opt_pkt_size > (XSK_UMEM__DEFAULT_FRAME_SIZE) ||
			    opt_pkt_size < MIN_PKT_SIZE) {
				fprintf(stderr,
					"ERROR: Invalid frame size %d\n",
					opt_pkt_size);
				usage(basename(argv[0]));
			}
			break;
		case 'P':
			opt_pkt_fill_pattern = strtol(optarg, NULL, 16);
			break;
		case 'V':
			opt_vlan_tag = true;
			break;
		case 'J':
			opt_pkt_vlan_id = atoi(optarg);
			break;
		case 'K':
			opt_pkt_vlan_pri = atoi(optarg);
			break;
		case 'G':
			if (!ether_aton_r(optarg,
					  (struct ether_addr *)&opt_txdmac)) {
				fprintf(stderr, "Invalid dmac address:%s\n",
					optarg);
				usage(basename(argv[0]));
			}
			break;
		case 'H':
			if (!ether_aton_r(optarg,
					  (struct ether_addr *)&opt_txsmac)) {
				fprintf(stderr, "Invalid smac address:%s\n",
					optarg);
				usage(basename(argv[0]));
			}
			break;
		case 'T':
			opt_tx_cycle_ns = atoi(optarg);
			opt_tx_cycle_ns *= NSEC_PER_USEC;
			break;
		case 'y':
			opt_tstamp = 1;
			break;
		case 'W':
			if (get_schpolicy(&opt_schpolicy, optarg)) {
				fprintf(stderr,
					"ERROR: Invalid policy %s. Default to SCHED_OTHER.\n",
					optarg);
				opt_schpolicy = SCHED_OTHER;
			}
			break;
		case 'U':
			opt_schprio = atoi(optarg);
			break;
		case 'x':
			opt_extra_stats = 1;
			break;
		case 'Q':
			opt_quiet = 1;
			break;
		case 'a':
			opt_app_stats = 1;
			break;
		case 'I':
			opt_irq_str = optarg;
			if (get_interrupt_number())
				irqs_at_init = get_irqs();
			if (irqs_at_init < 0) {
				fprintf(stderr, "ERROR: Failed to get irqs for %s\n", opt_irq_str);
				usage(basename(argv[0]));
			}
			break;
		case 'B':
			opt_busy_poll = 1;
			break;
		case 'R':
			opt_reduced_cap = true;
			break;
		default:
			usage(basename(argv[0]));
		}
	}

	if (!use_opt_file) {
		opt_ifindex = if_nametoindex(opt_if);
		if (!opt_ifindex) {
			fprintf(stderr, "ERROR: interface \"%s\" does not exist\n",
				opt_if);
			usage(basename(argv[0]));
		}
	}

	if ((opt_xsk_frame_size & (opt_xsk_frame_size - 1)) &&
	    !opt_unaligned_chunks) {
		fprintf(stderr, "--frame-size=%d is not a power of two\n",
			opt_xsk_frame_size);
		usage(basename(argv[0]));
	}

	if (opt_reduced_cap && opt_num_xsks > 1) {
		fprintf(stderr, "ERROR: -M and -R cannot be used together\n");
		usage(basename(argv[0]));
	}
}

static void kick_tx(struct xsk_socket_info *xsk)
{
	int ret;

	ret = sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	if (ret >= 0 || errno == ENOBUFS || errno == EAGAIN ||
	    errno == EBUSY || errno == ENETDOWN)
		return;
	exit_with_error(errno);
}


static inline void complete_tx_only(struct xsk_socket_info *xsk,
				    int batch_size)
{
	unsigned int rcvd;
	u32 idx;

	if (!xsk->outstanding_tx)
		return;

	if (!opt_need_wakeup || xsk_ring_prod__needs_wakeup(&xsk->tx)) {
		xsk->app_stats.tx_wakeup_sendtos++;
		kick_tx(xsk);
	}

	rcvd = xsk_ring_cons__peek(&xsk->umem->cq, batch_size, &idx);
	if (rcvd > 0) {
		xsk_ring_cons__release(&xsk->umem->cq, rcvd);
		xsk->outstanding_tx -= rcvd;
	}
}

static void rx_drop(struct xsk_socket_info *xsk)
{
	unsigned int rcvd, i;
	u32 idx_rx = 0, idx_fq = 0;
	int ret;

	rcvd = xsk_ring_cons__peek(&xsk->rx, opt_batch_size, &idx_rx);
	if (!rcvd) {
		if (opt_busy_poll || xsk_ring_prod__needs_wakeup(&xsk->umem->fq)) {
			xsk->app_stats.rx_empty_polls++;
			recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
		}
		return;
	}

	ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
	while (ret != rcvd) {
		if (ret < 0)
			exit_with_error(-ret);
		if (opt_busy_poll || xsk_ring_prod__needs_wakeup(&xsk->umem->fq)) {
			xsk->app_stats.fill_fail_polls++;
			recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
		}
		ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
	}

	for (i = 0; i < rcvd; i++) {
		u64 addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
		u32 len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;
		u64 orig = xsk_umem__extract_addr(addr);

		addr = xsk_umem__add_offset_to_addr(addr);
		char *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

		process_rx_packet(pkt, len);
		hex_dump(pkt, len, addr);
		*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) = orig;
	}


	xsk_ring_prod__submit(&xsk->umem->fq, rcvd);
	xsk_ring_cons__release(&xsk->rx, rcvd);
	xsk->ring_stats.rx_npkts += rcvd;
}

static void rx_drop_all(void)
{
	struct pollfd fds[MAX_SOCKS] = {};
	int i, ret;

	for (i = 0; i < num_socks; i++) {
		fds[i].fd = xsk_socket__fd(xsks[i]->xsk);
		fds[i].events = POLLIN;
	}

	for (;;) {
		if (opt_poll) {
			for (i = 0; i < num_socks; i++)
				xsks[i]->app_stats.opt_polls++;
			ret = poll(fds, num_socks, opt_timeout);
			if (ret <= 0)
				continue;
		}

		for (i = 0; i < num_socks; i++)
			rx_drop(xsks[i]);

		if (benchmark_done)
			break;
	}
}

static int tx_only(struct xsk_socket_info *xsk, u32 *frame_nb,
		   int batch_size, unsigned long tx_ns, int socket_th)
{
	u32 idx;//, tv_sec, tv_usec;
	unsigned int i;

	while (xsk_ring_prod__reserve(&xsk->tx, batch_size, &idx) <
				      batch_size) {
		complete_tx_only(xsk, batch_size);
		if (benchmark_done)
			return 0;
	}

	for (i = 0; i < batch_size; i++) {
		struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx,
								  idx + i);
		tx_desc->addr = (*frame_nb + i) * opt_xsk_frame_size;
		tx_desc->len = PKT_SIZE;

		/* Prepare packet payload */
		u64 addr = tx_desc->addr;
		char *pkt;
		pkt = xsk_umem__get_data(xsk->umem->buffer, addr);
		create_custom_udp_packet(socket_th, (char *) pkt_data, NULL);
		memcpy(pkt, pkt_data, PKT_SIZE);	// copy to ring buffer
	}

	xsk_ring_prod__submit(&xsk->tx, batch_size);
	xsk->ring_stats.tx_npkts += batch_size;
	xsk->outstanding_tx += batch_size;
	*frame_nb += batch_size;
	*frame_nb %= NUM_FRAMES;
	complete_tx_only(xsk, batch_size);

	return batch_size;
}

static inline int get_batch_size(int pkt_cnt)
{
	if (!opt_pkt_count)
		return opt_batch_size;

	if (pkt_cnt + opt_batch_size <= opt_pkt_count)
		return opt_batch_size;

	return opt_pkt_count - pkt_cnt;
}


static void tx_only_all(void)
{
	struct pollfd fds[MAX_SOCKS] = {};
	u32 frame_nb[MAX_SOCKS] = {};
	unsigned long next_tx_ns = 0;
	int pkt_cnt = 0;
	int i, ret;

	if (opt_poll && opt_tx_cycle_ns) {
		fprintf(stderr,
			"Error: --poll and --tx-cycles are both set\n");
		return;
	}

	for (i = 0; i < num_socks; i++) {
		fds[0].fd = xsk_socket__fd(xsks[i]->xsk);
		fds[0].events = POLLOUT;
	}

	if (opt_tx_cycle_ns) {
		/* Align Tx time to micro-second boundary */
		next_tx_ns = (get_nsecs() / NSEC_PER_USEC + 1) *
			     NSEC_PER_USEC;
		next_tx_ns += opt_tx_cycle_ns;

		/* Initialize periodic Tx scheduling variance */
		tx_cycle_diff_min = 1000000000;
		tx_cycle_diff_max = 0;
		tx_cycle_diff_ave = 0.0;
	}

	printf("-------- tx_only_all num_socks %d -------\n", num_socks);
	while ((opt_pkt_count && pkt_cnt < opt_pkt_count) || !opt_pkt_count) {
		int batch_size = get_batch_size(pkt_cnt);
		unsigned long tx_ns = 0;
		struct timespec next;
		int tx_cnt = 0;
		long diff;
		int err;

		if (opt_poll) {
			for (i = 0; i < num_socks; i++)
				xsks[i]->app_stats.opt_polls++;
			ret = poll(fds, num_socks, opt_timeout);
			if (ret <= 0)
				continue;

			if (!(fds[0].revents & POLLOUT))
				continue;
		}

		if (opt_tx_cycle_ns) {
			next.tv_sec = next_tx_ns / NSEC_PER_SEC;
			next.tv_nsec = next_tx_ns % NSEC_PER_SEC;
			err = clock_nanosleep(opt_clock, TIMER_ABSTIME, &next, NULL);
			if (err) {
				if (err != EINTR)
					fprintf(stderr,
						"clock_nanosleep failed. Err:%d errno:%d\n",
						err, errno);
				break;
			}

			/* Measure periodic Tx scheduling variance */
			tx_ns = get_nsecs();
			diff = tx_ns - next_tx_ns;
			if (diff < tx_cycle_diff_min)
				tx_cycle_diff_min = diff;

			if (diff > tx_cycle_diff_max)
				tx_cycle_diff_max = diff;

			tx_cycle_diff_ave += (double)diff;
			tx_cycle_cnt++;
		}/*  else if (opt_tstamp) {
			tx_ns = get_nsecs();
		} */

		for (i = 0; i < num_socks; i++)
			tx_cnt += tx_only(xsks[i], &frame_nb[i], batch_size, tx_ns, i);

		pkt_cnt += tx_cnt;

		if (benchmark_done)
			break;

		if (opt_tx_cycle_ns)
			next_tx_ns += opt_tx_cycle_ns;
	}
}


static int lookup_bpf_map(int prog_fd)
{
	__u32 i, *map_ids, num_maps, prog_len = sizeof(struct bpf_prog_info);
	__u32 map_len = sizeof(struct bpf_map_info);
	struct bpf_prog_info prog_info = {};
	int fd, err, xsks_map_fd = -ENOENT;
	struct bpf_map_info map_info;

	err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_len);
	if (err)
		return err;

	num_maps = prog_info.nr_map_ids;

	map_ids = calloc(prog_info.nr_map_ids, sizeof(*map_ids));
	if (!map_ids)
		return -ENOMEM;

	memset(&prog_info, 0, prog_len);
	prog_info.nr_map_ids = num_maps;
	prog_info.map_ids = (__u64)(unsigned long)map_ids;

	err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_len);
	if (err) {
		free(map_ids);
		return err;
	}

	for (i = 0; i < prog_info.nr_map_ids; i++) {
		fd = bpf_map_get_fd_by_id(map_ids[i]);
		if (fd < 0)
			continue;

		memset(&map_info, 0, map_len);
		err = bpf_obj_get_info_by_fd(fd, &map_info, &map_len);
		if (err) {
			close(fd);
			continue;
		}

		if (!strncmp(map_info.name, "xsks_map", sizeof(map_info.name)) &&
		    map_info.key_size == 4 && map_info.value_size == 4) {
			xsks_map_fd = fd;
			break;
		}

		close(fd);
	}

	free(map_ids);
	return xsks_map_fd;
}


static void apply_setsockopt(struct xsk_socket_info *xsk)
{
	int sock_opt;

	if (!opt_busy_poll)
		return;

	sock_opt = 1;
	if (setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_PREFER_BUSY_POLL,
		       (void *)&sock_opt, sizeof(sock_opt)) < 0)
		exit_with_error(errno);

	sock_opt = 20;
	if (setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_BUSY_POLL,
		       (void *)&sock_opt, sizeof(sock_opt)) < 0)
		exit_with_error(errno);

	sock_opt = opt_batch_size;
	if (setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_BUSY_POLL_BUDGET,
		       (void *)&sock_opt, sizeof(sock_opt)) < 0)
		exit_with_error(errno);
}

// struct thread_data {
// 	int socket_th;
// };

// static void *tx_func(void *arg)
// {
// 	// struct thread_data *t = arg;
// 	while (!benchmark_done) {
// 		printf("tx sleeping ...\n");
// 		sleep(1);
// 	}
// 	return NULL;
// }

// static void *rx_func(void *arg)
// {
// 	// struct thread_data *t = arg;
// 	while (!benchmark_done) {
// 		printf("rx sleeping ...\n");
// 		sleep(1);
// 	}
// 	return NULL;
// }


int main(int argc, char **argv)
{
	struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
	struct __user_cap_data_struct data[2] = { { 0 } };
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	bool rx = false, tx = false;
	struct sched_param schparam;
	pthread_t pt;
	int ret;
	// disable some checking from original code, and use opt from env file
	// TODO: what if set to 1? or remove this completely
	use_opt_file = 1;	
	char buffer_env_file[256] = {0};  

	parse_command_line(argc, argv);

	if (use_opt_file) {
		snprintf(buffer_env_file, 256, "cmd_args__%s.conf", hostname);
		printf("Reading opt from file: %s\n", buffer_env_file);
		argps = malloc(sizeof(struct arg_params));
		FILE *fp;
		fp = fopen(buffer_env_file, "r");
		if (fp == NULL) {
			perror("Failed opening config file: ");
			return 1;
		}
		if(parse_params_from_stream(argps, fp, '=', '#', 0)) {
			perror("Failed reading options from file. Exit.");
			exit(EXIT_FAILURE);
		}
	}

	if (opt_reduced_cap) {
		if (capget(&hdr, data)  < 0)
			fprintf(stderr, "Error getting capabilities\n");

		data->effective &= CAP_TO_MASK(CAP_NET_RAW);
		data->permitted &= CAP_TO_MASK(CAP_NET_RAW);

		if (capset(&hdr, data) < 0)
			fprintf(stderr, "Setting capabilities failed\n");

		if (capget(&hdr, data)  < 0) {
			fprintf(stderr, "Error getting capabilities\n");
		} else {
			fprintf(stderr, "Capabilities EFF %x Caps INH %x Caps Per %x\n",
				data[0].effective, data[0].inheritable, data[0].permitted);
			fprintf(stderr, "Capabilities EFF %x Caps INH %x Caps Per %x\n",
				data[1].effective, data[1].inheritable, data[1].permitted);
		}
	} else {
		if (setrlimit(RLIMIT_MEMLOCK, &r)) {
			fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
				strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	// ether_aton_r("00:07:32:74:c5:3b", &s_mac_addrs[0]);
	// ether_aton_r("00:07:32:74:c5:3c", &s_mac_addrs[1]);
	// ether_aton_r("00:07:32:74:c5:3d", &s_mac_addrs[2]);
	// ether_aton_r("00:07:32:74:dc:8f", &d_mac_addrs[0]);
	// ether_aton_r("00:07:32:74:dc:90", &d_mac_addrs[1]);
	// ether_aton_r("00:07:32:74:dc:91", &d_mac_addrs[2]);

	if (opt_bench == BENCH_TXONLY) {
		if (opt_tstamp && opt_pkt_size < PKTGEN_SIZE_MIN)
			opt_pkt_size = PKTGEN_SIZE_MIN;
	}

	opt_num_xsks = 3;
	void *all_bufs[opt_num_xsks];
	for (int s_th = 0; s_th < opt_num_xsks; s_th++) {
		struct xsk_umem_info *umem;
		void *bufs;
		printf("# Setting up XDP socket on device %d %s\n", 
					if_nametoindex(argps->if_names[s_th]), argps->if_names[s_th]);
		/* Reserve memory for the umem. Use hugepages if unaligned chunk mode */
		bufs = mmap(NULL, NUM_FRAMES * opt_xsk_frame_size,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS | opt_mmap_flags, -1, 0);
		if (bufs == MAP_FAILED) {
			printf("ERROR: mmap failed\n");
			exit(EXIT_FAILURE);
		}
		all_bufs[s_th] = bufs;

		/* Create sockets... */
		umem = xsk_configure_umem(bufs, NUM_FRAMES * opt_xsk_frame_size);
		if (opt_bench == BENCH_RXDROP || opt_bench == BENCH_L2FWD) {
			rx = true;
			xsk_populate_fill_ring(umem);
		}
		if (opt_bench == BENCH_L2FWD || opt_bench == BENCH_TXONLY)
			tx = true;
		xsks[s_th] = xsk_configure_socket(umem, rx, tx, argps->if_names[s_th],
										  argps->rx_queues[s_th]);
		num_socks++;
		apply_setsockopt(xsks[s_th]);

		/* Set up custom map of our bpf program */
		int xsks_map;
		xdp_progs[s_th] = load_and_return_xdp_program("xdpsock_kern.o", argps->if_names[s_th]);
		if (!xdp_progs[s_th])
			goto out;
		xsks_map = lookup_bpf_map(xdp_program__fd(xdp_progs[s_th]));
		printf("xsks_map: %d\n", xsks_map);
		if (xsks_map < 0) {
			fprintf(stderr, "ERROR: no xsks map found: %s\n",
				strerror(xsks_map));
				exit(EXIT_FAILURE);
		}
		int fd = xsk_socket__fd(xsks[s_th]->xsk);
		ret = bpf_map_update_elem(xsks_map, &s_th, &fd, 0);
		if (ret) {
			fprintf(stderr, "ERROR: bpf_map_update_elem for s_th %d\n", s_th);
			goto out;
		}
		/*  */
	}

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
	signal(SIGABRT, int_exit);

	setlocale(LC_ALL, "");

	prev_time = get_nsecs();
	start_time = prev_time;

	if (!opt_quiet) {
		ret = pthread_create(&pt, NULL, poller, NULL);
		if (ret)
			exit_with_error(ret);
	}

	/* Configure sched priority for better wake-up accuracy */
	memset(&schparam, 0, sizeof(schparam));
	schparam.sched_priority = opt_schprio;
	ret = sched_setscheduler(0, opt_schpolicy, &schparam);
	if (ret) {
		fprintf(stderr, "Error(%d) in setting priority(%d): %s\n",
			errno, opt_schprio, strerror(errno));
		goto out;
	}

	/*  */
	// int status;
	// static pthread_t tx_thread;
	// static pthread_t rx_thread;
	// status = pthread_create(&tx_thread, NULL, tx_func, NULL);
	// if (status)
	// {
	// 	printf("Thread tx_thread creation failed.\n");
	// 	goto out;
	// }
	// printf("# Thread tx created.\n");
	// status = pthread_create(&rx_thread, NULL, rx_func, NULL);
	// if (status)
	// {
	// 	printf("Thread rx_thread creation failed.\n");
	// 	goto out;
	// }
	// printf("# Thread rx created.\n");

	if (opt_bench == BENCH_RXDROP) {
		printf("Dropping only ...\n");
		rx_drop_all();
	}
	else if (opt_bench == BENCH_TXONLY) {
		printf("TXing only ...\n");
		tx_only_all();
	}

out:
	benchmark_done = true;
	printf("\n# OUT. Cleaning up ...\n");
	if (!opt_quiet)
		pthread_join(pt, NULL);
	// wait for rx and tx thread to complete
	// pthread_join(tx_thread, NULL);
	// pthread_join(rx_thread, NULL);
	//
	for (int i = 0; i < num_socks; i++) {
		printf("-- Clean xdp socket on device %d %s\n", 
					if_nametoindex(argps->if_names[i]), argps->if_names[i]);
		xdpsock_cleanup_index(i);
		munmap(all_bufs[i], NUM_FRAMES * opt_xsk_frame_size);
	}

	free(argps);

	return 0;
}
