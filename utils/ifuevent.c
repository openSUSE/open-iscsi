/*
 * ifuevent
 *
 * Monitor interface for network address changes and trigger uevents
 *
 * Copyright (c) 2009 Hannes Reinecke <hare@suse.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>

int debug = 0;
int continuous = 0;
char program_name[] = "ifuevent";

struct interface_info {
	int index;
	char ifname[IFNAMSIZ];
	char ifaddr[24];
	char hwaddr[64];
	int prefixlen;
	int flags;
};

static void print_iface_status(struct interface_info *i)
{
	if (!debug)
		return;

	printf("[%d] %s addr %s %s\n",
	       i->index, i->ifname,
	       strlen(i->ifaddr) ? i->ifaddr : "<unset>",
	       i->flags & IFF_UP ? "up" : "down");
}

static void trigger_uevent(struct interface_info *i)
{
	int fd;
	char attr[256];
	char value[] = "change";

	sprintf(attr,"/sys/class/net/%s/uevent", i->ifname);
	fd = open(attr, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "failed to open %s: %s\n",
			attr, strerror(errno));
		return;
	}

	if (write(fd, value, strlen(value)) != strlen(value))
		fprintf(stderr, "failed to write to %s: %s\n",
			attr, strerror(errno));

	close(fd);
}

static int handle_newlink_event(struct nlmsghdr *h, struct interface_info *i)
{
	struct ifinfomsg *ifi = NLMSG_DATA(h);

	if (debug)
		printf("[%d] newlink family %d type %d flags %x change %x\n",
		       ifi->ifi_index, ifi->ifi_family, ifi->ifi_type,
		       ifi->ifi_flags, ifi->ifi_change);

	/* We're only interested in IFF_UP changes */
	if ((ifi->ifi_change & IFF_UP) != IFF_UP)
		return 0;

	if (ifi->ifi_flags & IFF_UP) {
		if (!(i->flags & IFF_UP)) {
			i->flags |= IFF_UP;
			print_iface_status(i);
			return 1;
		}
	} else {
		if (i->flags & IFF_UP) {
			i->flags &= ~IFF_UP;
			print_iface_status(i);
		}
	}
	return 0;
}

static int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max)
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta,len);
	}
	return 0;
}

static int handle_newaddr_event(struct nlmsghdr *h, struct interface_info *i)
{
	struct ifaddrmsg *m;
	struct rtattr * rta_tb[IFA_MAX+1];
	char ifaddr[24];

	m = NLMSG_DATA(h);

	if (debug)
		printf("[%d] newaddr family %d flags %x prefix %d scope %d\n",
		       m->ifa_index, m->ifa_family, m->ifa_flags,
		       m->ifa_prefixlen, m->ifa_scope);

	if (m->ifa_family != AF_INET &&
	    m->ifa_family != AF_INET6)
		return 0;

	if (m->ifa_flags&IFA_F_TENTATIVE)
		return 0;

	if (m->ifa_prefixlen != i->prefixlen)
		i->prefixlen = m->ifa_prefixlen;

	memset(rta_tb, 0, sizeof(rta_tb));
	parse_rtattr(rta_tb, IFA_MAX, IFA_RTA(m),
		     h->nlmsg_len - NLMSG_LENGTH(sizeof(*m)));

	if (rta_tb[IFA_LOCAL] == NULL)
		rta_tb[IFA_LOCAL] = rta_tb[IFA_ADDRESS];
	if (rta_tb[IFA_LOCAL] == NULL)
		return 0;

	inet_ntop(m->ifa_family, RTA_DATA(rta_tb[IFA_LOCAL]),
		  ifaddr, 24);
	if (strncmp(i->ifaddr, ifaddr, 24)) {
		memcpy(i->ifaddr, ifaddr, 24);
		print_iface_status(i);
		return 1;
	}
	return 0;
}

static void recvaddrs(int fd, struct interface_info *i)
{
	char	buf[8192];
	struct sockaddr_nl nladdr;
	struct iovec iov = { buf, sizeof(buf) };

	while (1) {
		int status;
		struct nlmsghdr *h;

		struct msghdr msg = {
			(void*)&nladdr, sizeof(nladdr),
			&iov,	1,
			NULL,	0,
			0
		};

		status = recvmsg(fd, &msg, 0);

		if (status < 0)
			continue;

		if (status == 0)
			return;

		if (nladdr.nl_pid) /* Message not from kernel */
			continue;

		h = (struct nlmsghdr*)buf;
		while (NLMSG_OK(h, status)) {
			if (debug)
				printf("recv msg type %d\n", h->nlmsg_type);

			switch (h->nlmsg_type) {
			case NLMSG_DONE:
				return;
			case NLMSG_ERROR:
				return;
			case RTM_NEWLINK:
				if (handle_newlink_event(h, i) && !continuous)
					return;
				break;
			case RTM_NEWADDR:
				if (handle_newaddr_event(h, i) && !continuous)
					return;
				break;
			default:
				break;
			}
			h = NLMSG_NEXT(h, status);
		}
		if (msg.msg_flags & MSG_TRUNC)
			continue;
	}
	return;
}

static int setup_iface(int fd, struct interface_info *i)
{
	struct ifreq ifr;

	if (fd < 0)
		return EBADF;

	memset(&ifr, 0, sizeof(struct ifreq));
	memcpy(ifr.ifr_name, i->ifname, IFNAMSIZ);
	if (ioctl(fd, SIOCGIFINDEX, (void*)&ifr) < 0) {
		fprintf(stderr, "SIOCGIFINDEX failed: %s\n", strerror(errno));
		return errno;
	}
	i->index = ifr.ifr_ifindex;
	memset(&ifr, 0, sizeof(struct ifreq));
	memcpy(ifr.ifr_name, i->ifname, IFNAMSIZ);
	if (ioctl(fd, SIOCGIFFLAGS, (void*)&ifr) < 0) {
		fprintf(stderr, "SIOCGIFADDR failed: %s\n", strerror(errno));
		return errno;
	}
	i->flags = ifr.ifr_flags;
	memset(&ifr, 0, sizeof(struct ifreq));
	memcpy(ifr.ifr_name, i->ifname, IFNAMSIZ);
	if (ioctl(fd, SIOCGIFADDR, (void*)&ifr) == 0) {
		if (getnameinfo(&ifr.ifr_addr, 24, i->ifaddr, 24,
				NULL, 0, NI_NUMERICHOST) < 0) {
			fprintf(stderr, "getnameinfo failed: %s\n",
				strerror(errno));
		}
	}
	return 0;
}

static int check_iface_name(int fd, struct interface_info *i)
{
	struct ifreq ifr;
	int retval = 0;

	if (fd < 0)
		return EBADF;

	memset(&ifr, 0, sizeof(struct ifreq));
	ifr.ifr_ifindex = i->index;
	if (ioctl(fd, SIOCGIFNAME, (void*)&ifr) < 0) {
		fprintf(stderr, "SIOCGIFNAME failed: %s\n", strerror(errno));
		retval = errno;
	} else
		memcpy(i->ifname, ifr.ifr_name, IFNAMSIZ);

	return retval;
}

static struct option const long_options[] =
{
	{"debug", no_argument, NULL, 'd'},
	{"monitor", no_argument, NULL, 'm'},
};

static char *short_options = "dm";

static void usage(int status)
{
	if (status != 0)
		fprintf(stderr, "Try '%s --help' for more information.\n",
			program_name);
	else
		printf("usage: \
%s [-d|--debug] [-m|--monitor] ifname\n", program_name);
	exit(status);
}

int main(int argc, char *argv[])
{
	char ch;
	int fd, inet_fd;
	char *ifname = NULL;
	struct sockaddr_nl la;
	struct interface_info *i;
	int retval = 0;

	while ((ch = getopt_long(argc, argv, short_options,
				 long_options, NULL)) >= 0) {
		switch(ch) {
		case 'm':
			continuous = 1;
			break;
		case 'd':
			debug = 1;
			break;
		case 'h':
			usage(0);
		}
	}

	if (optind == argc)
		usage(ENODEV);

	ifname = argv[optind];

	i = malloc(sizeof(struct interface_info));
	if (!i)
		return ENOMEM;
	memset(i, 0, sizeof(struct interface_info));
	strncpy(i->ifname, ifname, IFNAMSIZ);

	inet_fd = socket(AF_INET, SOCK_DGRAM, 0);

	if ((retval = setup_iface(inet_fd, i)))
		return retval;

	print_iface_status(i);

	if ((i->flags & IFF_UP) && !continuous)
		goto uevent;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

	memset(&la, 0, sizeof(la));
	la.nl_family = AF_NETLINK;
	la.nl_pid = getpid();
	la.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_LINK | RTMGRP_NOTIFY;
	bind(fd, (struct sockaddr*) &la, sizeof(la));

	recvaddrs(fd, i);
	close(fd);

	/* Re-evaluate the interface name, might have been changed */
	check_iface_name(inet_fd, i);

	close(inet_fd);

	print_iface_status(i);

uevent:
	if (!retval)
		trigger_uevent(i);

	return retval;
}
