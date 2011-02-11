/* nic_nl.c: NIC uIP NetLink user space stack
 *
 * Copyright (c) 2004-2010 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by: Benjamin Li  (benli@broadcom.com)
 */

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/limits.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <iscsi_if.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/socket.h>

#include "uip_arp.h"
#include "logger.h"
#include "options.h"
#include "uevent.h"

#include "nic.h"
#include "nic_nl.h"
#include "nic_utils.h"

/*******************************************************************************
 * Constants
 ******************************************************************************/
#define PFX "NIC_NL "

static void *nlm_recvbuf = NULL;
static void *nlm_sendbuf = NULL;

static struct sockaddr_nl src_addr;

const static struct sockaddr_nl dest_addr = {
	.nl_family	= AF_NETLINK,
	.nl_pid		= 0, /* kernel */
	.nl_groups	= 0, /* unicast */
};

#define POLL_NL		0
#define POLL_MAX        1

/* Netlink */
int		nl_sock = INVALID_FD;

static int
nl_read(int ctrl_fd, char *data, int size, int flags)
{
	int rc;
	struct iovec iov;
	struct msghdr msg;

	iov.iov_base = data;
	iov.iov_len = size;

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
	src_addr.nl_groups = 1;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name= (void*)&src_addr;
	msg.msg_namelen = sizeof(src_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	rc = recvmsg(ctrl_fd, &msg, flags);

	return rc;
}

static int
nlpayload_read(int ctrl_fd, char *data, int count, int flags)
{
        int rc;
        struct iovec iov;
        struct msghdr msg;

	iov.iov_base = nlm_recvbuf;
	iov.iov_len = NLMSG_SPACE(count);
	memset(iov.iov_base, 0, iov.iov_len);

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
	src_addr.nl_groups = 1;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name= (void*)&src_addr;
	msg.msg_namelen = sizeof(src_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	rc = recvmsg(ctrl_fd, &msg, flags);

	memcpy(data, NLMSG_DATA(iov.iov_base), count);

	return rc;
}

static int
kwritev(int fd, enum iscsi_uevent_e type, struct iovec *iovp, int count)
{
	int i, rc;
	struct nlmsghdr *nlh;
	struct msghdr msg;
	struct iovec iov;
	int datalen = 0;

	for (i = 0; i < count; i++) {
		datalen += iovp[i].iov_len;
	}

	nlh = nlm_sendbuf;
	memset(nlh, 0, NLMSG_SPACE(datalen));

	nlh->nlmsg_len = NLMSG_SPACE(datalen);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_type = type;

	datalen = 0;
	for (i = 0; i < count; i++) {
		memcpy(NLMSG_DATA(nlh) + datalen, iovp[i].iov_base,
		       iovp[i].iov_len);
		datalen += iovp[i].iov_len;
	}
	iov.iov_base = (void*)nlh;
	iov.iov_len = nlh->nlmsg_len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name= (void*)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	do {
		rc = sendmsg(fd, &msg, 0);
		if (rc == -ENOMEM) {
			LOG_ERR(PFX "sendmsg: alloc_skb() failed");
			sleep(1);
		} else if (rc < 0) {
			LOG_ERR(PFX "sendmsg: bug?: on %d %s[0x%x]",
				fd, strerror(errno), errno);
			sleep(1);
		}
	} while ((rc < 0) && (event_loop_stop == 0));

	return rc;
}

/*
 * __kipc_call() should never block. Therefore
 * Netlink's xmit logic is serialized. This means we do not allocate on
 * xmit path. Instead we reuse nlm_sendbuf buffer.
 *
 * Transport must assure non-blocking operations for:
 *
 *	- session_create()
 *	- conn_create()
 *	- conn_bind()
 *	_ set_param()
 *	- conn_start()
 *	- conn_stop()
 *
 * Its OK to block for cleanup for short period of time in operatations for:
 *
 *	- conn_destroy()
 *	- session_destroy()
 *
 * FIXME: interface needs to be extended to allow longer blocking on
 *        cleanup. (Dima)
 */
int
__kipc_call(int fd, void *iov_base, int iov_len)
{
	int rc;
	struct iovec iov;
	struct iscsi_uevent *ev = iov_base;
	enum iscsi_uevent_e type = ev->type;
	int wait_response;

	/* Sanity check */
	if(iov_base == NULL)
		return -EINVAL;

	iov.iov_base = iov_base;
	iov.iov_len = iov_len;

	rc = kwritev(fd, type, &iov, 1);

	wait_response = 0;
	do {
		rc = nlpayload_read(fd, (void*)ev, sizeof(*ev), MSG_PEEK);
		if (rc < 0) {
			LOG_ERR(PFX "Error reading resp to reply: %s[%d]",
				strerror(rc), rc);
			return rc;
		}

		if (ev->type != type) {
			LOG_DEBUG(PFX "expecting event %d, got %d, handling...",
				  type, ev->type);
			if (ev->type == ISCSI_KEVENT_IF_ERROR) {
				if ((rc = nlpayload_read(fd, (void*)ev,
							 sizeof(*ev), 0)) < 0) {
					return rc;
				}
				if (ev->iferror == -ENOSYS) {
					/* not fatal so let caller handle log */
					LOG_DEBUG(PFX "Recieved iferror %d: %s",
						  ev->iferror,
						  strerror(ev->iferror));
				} else if (ev->iferror < 0) {
					LOG_ERR("Received iferror %d: %s",
						   ev->iferror,
						   strerror(ev->iferror));
				} else {
					LOG_ERR("Received iferror %d",
						   ev->iferror);
				}
				return ev->iferror;
			}
		} else if (ev->type == ISCSI_UEVENT_GET_STATS) {
			/* kget_stats() will read */
			return 0;
		} else {
			if ((rc = nlpayload_read(fd, (void*)ev,
						 sizeof(*ev), 0)) < 0) {
				return rc;
			}
			break;
		}

		wait_response++;
	} while ((ev->type != type) &&
		 (event_loop_stop == 0) &&
		 (wait_response < MAX_COUNT_NIC_NL_RESP));

	return rc;
}

static int ctldev_handle()
{
	nic_t *nic = NULL;
	int rc;
	size_t ev_size;
	struct iscsi_uevent *ev;
	char nlm_ev[NLMSG_SPACE(sizeof(struct iscsi_uevent))];
	struct nlmsghdr *nlh;
	char *data;
	uint8_t *payload;
	struct iscsi_path *path;
	char *msg_type_str;
	uint32_t host_no;
	int i;

	/*  Take a quick peek at what how much uIP will need to read */
	if ((rc = nl_read(nl_sock, nlm_ev,
		NLMSG_SPACE(sizeof(struct iscsi_uevent)), MSG_PEEK)) < 0) {
		LOG_ERR("can not read nlm_ev, error %d", rc);
		return rc;
	}
	nlh = (struct nlmsghdr *)nlm_ev;

	data = (char *) malloc(nlh->nlmsg_len);
	if(data == NULL) {
		LOG_ERR("Couldn't allocate %d bytes for Netlink iSCSI message\n",
			 nlh->nlmsg_len);
		return -ENOMEM;
	}

	memset(data, 0, nlh->nlmsg_len);
	ev_size = nlh->nlmsg_len - NLMSG_ALIGN(sizeof(struct nlmsghdr));
	if ((rc = nl_read(nl_sock, data, (int) nlh->nlmsg_len, 0)) < 0) {
		LOG_ERR("can not read nlm_ev, error %d", rc);
		goto error;
	}

	ev = (struct iscsi_uevent *)NLMSG_DATA(data);
	switch (ev->type) {
	case ISCSI_KEVENT_PATH_REQ:
		msg_type_str = "path_req";

		if((ev_size - sizeof(ev)) != sizeof(*path))
			LOG_WARN("Didn't get iscsi_path size(%d) expected %d",
				 ev_size - sizeof(ev), sizeof(*path));
		host_no = ev->r.req_path.host_no;

		break;
	case ISCSI_KEVENT_IF_DOWN:
		msg_type_str = "if_down";

		host_no = ev->r.notify_if_down.host_no;
		break;
	default:
		/*  We don't care about other iSCSI Netlink messages */
		LOG_DEBUG(PFX "Received ev->type: 0x%x", ev->type);
		rc = 0;
		goto error;
        }

	/*  This is a message that drivers should be interested in */
	LOG_INFO("Received: '%s': host_no: %d", msg_type_str,  host_no);

	rc = from_host_no_find_associated_eth_device(host_no, &nic);
	if(rc != 0) {
		LOG_ERR(PFX "Dropping msg, couldn't find nic with host no:%d\n",
			host_no);
		goto error;
	}

	payload = (uint8_t *) ((uint8_t *)ev) + sizeof(*ev);
	path = (struct iscsi_path *)payload;

	if (ev->type == ISCSI_KEVENT_PATH_REQ) {
		struct timespec sleep_req, sleep_rem;
		nic_interface_t *nic_iface;
		uint16_t ip_type;

		sleep_req.tv_sec  = 0;
		sleep_req.tv_nsec = 250000000;

		if (path->ip_addr_len == 4)
			ip_type = AF_INET;
		else if (path->ip_addr_len == 16)
			ip_type = AF_INET6;
		else 
			ip_type = 0;

		nic_iface = nic_find_nic_iface_protocol(nic, path->vlan_id,
							ip_type);
		if (nic_iface == NULL) {
			LOG_WARN(PFX "%s: Couldn't find nic_iface  "
				     "vlan: %d ip_addr_len",
				 nic->log_name,
				 path->vlan_id, path->ip_addr_len);
			goto error;
		}

		/*  Ensure that the NIC is RUNNING */
		rc = -EIO;
		for (i=0; i<10; i++) {
			if(((nic->state & NIC_RUNNING) == NIC_RUNNING) &&
			   (nic_iface->state & NIC_IFACE_RUNNING))  {
				rc = 0;
				break;
			}
		
			nanosleep(&sleep_req, &sleep_rem);
		}

		if (rc !=0) {
			LOG_WARN(PFX "%s: is not running so can't issue "
				     "neigh req, cmd: 0x%x state: 0x%x",
				 nic->log_name, ev->type, nic->state);
			goto error;
		}
	}

	if(nic->ops) {
		switch (ev->type) {
        	case ISCSI_KEVENT_PATH_REQ:
			/*  pass the request up to the user space
			 *  library driver */
			if(nic->ops->handle_iscsi_path_req) {
				nic->ops->handle_iscsi_path_req(nic,
								nl_sock, ev,
								path, ev_size);
			}
			break;
		case ISCSI_KEVENT_IF_DOWN:
			nic_remove(nic, 0);

			break;
		}
	}

	rc = 0;

error:
	free(data);

	return rc;
}

/**
 *  nic_nl_open() - This is called when opening/creating the Netlink listening
 *                   thread
 *  @param dev - CNIC UIO device to create a NetLink listener on
 *  @return 0 on success, <0 on failure
 */
int nic_nl_open()
{
	int rc;
	struct pollfd poll_array[POLL_MAX];
	memset(poll_array, 0, sizeof(poll_array));

	nlm_sendbuf = calloc(1, NLM_BUF_DEFAULT_MAX);
	if (!nlm_sendbuf) {
		LOG_ERR(PFX "can't allocate nlm_sendbuf");
		rc = -ENOMEM;
		goto error;
	}

	nlm_recvbuf = calloc(1, NLM_BUF_DEFAULT_MAX);
	if (!nlm_recvbuf) {
		LOG_ERR(PFX "can't allocate nlm_recvbuf");
		rc = -ENOMEM;
		goto error;
	}

	nl_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ISCSI);
	if (nl_sock < 0) {
		LOG_ERR(PFX "can not create NETLINK_ISCSI socket");
		rc = -ENOMEM;
		goto error;
	}

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
	src_addr.nl_groups = ISCSI_NL_GRP_UIP;

        while ((!event_loop_stop) && (bnx2i_loaded == 0)) {
		rc = bind(nl_sock,
			  (struct sockaddr *)&src_addr, sizeof(src_addr));
		if (rc == 0)
			break;

		LOG_ERR(PFX "waiting binding to NETLINK_ISCSI socket");

		pthread_mutex_lock(&bnx2i_module_loaded_mutex);
		pthread_cond_wait(&bnx2i_module_loaded_cond,
				  &bnx2i_module_loaded_mutex);
		pthread_mutex_unlock(&bnx2i_module_loaded_mutex);

		sleep(1);
	}

	if(event_loop_stop) {
		rc = -EINVAL;
		goto error;
	}

	LOG_INFO(PFX "Netlink to CNIC on pid %d is ready", src_addr.nl_pid);

	poll_array[POLL_NL].fd = nl_sock;
	poll_array[POLL_NL].events = POLLIN;

        while (!event_loop_stop) {
                int res = poll(poll_array, POLL_MAX, NL_POLL_RESOLUTION);
                if (res > 0) {
                        if (poll_array[POLL_NL].revents)
                                ctldev_handle();
                } else if (res < 0) {
                        if (errno == EINTR) {
                                LOG_DEBUG(PFX "event_loop interrupted");
                        } else {
                                LOG_ERR(PFX "got poll() error (%d), errno (%d), "
                                          "exiting", res, errno);
                                break;
                        }
                }
        }

	LOG_INFO(PFX "Netlink thread exit'ing");
	rc = 0;

error:
	if(nlm_sendbuf) {
		free(nlm_sendbuf);
		nlm_sendbuf = NULL;
	}

	if(nlm_recvbuf) {
		free(nlm_recvbuf);
		nlm_recvbuf = NULL;
	}

	return 0;
}
