/*
 * Copyright (c) 2006, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the uIP TCP/IP stack
 *
 * $Id: uip-neighbor.c,v 1.2 2006/06/12 08:00:30 adam Exp $
 */

/**
 * \file
 *         Database of link-local neighbors, used by IPv6 code and
 *         to be used by a future ARP code rewrite.
 * \author
 *         Adam Dunkels <adam@sics.se>
 */

#include "logger.h"
#include "uip.h"
#include "uip-neighbor.h"

#include <string.h>
#include <arpa/inet.h>

#define MAX_TIME 128

/*---------------------------------------------------------------------------*/
void
uip_neighbor_init(struct uip_stack *ustack)
{
  int i;

  for(i = 0; i < UIP_NEIGHBOR_ENTRIES; ++i) {
    ustack->neighbor_entries[i].time = MAX_TIME;
  }
}
/*---------------------------------------------------------------------------*/
#if 0
void
uip_neighbor_periodic(void)
{
  int i;

  for(i = 0; i < UIP_NEIGHBOR_ENTRIES; ++i) {
    if(entries[i].time < MAX_TIME) {
      entries[i].time++;
    }
  }
}
#endif
/*---------------------------------------------------------------------------*/
void
uip_neighbor_add(struct uip_stack *ustack,
		 uip_ip6addr_t ipaddr, struct uip_eth_addr *addr)
{
  int i, oldest;
  u8_t oldest_time;
  char buf[128];

   inet_ntop(AF_INET6, ipaddr, buf, sizeof(buf));

   LOG_INFO("Adding neighbor %s with link address %02x:%02x:%02x:%02x:%02x:%02x\n",
   	   buf,
	   addr[0], addr[1], addr[2],
	   addr[3], addr[4], addr[5]);
  
  /* Find the first unused entry or the oldest used entry. */
  oldest_time = 0;
  oldest = 0;
  for(i = 0; i < UIP_NEIGHBOR_ENTRIES; ++i) {
    if(ustack->neighbor_entries[i].time == MAX_TIME) {
      oldest = i;
      break;
    }
    if(uip_ip6addr_cmp(ustack->neighbor_entries[i].ipaddr, ipaddr)) {
      oldest = i;
      break;
    }
    if(ustack->neighbor_entries[i].time > oldest_time) {
      oldest = i;
      oldest_time = ustack->neighbor_entries[i].time;
    }
  }

  /* Use the oldest or first free entry (either pointed to by the
     "oldest" variable). */
  ustack->neighbor_entries[oldest].time = 0;
  uip_ip6addr_copy(ustack->neighbor_entries[oldest].ipaddr, ipaddr);
  memcpy(&ustack->neighbor_entries[oldest].addr,
  	 addr, sizeof(struct uip_eth_addr));
}
/*---------------------------------------------------------------------------*/
static struct neighbor_entry *
find_entry(struct uip_stack *ustack,
	   uip_ip6addr_t ipaddr)
{
  int i;
  char buf[128];
  inet_ntop(AF_INET6, ipaddr, buf, sizeof(buf));
  
  for(i = 0; i < UIP_NEIGHBOR_ENTRIES; ++i) {
    if(uip_ip6addr_cmp(ustack->neighbor_entries[i].ipaddr, ipaddr)) {

      LOG_DEBUG("found %s at %02x:%02x:%02x:%02x:%02x:%02x\n",
           buf,
	   ustack->neighbor_entries[i].addr.addr[0],
	   ustack->neighbor_entries[i].addr.addr[1],
	   ustack->neighbor_entries[i].addr.addr[2],
	   ustack->neighbor_entries[i].addr.addr[3],
	   ustack->neighbor_entries[i].addr.addr[4],
	   ustack->neighbor_entries[i].addr.addr[5]);

      return &ustack->neighbor_entries[i];
    }
  }


  LOG_WARN("Could not find entry: %s",
  	   buf);

  return NULL;
}
/*---------------------------------------------------------------------------*/
void
uip_neighbor_update(struct uip_stack *ustack, uip_ip6addr_t ipaddr)
{
  struct neighbor_entry *e;

  e = find_entry(ustack, ipaddr);
  if(e != NULL) {
    e->time = 0;
  }
}
/*---------------------------------------------------------------------------*/
struct uip_eth_addr *
uip_neighbor_lookup(struct uip_stack *ustack, uip_ip6addr_t ipaddr)
{
  struct neighbor_entry *e;

  e = find_entry(ustack, ipaddr);
  if(e != NULL) {
    /*    printf("Lookup neighbor with link address %02x:%02x:%02x:%02x:%02x:%02x\n",
	   e->addr.addr.addr[0], e->addr.addr.addr[1], e->addr.addr.addr[2], e->addr.addr.addr[3],
	   e->addr.addr.addr[4], e->addr.addr.addr[5]);*/

    return &e->addr;
  }
  return NULL;
}

void
uip_neighbor_out(struct uip_stack *ustack)
{
  struct neighbor_entry *e;
  struct uip_ipv6_hdr *ipv6_hdr = (struct uip_ipv6_hdr *)IPv6_BUF(ustack);
  
  /* Find the destination IP address in the neighbor table and construct
     the Ethernet header. If the destination IP addres isn't on the
     local network, we use the default router's IP address instead.

     If not ARP table entry is found, we overwrite the original IP
     packet with an ARP request for the IP address. */
  e = find_entry(ustack, ipv6_hdr->destipaddr);

  if(e == NULL)
  	/* TODO determine what to do in IPv6 case */
  	return;

  memcpy(ETH_BUF(ustack)->dest.addr, &e->addr, 6);
  memcpy(ETH_BUF(ustack)->src.addr, ustack->uip_ethaddr.addr, 6);
  
  ETH_BUF(ustack)->type = htons(UIP_ETHTYPE_IPv6);

  ustack->uip_len += sizeof(struct uip_eth_hdr);
}

/*---------------------------------------------------------------------------*/
