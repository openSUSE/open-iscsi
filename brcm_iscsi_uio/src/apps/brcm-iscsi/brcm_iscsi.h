/**
 * \addtogroup apps
 * @{
 */

/**
 * \defgroup helloworld Hello, world
 * @{
 *
 * A small example showing how to write applications with
 * \ref psock "protosockets".
 */

/**
 * \file
 *         Header file for an example of how to write uIP applications
 *         with protosockets.
 * \author
 *         Benjamin Li <benli@broadcom.com>
 */

#ifndef __BRCM_ISCSI_H__
#define __BRCM_ISCSI_H__

/* Since this file will be included by uip.h, we cannot include uip.h
   here. But we might need to include uipopt.h if we need the u8_t and
   u16_t datatypes. */
#include "uipopt.h"
#include "uip.h"
#include "psock.h"

/* Next, we define the uip_tcp_appstate_t datatype. This is the state
   of our application, and the memory required for this state is
   allocated together with each TCP connection. One application state
   for each TCP connection. */
typedef struct hello_world_state {
  struct psock p;
  u8_t inputbuffer[32];
  u8_t name[40];

  struct uip_udp_conn *conn;
} uip_tcp_appstate_t;

/* Finally we define the application function to be called by uIP. */
void brcm_iscsi_appcall(struct uip_stack *ustack);
#ifndef UIP_APPCALL
#define UIP_APPCALL brcm_iscsi_appcall 
#endif /* UIP_APPCALL */

void brcm_iscsi_init(void);

#endif /* __BRCM_ISCSI_H__ */
/** @} */
/** @} */
