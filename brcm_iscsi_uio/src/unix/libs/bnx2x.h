/* bnx2x.h: bnx2x user space driver
 *
 * Copyright (c) 2004-2010 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by: Benjamin Li  (benli@broadcom.com)
 */

#ifndef __BNX2X_H__
#define __BNX2X_H__

#include "nic.h"

/******************************************************************************
 *  Default CNIC values
 ******************************************************************************/
#define DEFAULT_BNX2X_NUM_RXBD	15
#define DEFAULT_BNX2X_RX_LEN	0x400


/******************************************************************************
 *  BNX2X Hardware structures
 ******************************************************************************/
#define HC_USTORM_DEF_SB_NUM_INDICES 8
#define HC_CSTORM_DEF_SB_NUM_INDICES 8
#define HC_XSTORM_DEF_SB_NUM_INDICES 4
#define HC_TSTORM_DEF_SB_NUM_INDICES 4

struct atten_def_status_block {
	volatile __u32 attn_bits;
	volatile __u32 attn_bits_ack;
	volatile __u8 status_block_id;
	volatile __u8 reserved0;
	volatile __u16 attn_bits_index;
	volatile __u32 reserved1;
};

struct cstorm_def_status_block_u {
	volatile __u16 index_values[HC_USTORM_DEF_SB_NUM_INDICES];
	volatile __u16 status_block_index;
	volatile __u8 func;
	volatile __u8 status_block_id;
	volatile __u32 __flags;
};

struct cstorm_def_status_block_c {
	volatile __u16 index_values[HC_CSTORM_DEF_SB_NUM_INDICES];
	volatile __u16 status_block_index;
	volatile __u8 func;
	volatile __u8 status_block_id;
	volatile __u32 __flags;
};

struct xstorm_def_status_block {
	volatile __u16 index_values[HC_XSTORM_DEF_SB_NUM_INDICES];
	volatile __u16 status_block_index;
	volatile __u8 func;
	volatile __u8 status_block_id;
	volatile __u32 __flags;
};

struct tstorm_def_status_block {
	volatile __u16 index_values[HC_TSTORM_DEF_SB_NUM_INDICES];
	volatile __u16 status_block_index;
	volatile __u8 func;
	volatile __u8 status_block_id;
	volatile __u32 __flags;
};

struct host_def_status_block {
	struct atten_def_status_block atten_status_block;
	struct cstorm_def_status_block_u u_def_status_block;
	struct cstorm_def_status_block_c c_def_status_block;
	struct xstorm_def_status_block x_def_status_block;
	struct tstorm_def_status_block t_def_status_block;
};

#define HC_INDEX_DEF_U_ETH_ISCSI_RX_CQ_CONS 1
#define HC_INDEX_DEF_U_ETH_ISCSI_RX_BD_CONS 3
#define HC_INDEX_DEF_C_ETH_ISCSI_CQ_CONS 5

struct atten_sp_status_block {
	__u32 attn_bits;
	__u32 attn_bits_ack;
	__u8 status_block_id;
	__u8 reserved0;
	__u16 attn_bits_index;
	__u32 reserved1;
};

#define HC_SP_SB_MAX_INDICES	16

struct hc_sp_status_block {
	__u16 index_values[HC_SP_SB_MAX_INDICES];
	__u16 running_index;
	__u16 rsrv;
	__u32 rsrv1;
};

struct host_sp_status_block {
	struct atten_sp_status_block atten_status_block;
	struct hc_sp_status_block sp_sb;
};

#define HC_SP_INDEX_ETH_ISCSI_CQ_CONS		5
#define HC_SP_INDEX_ETH_ISCSI_RX_CQ_CONS	1

/*  TX Buffer descriptor */
struct eth_tx_bd_flags {
	__u8 as_bitfield;
#define ETH_TX_BD_FLAGS_VLAN_TAG (0x1<<0)
#define ETH_TX_BD_FLAGS_VLAN_TAG_SHIFT 0
#define ETH_TX_BD_FLAGS_IP_CSUM (0x1<<1)
#define ETH_TX_BD_FLAGS_IP_CSUM_SHIFT 1
#define ETH_TX_BD_FLAGS_L4_CSUM (0x1<<2)
#define ETH_TX_BD_FLAGS_L4_CSUM_SHIFT 2
#define ETH_TX_BD_FLAGS_END_BD (0x1<<3)
#define ETH_TX_BD_FLAGS_END_BD_SHIFT 3
#define ETH_TX_BD_FLAGS_START_BD (0x1<<4)
#define ETH_TX_BD_FLAGS_START_BD_SHIFT 4
#define ETH_TX_BD_FLAGS_HDR_POOL (0x1<<5)
#define ETH_TX_BD_FLAGS_HDR_POOL_SHIFT 5
#define ETH_TX_BD_FLAGS_SW_LSO (0x1<<6)
#define ETH_TX_BD_FLAGS_SW_LSO_SHIFT 6
#define ETH_TX_BD_FLAGS_IPV6 (0x1<<7)
#define ETH_TX_BD_FLAGS_IPV6_SHIFT 7
};

struct eth_tx_start_bd {
	__u32 addr_lo;
	__u32 addr_hi;
	__u16 nbd;
	__u16 nbytes;
	__u16 vlan;
	struct eth_tx_bd_flags bd_flags;
	__u8 general_data;
#define ETH_TX_START_BD_HDR_NBDS (0x3F<<0)
#define ETH_TX_START_BD_HDR_NBDS_SHIFT 0
#define ETH_TX_START_BD_ETH_ADDR_TYPE (0x3<<6)
#define ETH_TX_START_BD_ETH_ADDR_TYPE_SHIFT 6
};

struct eth_tx_bd {
	__u32 addr_lo;
	__u32 addr_hi;
	__u16 total_pkt_bytes;
	__u16 nbytes;
	__u8 reserved[4];
};

/*  RX Buffer descriptor */
struct eth_rx_bd {
	__u32 addr_lo;
	__u32 addr_hi;
};

struct ramrod_data {
	volatile __u32 data_lo;
	volatile __u32 data_hi;
};

struct common_ramrod_eth_rx_cqe {
	volatile __u8 ramrod_type;
#define COMMON_RAMROD_ETH_RX_CQE_TYPE (0x1<<0)
#define COMMON_RAMROD_ETH_RX_CQE_TYPE_SHIFT 0
#define COMMON_RAMROD_ETH_RX_CQE_RESERVED0 (0x7F<<1)
#define COMMON_RAMROD_ETH_RX_CQE_RESERVED0_SHIFT 1
	volatile __u8 conn_type;
	volatile __u16 reserved1;
	volatile __u32 conn_and_cmd_data;
#define COMMON_RAMROD_ETH_RX_CQE_CID (0xFFFFFF<<0)
#define COMMON_RAMROD_ETH_RX_CQE_CID_SHIFT 0
#define COMMON_RAMROD_ETH_RX_CQE_CMD_ID (0xFF<<24)
#define COMMON_RAMROD_ETH_RX_CQE_CMD_ID_SHIFT 24
	struct ramrod_data protocol_data;
	__u32 reserved2[4];
};

struct parsing_flags {
	volatile __u16 flags;
};

struct eth_fast_path_rx_cqe {
	volatile __u8 type_error_flags;
#define ETH_FAST_PATH_RX_CQE_TYPE (0x1<<0)
#define ETH_FAST_PATH_RX_CQE_TYPE_SHIFT 0
#define ETH_FAST_PATH_RX_CQE_PHY_DECODE_ERR_FLG (0x1<<1)
#define ETH_FAST_PATH_RX_CQE_PHY_DECODE_ERR_FLG_SHIFT 1
#define ETH_FAST_PATH_RX_CQE_IP_BAD_XSUM_FLG (0x1<<2)
#define ETH_FAST_PATH_RX_CQE_IP_BAD_XSUM_FLG_SHIFT 2
#define ETH_FAST_PATH_RX_CQE_L4_BAD_XSUM_FLG (0x1<<3)
#define ETH_FAST_PATH_RX_CQE_L4_BAD_XSUM_FLG_SHIFT 3
#define ETH_FAST_PATH_RX_CQE_START_FLG (0x1<<4)
#define ETH_FAST_PATH_RX_CQE_START_FLG_SHIFT 4
#define ETH_FAST_PATH_RX_CQE_END_FLG (0x1<<5)
#define ETH_FAST_PATH_RX_CQE_END_FLG_SHIFT 5
#define ETH_FAST_PATH_RX_CQE_RESERVED0 (0x3<<6)
#define ETH_FAST_PATH_RX_CQE_RESERVED0_SHIFT 6
	volatile __u8 status_flags;
#define ETH_FAST_PATH_RX_CQE_RSS_HASH_TYPE (0x7<<0)
#define ETH_FAST_PATH_RX_CQE_RSS_HASH_TYPE_SHIFT 0
#define ETH_FAST_PATH_RX_CQE_RSS_HASH_FLG (0x1<<3)
#define ETH_FAST_PATH_RX_CQE_RSS_HASH_FLG_SHIFT 3
#define ETH_FAST_PATH_RX_CQE_BROADCAST_FLG (0x1<<4)
#define ETH_FAST_PATH_RX_CQE_BROADCAST_FLG_SHIFT 4
#define ETH_FAST_PATH_RX_CQE_MAC_MATCH_FLG (0x1<<5)
#define ETH_FAST_PATH_RX_CQE_MAC_MATCH_FLG_SHIFT 5
#define ETH_FAST_PATH_RX_CQE_IP_XSUM_NO_VALIDATION_FLG (0x1<<6)
#define ETH_FAST_PATH_RX_CQE_IP_XSUM_NO_VALIDATION_FLG_SHIFT 6
#define ETH_FAST_PATH_RX_CQE_L4_XSUM_NO_VALIDATION_FLG (0x1<<7)
#define ETH_FAST_PATH_RX_CQE_L4_XSUM_NO_VALIDATION_FLG_SHIFT 7
	volatile __u8 placement_offset;
	volatile __u8 queue_index;
	volatile __u32 rss_hash_result;
	volatile __u16 vlan_tag;
	volatile __u16 pkt_len;
	volatile __u16 len_on_bd;
	struct parsing_flags pars_flags;
	volatile __u16 sgl[8];
};

struct eth_rx_cqe_next_page {
	__u32 addr_lo;
	__u32 addr_hi;
	__u32 reserved[6];
};

union eth_rx_cqe {
	struct eth_fast_path_rx_cqe fast_path_cqe;
	struct common_ramrod_eth_rx_cqe ramrod_cqe;
	struct eth_rx_cqe_next_page next_page_cqe;
};

/******************************************************************************
 *  BNX2X Registers and HSI
 ******************************************************************************/
#define BNX2X_BAR_SIZE			0x500000
#define BNX2X_BAR2_SIZE			0x12000

#define BNX2X_CHIP_ID(bp)		(bp->chip_id & 0xfffffff0)

#define PORT_MAX			2

/* [R 4] This field indicates the type of the device. '0' - 2 Ports; '1' - 1
 *    Port. */
#define BNX2X_MISC_REG_BOND_ID                                         0xa400
/* [R 8] These bits indicate the metal revision of the chip. This value
 *    starts at 0x00 for each all-layer tape-out and increments by one for each
 *       tape-out. */
#define BNX2X_MISC_REG_CHIP_METAL                                      0xa404
/* [R 16] These bits indicate the part number for the chip. */
#define BNX2X_MISC_REG_CHIP_NUM                                        0xa408
/* [R 4] These bits indicate the base revision of the chip. This value
 *    starts at 0x0 for the A0 tape-out and increments by one for each
 *       all-layer tape-out. */
#define BNX2X_MISC_REG_CHIP_REV                                        0xa40c

#define BNX2X_CHIP_NUM(bp)		(bp->chip_id >> 16)
#define CHIP_NUM_57710			0x164e
#define CHIP_NUM_57711			0x164f
#define CHIP_NUM_57711E			0x1650
#define CHIP_NUM_57712			0x1662
#define CHIP_NUM_57712E			0x1663
#define CHIP_IS_E1(bp)			(BNX2X_CHIP_NUM(bp) == CHIP_NUM_57710)
#define CHIP_IS_57711(bp)		(BNX2X_CHIP_NUM(bp) == CHIP_NUM_57711)
#define CHIP_IS_57711E(bp)		(BNX2X_CHIP_NUM(bp) == CHIP_NUM_57711E)
#define CHIP_IS_57712(bp)		(BNX2X_CHIP_NUM(bp) == CHIP_NUM_57712)
#define CHIP_IS_57712E(bp)		(BNX2X_CHIP_NUM(bp) == CHIP_NUM_57712E)
#define CHIP_IS_E1H(bp)			(CHIP_IS_57711(bp) || \
					 CHIP_IS_57711E(bp))
#define CHIP_IS_E2(bp)			(CHIP_IS_57712(bp) || \
					 CHIP_IS_57712E(bp))
#define IS_E1H_OFFSET			CHIP_IS_E1H(bp)

#define MISC_REG_SHARED_MEM_ADDR			0xa2b4

#define MISC_REG_BOND_ID				0xa400
#define MISC_REG_CHIP_METAL				0xa404
#define MISC_REG_CHIP_NUM				0xa408
#define MISC_REG_CHIP_REV				0xa40c

#define MISC_REG_PORT4MODE_EN				0x4750
#define MISC_REG_PORT4MODE_EN_OVWR			0x4720

#define BAR_USTRORM_INTMEM				0x400000
#define BAR_CSTRORM_INTMEM				0x410000
#define BAR_XSTRORM_INTMEM				0x420000
#define BAR_TSTRORM_INTMEM				0x430000

#define USTORM_RX_PRODS_OFFSET(port, client_id) \
	(IS_E1H_OFFSET ? (0x1000 + (port * 0x680) + (client_id * 0x40)) \
	: (0x4000 + (port * 0x360) + (client_id * 0x30)))

struct iro {
	__u32 base;
	__u16 m1;
	__u16 m2;
	__u16 m3;
	__u16 size;
};

#define USTORM_RX_PRODS_E1X_OFFSET(port, client_id) \
	bp->iro[0].base + ((port) * bp->iro[0].m1) + ((client_id) * bp->iro[0].m2)

#define USTORM_RX_PRODS_E2_OFFSET(qzone_id) \
	(bp->iro[0].base + ((qzone_id) * bp->iro[0].m1))

#define ETH_MAX_RX_CLIENTS_E1H		28
#define ETH_MAX_RX_CLIENTS_E2		28

#define BNX2X_CL_QZONE_ID(bp, cli)					\
		cli + (bp->port * (CHIP_IS_E2(bp) ?			\
				   ETH_MAX_RX_CLIENTS_E2 :		\
				   ETH_MAX_RX_CLIENTS_E1H))

#define	SHMEM_P0_ISCSI_MAC_UPPER	0x4c
#define	SHMEM_P0_ISCSI_MAC_LOWER	0x50
#define	SHMEM_P1_ISCSI_MAC_UPPER	0x1dc
#define	SHMEM_P1_ISCSI_MAC_LOWER	0x1e0

#define SHMEM_ISCSI_MAC_UPPER(bp)	\
	(((bp)->port == 0) ? SHMEM_P0_ISCSI_MAC_UPPER : SHMEM_P1_ISCSI_MAC_UPPER)

#define SHMEM_ISCSI_MAC_LOWER(bp)	\
	(((bp)->port == 0) ? SHMEM_P0_ISCSI_MAC_LOWER : SHMEM_P1_ISCSI_MAC_LOWER)

#define BNX2X_RCQ_DESC_CNT	(4096 / sizeof(union eth_rx_cqe))
#define BNX2X_MAX_RCQ_DESC_CNT		(BNX2X_RCQ_DESC_CNT - 1)

#define BNX2X_RX_DESC_CNT	(4096 / sizeof(struct eth_rx_bd))
#define BNX2X_MAX_RX_DESC_CNT		(BNX2X_RX_DESC_CNT - 2)

#define BNX2X_TX_DESC_CNT	(4096 / sizeof(struct eth_tx_start_bd))
#define BNX2X_MAX_TX_DESC_CNT		(BNX2X_TX_DESC_CNT - 1)

#define BNX2X_NEXT_RX_IDX(x)	((((x) & (BNX2X_RX_DESC_CNT - 1)) == \
				  (BNX2X_MAX_RX_DESC_CNT - 1)) ? (x) + 3 : (x) + 1)

#define BNX2X_NEXT_RCQ_IDX(x)	((((x) & BNX2X_MAX_RCQ_DESC_CNT) == \
				  (BNX2X_MAX_RCQ_DESC_CNT - 1)) ? (x) + 2 : (x) + 1)

#define BNX2X_NEXT_TX_BD(x) (((x) & (BNX2X_MAX_TX_DESC_CNT - 1)) ==	\
		(BNX2X_MAX_TX_DESC_CNT - 1)) ?				\
	(x) + 2 : (x) + 1

#define BNX2X_TX_RING_IDX(x) ((x) & BNX2X_MAX_TX_DESC_CNT)

struct ustorm_eth_rx_producers {
	__u16 cqe_prod;
	__u16 bd_prod;
	__u16 sge_prod;
	__u16 reserved;
};

#define BNX2X_UNKNOWN_MAJOR_VERSION	-1
#define BNX2X_UNKNOWN_MINOR_VERSION	-1
#define BNX2X_UNKNOWN_SUB_MINOR_VERSION	-1
struct bnx2x_driver_version {
	uint16_t	major;
	uint16_t	minor;
	uint16_t	sub_minor;
};

typedef struct bnx2x {
	nic_t	*parent;

	struct bnx2x_driver_version version;

	uint16_t   flags;
#define CNIC_UIO_UNITIALIZED		0x0001
#define CNIC_UIO_INITIALIZED		0x0002
#define CNIC_UIO_ENABLED		0x0004
#define CNIC_UIO_DISABLED		0x0008
#define CNIC_UIO_IPv6_ENABLED		0x0010
#define CNIC_UIO_ADDED_MULICAST		0x0020
#define CNIC_UIO_MSIX_ENABLED		0x0200
#define CNIC_UIO_TX_HAS_SENT		0x0400

	void *reg;		/* Pointer to the BAR1 mapped registers	*/
	void *reg2;		/* Pointer to the BAR2 mapped registers	*/

	int mem_fd;

	__u32 chip_id;
	__u32 shmem_base;
	int func;
	int port;
	int pfid;

	struct iro *iro;

	__u32 tx_doorbell;

	__u16 tx_prod;
	__u16 tx_bd_prod;
	__u16 tx_cons;

	__u32 rx_prod_io;

	__u16 rx_prod;
	__u16 rx_bd_prod;
	__u16 rx_cons;
	__u16 rx_bd_cons;

	__u16 (*get_rx_cons)(struct bnx2x *);
	__u16 (*get_tx_cons)(struct bnx2x *);

	/*  RX ring parameters */
	uint32_t rx_ring_size;
	uint32_t rx_buffer_size;

	void *bufs;		/* Pointer to the mapped buffer space	*/

	/*  Hardware Status Block locations */
	void *sblk_map;
	union {
		struct host_def_status_block *def;
		struct host_sp_status_block *sp;
	} status_blk;

	int status_blk_size;

	uint16_t rx_index;
	union eth_rx_cqe *rx_comp_ring;
	void **rx_pkt_ring;

	struct eth_tx_start_bd *tx_ring;
	void *tx_pkt;

} bnx2x_t;

/******************************************************************************
 *  bnx2x Function Declarations
 ******************************************************************************/
void bnx2x_start_xmit(nic_t *nic, size_t len);

//struct nic_interface * bnx2x_find_nic_iface(nic_t * nic,
//                                           uint16_t vlan_id);

struct nic_ops * bnx2x_get_ops();
#endif /* __BNX2X_H__*/
