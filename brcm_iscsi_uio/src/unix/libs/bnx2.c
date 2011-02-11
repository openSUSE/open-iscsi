/* bnx2.c: CNIC user space driver
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
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <fcntl.h>
#include <unistd.h>

#include "config.h"

#include "build_date.h"
#include "bnx2.h"
#include "cnic.h"
#include "logger.h"
#include "nic.h"
#include "nic_utils.h"
#include "options.h"

#define PFX	"bnx2 "

/*  Foward struct declarations */
struct nic_ops bnx2_op;

/*  Determine is the CNIC kernel module is loaded or not */
int lib_bnx2_loaded = 0;

/*******************************************************************************
 * NIC Library Strings
 ******************************************************************************/
static const char library_name[] = "bnx2";
static const char library_version[] = PACKAGE_VERSION;
static const char library_uio_name[] = "bnx2_cnic";

/*  Template strings used to read RX parameters from sysfs */
static const char cnic_sysfs_buf_size_template[] = "/sys/class/uio/uio%d/device/uio_buf_size";
static const char cnic_sysfs_rx_ring_size_template[] = "/sys/class/uio/uio%d/device/uio_rx_ring_size";
static const char cnic_sysfs_uio_event_template[] = "/sys/class/uio/uio%d/event";

/*  The name that should be returned from /sys/class/uio/uio0/name */
static const char cnic_uio_sysfs_name_tempate[] = "/sys/class/uio/uio%i/name";
static const char cnic_uio_sysfs_name[] = "bnx2_cnic";

/*******************************************************************************
 * String constants used to display human readable adapter name
 ******************************************************************************/
static const char brcm_5706C[] = "Broadcom NetXtreme II BCM5706 1000Base-T";
static const char hp_NC370T[]  = "HP NC370T Multifunction Gigabit Server Adapter";
static const char hp_NC370I[]  = "HP NC370i Multifunction Gigabit Server Adapter";
static const char brcm_5706S[] = "Broadcom NetXtreme II BCM5706 1000Base-SX";
static const char hp_NC370F[]  = "HP NC370F Multifunction Gigabit Server Adapter";
static const char brcm_5708C[] = "Broadcom NetXtreme II BCM5708 1000Base-T";
static const char brcm_5708S[] = "Broadcom NetXtreme II BCM5708 1000Base-SX";
static const char brcm_5709C[] = "Broadcom NetXtreme II BCM5709 1000Base-T";
static const char brcm_5709S[] = "Broadcom NetXtreme II BCM5709 1000Base-SX";
static const char brcm_5716C[] = "Broadcom NetXtreme II BCM5716 1000Base-T";
static const char brcm_5716S[] = "Broadcom NetXtreme II BCM5716 1000Base-SX";

/*******************************************************************************
 * PCI ID constants
 ******************************************************************************/
#define PCI_VENDOR_ID_BROADCOM          0x14e4
#define PCI_DEVICE_ID_NX2_5709          0x1639
#define PCI_DEVICE_ID_NX2_5709S         0x163a
#define PCI_DEVICE_ID_NX2_5706          0x164a
#define PCI_DEVICE_ID_NX2_5708          0x164c
#define PCI_DEVICE_ID_NX2_5706S         0x16aa
#define PCI_DEVICE_ID_NX2_5708S         0x16ac

#define PCI_VENDOR_ID_HP                0x103c

#define PCI_ANY_ID (~0)

/*  This is the table used to match PCI vendor and device ID's to the
 *  human readable string names of the devices */
static const struct pci_device_id bnx2_pci_tbl[] = {
        { PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_5706,
          PCI_VENDOR_ID_HP, 0x3101, hp_NC370T },
        { PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_5706,
          PCI_VENDOR_ID_HP, 0x3106, hp_NC370I },
        { PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_5706,
          PCI_ANY_ID, PCI_ANY_ID, brcm_5706S },
        { PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_5708,
          PCI_ANY_ID, PCI_ANY_ID, brcm_5708C },
        { PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_5706S,
          PCI_VENDOR_ID_HP, 0x3102, hp_NC370F },
        { PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_5706S,
          PCI_ANY_ID, PCI_ANY_ID, brcm_5706S },
        { PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_5708S,
          PCI_ANY_ID, PCI_ANY_ID, brcm_5708S },
        { PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_5709,
          PCI_ANY_ID, PCI_ANY_ID, brcm_5709C },
        { PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_5709S,
          PCI_ANY_ID, PCI_ANY_ID, brcm_5709S },
        { PCI_VENDOR_ID_BROADCOM, 0x163b,
          PCI_ANY_ID, PCI_ANY_ID, brcm_5716C },
        { PCI_VENDOR_ID_BROADCOM, 0x163c,
          PCI_ANY_ID, PCI_ANY_ID, brcm_5716S },
};

/*******************************************************************************
 * bnx2 Library Functions
 ******************************************************************************/
/**
 *  bnx2_get_library_name() - Used to get the name of this NIC libary
 *  @param name - This function will return the pointer to this NIC
 *                library name
 *  @param name_size
 */
static void bnx2_get_library_name(char **name,
				  size_t *name_size)
{
	*name = (char *)library_name;
	*name_size = sizeof(library_name);
}

/**
 *  bnx2_get_library_version() - Used to get the version string of this
 *                               NIC libary
 *  @param version - This function will return the pointer to this NIC
 *                   library version string
 *  @param version_size - This will be set with the version size 
 */
static void bnx2_get_library_version(char **version,
				     size_t *version_size)
{
	*version = (char *) library_version;
	*version_size = sizeof(library_version);
}

/**
 *  bnx2_get_build_date() - Used to get the build date string of this library
 *  @param version - This function will return the pointer to this NIC
 *                   library build date string
 *  @param version_size - This will be set with the build date string size 
 */
static void bnx2_get_build_date(char **build,
				size_t *build_size)
{
	*build = (char *) build_date;
	*build_size = sizeof(build_date);
}

/**
 *  bnx2_get_transport_name() - Used to get the transport name associated
 *                              with this this NIC libary
 *  @param transport_name - This function will return the pointer to this NIC
 *                          library's associated transport string
 *  @param transport_name_size - This will be set with the transport name size
 */
static void bnx2_get_transport_name(char **transport_name,
		  	  	    size_t *transport_name_size)
{
	*transport_name = (char *) bnx2i_library_transport_name;
	*transport_name_size = bnx2i_library_transport_name_size;
}

/**
 *  bnx2_get_uio_name() - Used to get the uio name associated with this this 
 *                        NIC libary
 *  @param uio_name - This function will return the pointer to this NIC
 *                    library's associated uio string
 *  @param transport_name_size - This will be set with the uio name size
 */
static void bnx2_get_uio_name(char **uio_name,
			      size_t *uio_name_size)
{
	*uio_name = (char *) library_uio_name;
	*uio_name_size = sizeof(library_uio_name);
}

/**
 *  bnx2_get_pci_table() - Used to get the PCI table for this NIC libary
 *  			   to determine which NIC's based off of PCI ID's
 *  			   are supported
 *  @param table - This function will return the pointer to the PCI table
 *  @param entries - This function will return the number of entries in the NIC
 *                   library's PCI table
 */
static void bnx2_get_pci_table(struct pci_device_id **table,
			       uint32_t *entries)
{
	*table = (struct pci_device_id *) bnx2_pci_tbl;
	*entries = (uint32_t) (sizeof(bnx2_pci_tbl)/sizeof(bnx2_pci_tbl[0]));
}

/**
 *  bnx2_get_ops() - Used to get the NIC library op table
 *  @param op - The op table of this NIC library
 */
struct nic_ops * bnx2_get_ops()
{
	return &bnx2_op;
}

/*******************************************************************************
 * bnx2 Utility Functions
 ******************************************************************************/
/*******************************************************************************
 * Utility Functions Used to read register from the CNIC device
 ******************************************************************************/
static void bnx2_wr32(bnx2_t *bp, __u32 off, __u32 val)
{
	*((volatile __u32 *)(bp->reg + off)) = val;
}

static void bnx2_wr16(bnx2_t *bp, __u32 off, __u16 val)
{
	*((volatile __u16 *)(bp->reg + off)) = val;
}

static __u32 bnx2_rd32(bnx2_t *bp, __u32 off)
{
	return *((volatile __u32 *)(bp->reg + off));
}

static int bnx2_reg_sync(bnx2_t *bp, __u32 off, __u16 length)
{
	return msync(bp->reg + off, length, MS_SYNC);
}

/**
 * bnx2_get_chip_id() - Used to retrive the chip ID from the nic
 * @param dev - Device used to determin NIC type
 * @return Chip ID read from the MISC ID register
 */
static int bnx2_get_chip_id(bnx2_t *bp)
{
	return bnx2_rd32(bp, BNX2_MISC_ID);
}

/**
 *  bnx2_uio_verify()
 *
 */
static int bnx2_uio_verify(nic_t *nic)
{
        char *raw = NULL, *raw_tmp;
	uint32_t raw_size = 0;
	char temp_path[sizeof(cnic_uio_sysfs_name_tempate) + 8];
	int rc = 0;

	/*  Build the path to determine uio name */
	snprintf(temp_path, sizeof(temp_path),
		 cnic_uio_sysfs_name_tempate, nic->uio_minor);

        rc = capture_file(&raw, &raw_size, temp_path);
        if(rc != 0)
        {
                goto error;
        }

	/* sanitize name string by replacing newline with null termination */
	raw_tmp = raw;
	while(*raw_tmp != '\n')
		raw_tmp++;
	*raw_tmp = '\0';

	if (strncmp(raw, cnic_uio_sysfs_name,
		    sizeof(cnic_uio_sysfs_name)) != 0) {
		LOG_ERR(PFX "%s: uio names not equal: "
		            "expecting %s got %s from %s",
			nic->log_name, cnic_uio_sysfs_name, raw, temp_path);
		rc = -EIO;
	}

	free(raw);

	LOG_INFO(PFX "%s: Verified is a cnic_uio device", nic->log_name);

      error:
	return rc;
}

/*******************************************************************************
 * bnx2 Utility Functions to get to the hardware consumer indexes
 ******************************************************************************/
static __u16 bnx2_get_rx_msix(bnx2_t *bp)
{
	struct status_block_msix *sblk = bp->status_blk.msix;
	__u16 rx_cons;

	msync(sblk, sizeof(*sblk), MS_SYNC);
	rx_cons = sblk->status_rx_quick_consumer_index;
	barrier();
	if ((rx_cons & (MAX_RX_DESC_CNT)) == (MAX_RX_DESC_CNT))
		rx_cons++;

	return rx_cons;
}

static __u16 bnx2_get_rx_msi(bnx2_t *bp)
{
	struct status_block *sblk = bp->status_blk.msi;
	__u16 rx_cons;

	msync(sblk, sizeof(*sblk), MS_SYNC);
	rx_cons = CNIC_SBLK_EVEN_IDX(sblk->rx2);
	barrier();
	if ((rx_cons & (MAX_RX_DESC_CNT)) == (MAX_RX_DESC_CNT))
		rx_cons++;

	return rx_cons;
}

static __u16 bnx2_get_tx_msix(bnx2_t *bp)
{
        struct status_block_msix *sblk = bp->status_blk.msix;
        __u16 tx_cons;

	msync(sblk, sizeof(*sblk), MS_SYNC);
        tx_cons = sblk->status_tx_quick_consumer_index;
	barrier();
        if ((tx_cons & (MAX_TX_DESC_CNT)) == (MAX_TX_DESC_CNT))
                tx_cons++;

        return tx_cons;
}

static __u16 bnx2_get_tx_msi(bnx2_t *bp)
{
	struct status_block *sblk = bp->status_blk.msi;
	__u16 tx_cons;

	msync(sblk, sizeof(*sblk), MS_SYNC);
	tx_cons = CNIC_SBLK_EVEN_IDX(sblk->tx2);
	barrier();
	if ((tx_cons & (MAX_TX_DESC_CNT)) == (MAX_TX_DESC_CNT))
		tx_cons++;

	return tx_cons;
}

typedef enum {
	CNIC_VLAN_STRIPPING_ENABLED = 1,
	CNIC_VLAN_STRIPPING_DISABLED = 2,
} CNIC_VLAN_STRIPPING_MODE;

/**
 *  bnx2_strip_vlan_enabled() - This will query the device to determine whether
 *                              VLAN tag stripping is enabled or not
 *  @param dev - device to check stripping or not
 *  @ return CNIC_VLAN_STRIPPING_ENABLED stripping is enabled
 *           CNIC_VLAN_STRIPPING_DISABLED stripping is not enabled
 */
static CNIC_VLAN_STRIPPING_MODE bnx2_strip_vlan_enabled(bnx2_t *bp)
{
	uint32_t val;

	val = bnx2_rd32(bp, BNX2_EMAC_RX_MODE);

	if(val & BNX2_EMAC_RX_MODE_KEEP_VLAN_TAG)
		return CNIC_VLAN_STRIPPING_DISABLED;
	else
		return CNIC_VLAN_STRIPPING_ENABLED;
}

/**
 *  bnx2_alloc() - Used to allocate a CNIC structure
 */
static bnx2_t * bnx2_alloc(nic_t *nic)
{
	bnx2_t *bp = malloc(sizeof(*bp));
	if(bp == NULL)
	{
		LOG_ERR(PFX "%s: Could not allocate CNIC space",
			nic->log_name);
		return NULL;
	}

	/*  Clear out the CNIC contents */
	memset(bp, 0, sizeof(*bp));

	bp->flags = CNIC_UIO_TX_HAS_SENT;

	bp->parent = nic;
	nic->priv = (void *) bp;

	return bp;
}

/**
 * bnx2_open() - This will initialize all the hardware resources 
 * @param dev - The struct nic device to open
 * @return 0 on success, on failure a errno will be returned
 */
static int bnx2_open(nic_t *nic)
{
	bnx2_t *bp; 
	struct stat uio_stat;
	int i, rc;
	__u32 val;
	uint32_t tx_cid;
	__u32 msix_vector = 0;

	/*  Sanity Check: validate the parameters */
	if (nic == NULL) {
		LOG_ERR(PFX "bnx2_open(): nic == NULL");
		return -EINVAL;
	}

	bp = bnx2_alloc(nic);
	if (bp == NULL) {
		LOG_ERR(PFX "bnx2_open(): Couldn't allocate bp priv struct",
			nic->log_name);
		return -ENOMEM;
	}

	while (nic->fd < 0) {
		nic->fd = open(nic->uio_device_name, O_RDWR | O_NONBLOCK);
		if (nic->fd != INVALID_FD) {
			LOG_ERR(PFX "%s: uio device has been brought up via pid: %d on fd: %d",
				nic->uio_device_name, getpid(), nic->fd);

			rc = bnx2_uio_verify(nic);
			if(rc != 0)
				continue;

			break;
		} else {
			if (lib_bnx2_loaded == 0) {
				LOG_ERR(PFX "%s: Could not open device: %s, "
					    "awaiting for the device to appear",
					nic->log_name, nic->uio_device_name);
		
				/*  Time to wait for the device to come up */
				pthread_mutex_lock(&nic->uio_wait_mutex);
				pthread_cond_wait(&nic->uio_wait_cond,
						  &nic->uio_wait_mutex);
				pthread_mutex_unlock(&nic->uio_wait_mutex);

				/*  udev might not have created the file yet */
				sleep(2);

				lib_bnx2_loaded = 1;
			} else {
				/*  udev might not have created the file yet */
				sleep(2);
			}
		}
	}
	if (fstat(nic->fd, &uio_stat) < 0) {
		LOG_ERR(PFX "%s: Could not fstat device", nic->log_name);
		return -ENODEV;
	}
	nic->uio_minor = minor(uio_stat.st_rdev);

	/*  TODO: hardcoded with the cnic driver */
	bp->rx_ring_size = 3;
	bp->rx_buffer_size = 0x400;

	LOG_DEBUG(PFX "%s: using rx ring size: %d, rx buffer size: %d",
		  nic->log_name, bp->rx_ring_size, bp->rx_buffer_size);

	/*  Determine the number of UIO events that have already occured */
	rc = detemine_initial_uio_events(nic, &nic->intr_count);
	if(rc != 0) {
		LOG_ERR("Could not determine the number ofinitial UIO events");
		nic->intr_count = 0;
	}

	/*  Allocate space for rx ring pointer */
	bp->rx_ring = malloc(sizeof(struct l2_fhdr *) * bp->rx_ring_size);
	if(bp->rx_ring == NULL)
	{
		LOG_ERR(PFX "%s: Could not allocate space for rx_ring",
			nic->log_name);
		goto error_alloc_rx_ring;
	}
	mlock(bp->rx_ring, sizeof(struct l2_fhdr *) * bp->rx_ring_size);

	/*  Allocate space for rx pkt ring */
	bp->rx_pkt_ring = malloc(sizeof(void *) * bp->rx_ring_size);
	if(bp->rx_pkt_ring == NULL)
	{
		LOG_ERR(PFX "%s: Could not allocate space for rx_pkt_ring",
			nic->log_name);
		goto error_alloc_rx_pkt_ring;
	}
	mlock(bp->rx_pkt_ring, sizeof(void *) * bp->rx_ring_size);

	bp->reg = mmap(NULL, 0x12800, PROT_READ | PROT_WRITE, MAP_SHARED,
			 nic->fd, (off_t) 0);
	if (bp->reg == MAP_FAILED) {
		LOG_INFO(PFX "%s: Couldn't mmap registers: %s",
			 nic->log_name, strerror(errno));
		bp->reg = NULL;
		goto error_regs;
	}

	msync(bp->reg, 0x12800, MS_SYNC);
	LOG_DEBUG(PFX "Chip ID: %x", bnx2_get_chip_id(bp));

	/*  on a 5709 when using MSI-X the status block is at an offset */
	if(CHIP_NUM(bnx2_get_chip_id(bp)) == CHIP_NUM_5709) {
		/*  determine if we are using MSI-X */
		val = bnx2_rd32(bp, BNX2_TSCH_TSS_CFG);
		if(val) {
			/*  We are in MSI-X mode */
			uint32_t base_cid = ((val >> 10) & 0x7ff) << 3;
			msix_vector = (val >> 24) & 0xf;

			bp->status_blk_size = (128 * 9);

			tx_cid = base_cid + msix_vector - 1;
			bp->flags |= CNIC_UIO_MSIX_ENABLED;

			bp->get_tx_cons  = bnx2_get_tx_msix;
			bp->get_rx_cons  = bnx2_get_rx_msix;

			LOG_DEBUG(PFX "%s: tss_cfg: 0x%x tx cid: %d",
				  nic->log_name, val, tx_cid);

			LOG_INFO(PFX "%s: detected using MSI-X vector: %d",
				 nic->log_name, msix_vector);
		} else {
			/*  We are not in MSI-X mode */
			bp->status_blk_size = 64;
			tx_cid = 20;

			bp->get_tx_cons  = bnx2_get_tx_msi;
			bp->get_rx_cons  = bnx2_get_rx_msi;
		}
	} else {
		bp->status_blk_size = 64;
		tx_cid = 20;

		bp->get_tx_cons  = bnx2_get_tx_msi;
		bp->get_rx_cons  = bnx2_get_rx_msi;
	}

	bp->sblk_map = mmap(NULL, bp->status_blk_size,
		 	     PROT_READ | PROT_WRITE, MAP_SHARED,
			     nic->fd, (off_t) getpagesize());
	if (bp->sblk_map == MAP_FAILED) {
		LOG_INFO(PFX "%s: Could not mmap status block: %s",
			 nic->log_name, strerror(errno));
		goto error_sblk;
	}

	if(bp->flags & CNIC_UIO_MSIX_ENABLED) {
		uint8_t *status_blk =  (uint8_t *) bp->sblk_map;
		status_blk += (msix_vector * 128);

		bp->status_blk.msix = (struct status_block_msix *) status_blk;

		LOG_DEBUG(PFX "%s: msix initial cons: tx:%d rx:%d",
				nic->log_name,
			bp->status_blk.msix->status_tx_quick_consumer_index,
			bp->status_blk.msix->status_rx_quick_consumer_index);
	} else {
		bp->status_blk.msi = (struct status_block *) bp->sblk_map;

		LOG_DEBUG(PFX "%s: msi initial tx:%d rx:%d",
			  nic->log_name,
			  CNIC_SBLK_EVEN_IDX(bp->status_blk.msi->tx2),
			  CNIC_SBLK_EVEN_IDX(bp->status_blk.msi->rx2));
	}

	bp->tx_ring = mmap(NULL, 2 * getpagesize(),
			    PROT_READ | PROT_WRITE, MAP_SHARED, nic->fd,
			    (off_t) 2 * getpagesize());
	if (bp->tx_ring == MAP_FAILED) {
		LOG_INFO(PFX "%s: Could not mmap tx ring: %s",
			 nic->log_name, strerror(errno));
		bp->tx_ring = NULL;
		goto error_tx_ring;
	}

	bp->bufs = mmap(NULL, (bp->rx_ring_size + 1) * bp->rx_buffer_size,
			 PROT_READ | PROT_WRITE,
			 MAP_SHARED, nic->fd, (off_t) 3 * getpagesize());
	if (bp->bufs == MAP_FAILED) {
		LOG_INFO(PFX "%s: Could not mmap buffers: %s",
			 nic->log_name, strerror(errno));
		bp->bufs = NULL;
		goto error_bufs;
	}

	bp->tx_bidx_io = MB_GET_CID_ADDR(tx_cid) + BNX2_L2CTX_TX_HOST_BIDX;
	bp->tx_bseq_io = MB_GET_CID_ADDR(tx_cid) + BNX2_L2CTX_TX_HOST_BSEQ;
	LOG_INFO(PFX "%s: tx_bidx_io: 0x%x tx_bseq_io: 0x%x",
		 nic->log_name,
		 bp->tx_bidx_io, bp->tx_bseq_io);

	bp->rx_bidx_io = MB_GET_CID_ADDR(2) + BNX2_L2CTX_HOST_BDIDX;
	bp->rx_bseq_io = MB_GET_CID_ADDR(2) + BNX2_L2CTX_HOST_BSEQ;

	bp->tx_cons = 0;
	bp->tx_prod = 0;
	bp->tx_pkt = bp->bufs;

	bp->rx_index = 0;
	bp->rx_cons = 0;
	bp->rx_prod = bp->rx_ring_size;
	bp->rx_bseq = bp->rx_prod * bp->rx_buffer_size;
	bnx2_wr16(bp, bp->rx_bidx_io, bp->rx_prod);
	bnx2_wr32(bp, bp->rx_bseq_io, bp->rx_bseq);

	bnx2_reg_sync(bp, bp->rx_bidx_io, sizeof(__u16));
	bnx2_reg_sync(bp, bp->rx_bseq_io, sizeof(__u32));

	for (i = 0; i < bp->rx_ring_size; i++) {
		void *ptr = bp->bufs + (bp->rx_buffer_size * (i + 1));

		bp->rx_ring[i] = (struct l2_fhdr *)ptr;
		bp->rx_pkt_ring[i] = ptr + sizeof(struct l2_fhdr) + 2;
	}

	/*  Read the MAC address used for the iSCSI interface */
	val = bnx2_rd32(bp, BNX2_EMAC_MAC_MATCH4);
	nic->mac_addr[0] = (__u8) (val >> 8);
	nic->mac_addr[1] = (__u8) val;

	val = bnx2_rd32(bp, BNX2_EMAC_MAC_MATCH5);
	nic->mac_addr[2] = (__u8) (val >> 24);
	nic->mac_addr[3] = (__u8) (val >> 16);
	nic->mac_addr[4] = (__u8) (val >> 8);
	nic->mac_addr[5] = (__u8) val;

	LOG_INFO(PFX "%s:  Using mac address: %2x:%2x:%2x:%2x:%2x:%2x",
		 nic->log_name,
		 nic->mac_addr[0], nic->mac_addr[1], nic->mac_addr[2],
		 nic->mac_addr[3], nic->mac_addr[4], nic->mac_addr[5]);

	/*  Determine if Hardware VLAN tag stripping is enabled or not */
	if(CNIC_VLAN_STRIPPING_ENABLED == bnx2_strip_vlan_enabled(bp))
	{
		nic->flags |= NIC_VLAN_STRIP_ENABLED;
	}

	/*  Prepare the multicast addresses */
	rc = enable_multicast(nic);
	if(rc != 0)
		goto error_bufs;

	msync(bp->reg, 0x12800, MS_SYNC);
	LOG_INFO("%s: CNIC uio initialized", nic->log_name);

	return 0;

      error_bufs:
	munmap(bp->tx_ring, 2 * getpagesize());

      error_tx_ring:
	munmap(bp->status_blk.msi, bp->status_blk_size);

      error_sblk:
	munmap(bp->reg, 0x12800);

      error_regs:
	munlock(bp->rx_pkt_ring, sizeof(void *) * bp->rx_ring_size);
	free(bp->rx_pkt_ring);
	bp->rx_pkt_ring = NULL;

      error_alloc_rx_pkt_ring:
	munlock(bp->rx_ring, sizeof(struct l2_fhdr *) * bp->rx_ring_size);
	free(bp->rx_ring);
	bp->rx_ring = NULL;

      error_alloc_rx_ring:

	return errno;
}

/**
 *  bnx2_uio_close_resources() - Used to free resource for the NIC/CNIC
 *  @param nic - NIC device to free resource
 *  @param graceful - whether to wait to close gracefully
 *  @return 0 on success, <0 on failure
 */
static int bnx2_uio_close_resources(nic_t *nic, NIC_SHUTDOWN_T graceful)
{
	bnx2_t *bp = (bnx2_t *) nic->priv;
	int rc = 0;

	/*  Remove the multicast addresses if added */
	if((nic->flags & NIC_ADDED_MULICAST) &&
	   (graceful == ALLOW_GRACEFUL_SHUTDOWN))
		disable_multicast(nic);

	/*  Check if there is an assoicated CNIC device */
	if(bp == NULL) {
		LOG_WARN(PFX "%s: when closing resources there is "
		             "no assoicated bnx2",
			     nic->log_name);
		return -EIO;
	}

	/*  Clean up allocated memory */
	if(bp->rx_ring != NULL) {
		free(bp->rx_ring);
		bp->rx_ring = NULL;
	}

	if(bp->rx_pkt_ring != NULL) {
		free(bp->rx_pkt_ring);
		bp->rx_pkt_ring = NULL;
	}

	/*  Clean up mapped registers */
	if (bp->bufs != NULL) {
		rc = munmap(bp->bufs,
			    (bp->rx_ring_size + 1) * bp->rx_buffer_size);
		if (rc != 0)
			LOG_WARN(PFX "%s: Couldn't unmap bufs",
				 nic->log_name);
		bp->bufs = NULL;
	}

	if (bp->tx_ring != NULL) {
		rc = munmap(bp->tx_ring, 2 * getpagesize());
		if (rc != 0)
			LOG_WARN(PFX "%s: Couldn't unmap tx_rings",
				 nic->log_name);
		bp->tx_ring = NULL;
	}

	if (bp->status_blk.msix != NULL || 
	    bp->status_blk.msi  != NULL) {
		rc = munmap(bp->sblk_map, bp->status_blk_size);
		if (rc != 0)
			LOG_WARN(PFX "%s: Couldn't unmap status block",
				 nic->log_name);
		bp->sblk_map = NULL;

		bp->status_blk.msix = NULL;
		bp->status_blk.msi = NULL;
	}

	if (bp->reg != NULL) {
		rc = munmap(bp->reg, 0x12800);
		if (rc != 0)
			LOG_WARN(PFX "%s: Couldn't unmap regs",
				 nic->log_name);
		bp->reg = NULL;
	}

	if (nic->fd != INVALID_FD) {
		rc = close(nic->fd);
		if (rc != 0) {
			LOG_WARN(PFX "%s: Couldn't close uio file descriptor: %d",
				 nic->log_name, nic->fd);
		} else {
			LOG_DEBUG(PFX "%s: Closed uio file descriptor: %d",
				 nic->log_name, nic->fd);
		}

		nic->fd = INVALID_FD;
	} else {
		LOG_WARN(PFX "%s: Invalid uio file descriptor: %d",
				 nic->log_name, nic->fd);
	}

	LOG_INFO(PFX "%s: Closed all resources", nic->log_name);

	return 0;
}

/**
 *  bnx2_close() - Used to close the NIC device
 *  @param nic - NIC device to close
 *  @param graceful - whether to wait to close gracefully
 *  @return 0 if successful, <0 if there is an error
 */
static int bnx2_close(nic_t *nic, NIC_SHUTDOWN_T graceful)
{
	/*  Sanity Check: validate the parameters */
	if(nic == NULL) {
		LOG_ERR(PFX "bnx2_close(): nic == NULL");
		return -EINVAL;
	}

	LOG_INFO(PFX "Closing NIC device: %s", nic->log_name);

	bnx2_uio_close_resources(nic, graceful);

	/*  Free any named strings we might be holding onto */
	if(nic->flags & NIC_CONFIG_NAME_MALLOC) {
		free(nic->config_device_name);
		nic->flags &= ~NIC_CONFIG_NAME_MALLOC;
	}
	nic->config_device_name = NULL;

	if(nic->flags & NIC_UIO_NAME_MALLOC) {
		free(nic->uio_device_name);
		nic->uio_device_name = NULL;

		nic->flags &= ~NIC_UIO_NAME_MALLOC;
	}

	return 0;
}

static void bnx2_prepare_xmit_packet(nic_t *nic,
				     nic_interface_t *nic_iface,
				     struct packet *pkt)
{
	bnx2_t *bp = (bnx2_t *) nic->priv;

	/*  Determine if we need to insert the VLAN tag */
	if((nic_iface->vlan_id != 0) && 
	   (NIC_VLAN_STRIP_ENABLED & nic->flags))
	{
		uint16_t insert_tpid = const_htons(UIP_ETHTYPE_8021Q);
		uint16_t insert_vlan_id = htons((0x0FFF & nic_iface->vlan_id) +
			((0x000F & nic_iface->vlan_priority) << 12));

		/* We need to reinsert the VLAN tag */
		memcpy(bp->tx_pkt, pkt->buf, 12);
		memcpy(bp->tx_pkt + 12, &insert_tpid, 2);
		memcpy(bp->tx_pkt + 14, &insert_vlan_id, 2);
		memcpy(bp->tx_pkt + 16, pkt->buf + 12, pkt->buf_size - 12);

		pkt->buf_size = pkt->buf_size +4;

		LOG_DEBUG(PFX "%s: Inserted vlan tag id: 0x%x",
			  nic->log_name,
			  ntohs(insert_vlan_id));
	} else {
		memcpy(bp->tx_pkt, pkt->buf, pkt->buf_size);
	}

	msync(bp->tx_pkt, pkt->buf_size, MS_SYNC);
}

/**
 *  bnx2_get_tx_pkt() - This function is used to a TX packet from the NIC
 *  @param nic - The NIC device to send the packet
 *
 */
void * bnx2_get_tx_pkt(nic_t *nic)
{
	bnx2_t *bp = (bnx2_t *) nic->priv;
	return bp->tx_pkt;
}

/**
 *  bnx2_start_xmit() - This function is used to send a packet of data
 *  @param nic - The NIC device to send the packet
 *  @param len - the length of the TX packet
 *
 */
void bnx2_start_xmit(nic_t *nic, size_t len)
{
	bnx2_t *bp = (bnx2_t *) nic->priv;
	uint16_t ring_prod;
	struct tx_bd *txbd;

	ring_prod = TX_RING_IDX(bp->tx_prod);
	txbd = &bp->tx_ring[ring_prod];

	txbd->tx_bd_mss_nbytes = len;
	txbd->tx_bd_vlan_tag_flags = TX_BD_FLAGS_END | TX_BD_FLAGS_START;

	bp->tx_bseq += len;
	bp->tx_prod = NEXT_TX_BD(bp->tx_prod);

	bnx2_wr16(bp, bp->tx_bidx_io, bp->tx_prod);
	bnx2_wr32(bp, bp->tx_bseq_io, bp->tx_bseq);

	bnx2_reg_sync(bp, bp->tx_bidx_io, sizeof(__u16));
	bnx2_reg_sync(bp, bp->tx_bseq_io, sizeof(__u32));

	LOG_DEBUG(PFX "%s: sent %d bytes using dev->tx_prod: %d",
		      nic->log_name, len, bp->tx_prod);
}

/**
 *  bnx2_write() - Used to write the data to the hardware
 *  @param nic - NIC hardware to read from
 *  @param pkt - The packet which will hold the data to be sent on the wire
 *  @return 0 if successful, <0 if failed
 */
int bnx2_write(nic_t *nic, nic_interface_t *nic_iface,
		packet_t *pkt)
{
	bnx2_t *bp = (bnx2_t *) nic->priv;
	struct uip_stack *uip = &nic_iface->ustack;

	/* Sanity Check: validate the parameters */
	if(nic == NULL || nic_iface == NULL || pkt == NULL) {
		LOG_ERR(PFX "%s: bnx2_write() nic == 0x%p || "
			    " nic_iface == 0x%p || "
			    " pkt == 0x%x", nic, nic_iface, pkt);
		return -EINVAL;
	}

	if(pkt->buf_size == 0) {
		LOG_ERR(PFX "%s: Trying to transmitted 0 sized packet",
			nic->log_name);
		return -EINVAL;
	}

	if(pthread_mutex_trylock(&nic->xmit_mutex) != 0)
	{
		LOG_ERR(PFX "%s: Dropped previous transmitted packet",
			nic->log_name);
		return -EINVAL;
	}

	bnx2_prepare_xmit_packet(nic, nic_iface,
				 pkt);
	bnx2_start_xmit(nic, pkt->buf_size);

	/*  bump the bnx2 dev send statistics */
	nic->stats.tx.packets++;
	nic->stats.tx.bytes += uip->uip_len;

	LOG_DEBUG(PFX "%s: transmitted %d bytes "
		      "dev->tx_cons: %d, dev->tx_prod: %d, dev->tx_bseq:%d",
		  nic->log_name, pkt->buf_size,
		  bp->tx_cons, bp->tx_prod, bp->tx_bseq);

	return 0;
}

/**
 *  bnx2_read() - Used to read the data from the hardware
 *  @param nic - NIC hardware to read from
 *  @param pkt - The packet which will hold the data
 *  @return 0 if successful, <0 if failed
 */
static int bnx2_read(nic_t *nic, packet_t *pkt)
{
	bnx2_t *bp = (bnx2_t *) nic->priv;
	int rc = 0;
	uint16_t hw_cons, sw_cons;

	/* Sanity Check: validate the parameters */
	if (unlikely(nic == NULL || pkt == NULL)) {
		LOG_ERR(PFX "%s: bnx2_write() nic == 0x%p || "
			    " pkt == 0x%x", nic, pkt);
		return -EINVAL;
	}

	hw_cons = bp->get_rx_cons(bp);
	sw_cons = bp->rx_cons;

	if (sw_cons != hw_cons) {
		uint8_t rx_index = bp->rx_index % 3;
		struct l2_fhdr *rx_hdr = bp->rx_ring[rx_index];
		void *rx_pkt = bp->rx_pkt_ring[rx_index];
		int len;
		uint16_t errors;
	
		LOG_DEBUG(PFX "%s: clearing rx interrupt: %d %d %d",
			  nic->log_name,
			  sw_cons, hw_cons, rx_index);

		msync(rx_hdr, sizeof(struct l2_fhdr), MS_SYNC); 
		errors = ((rx_hdr->l2_fhdr_status & 0xffff0000) >> 16);
		len = ((rx_hdr->l2_fhdr_vtag_len & 0xffff0000) >> 16) - 4;

		if (unlikely((errors & (L2_FHDR_ERRORS_BAD_CRC     |
			      		L2_FHDR_ERRORS_PHY_DECODE  |
					L2_FHDR_ERRORS_ALIGNMENT   |
				        L2_FHDR_ERRORS_TOO_SHORT   |
			       		L2_FHDR_ERRORS_GIANT_FRAME)) ||
			     (len <= 0) ||
			     (len > (bp->rx_buffer_size -
			     		(sizeof(struct l2_fhdr) + 2))) || 
			     (len > pkt->max_buf_size))) {
			/*  One of the fields in the BD is bad */
			uint16_t status = ((rx_hdr->l2_fhdr_status &
					    0x0000ffff));

			LOG_ERR(PFX "%s: Recv error: 0x%x status: 0x%x "
				    "len: %d",
				nic->log_name, errors, status, len);

			if ((len < (bp->rx_buffer_size -
			     		(sizeof(struct l2_fhdr) + 2))) &&
			     (len < pkt->max_buf_size))
				dump_packet_to_log(pkt->nic_iface, rx_pkt, len);
		} else {
			msync(rx_pkt, len, MS_SYNC); 
			/*  Copy the data */
			memcpy(pkt->buf, rx_pkt, len);
			pkt->buf_size = len;

			/*  Properly set the packet flags */
			/*  check if there is VLAN tagging on the packet */
			if(rx_hdr->l2_fhdr_status & L2_FHDR_STATUS_VLAN_TAG) {
				pkt->vlan_tag = rx_hdr->l2_fhdr_vtag_len & 0x0FFF;
				pkt->flags |= VLAN_TAGGED;
			} else {
				pkt->vlan_tag = 0;
			}

			rc = 1;

			LOG_DEBUG(PFX "%s: processing packet length: %d",
				  nic->log_name, len);
		}

		bp->rx_index++;
		sw_cons = NEXT_RX_BD(sw_cons);
		bp->rx_prod = NEXT_RX_BD(bp->rx_prod);
		bp->rx_bseq += 0x400;

		bp->rx_cons = sw_cons;
		bnx2_wr16(bp, bp->rx_bidx_io, bp->rx_prod);
		bnx2_wr32(bp, bp->rx_bseq_io, bp->rx_bseq);

		bnx2_reg_sync(bp, bp->rx_bidx_io, sizeof(__u16));
		bnx2_reg_sync(bp, bp->rx_bseq_io, sizeof(__u32));

		/*  bump the bnx2 dev recv statistics */
		nic->stats.rx.packets++;
		nic->stats.rx.bytes += pkt->buf_size;
	}

	return rc;
}
/*******************************************************************************
 * Clearing TX interrupts
 ******************************************************************************/
/**
 *  bnx2_clear_tx_intr() - This routine is called when a TX interrupt occurs
 *  @param nic - the nic the interrupt occured on
 *  @return  0 on success
 */
static int bnx2_clear_tx_intr(nic_t *nic)
{
	bnx2_t *bp = (bnx2_t *) nic->priv;
	uint16_t hw_cons = bp->get_tx_cons(bp);

	/* Sanity check: ensure the parameters passed in are valid */
	if(unlikely(nic == NULL)) {
		LOG_ERR(PFX "bnx2_read() nic == NULL");
		return -EINVAL;
	}

	if(bp->flags & CNIC_UIO_TX_HAS_SENT) {
		bp->flags &= ~CNIC_UIO_TX_HAS_SENT;
	}

	LOG_DEBUG(PFX "%s: clearing tx interrupt [%d %d]",
		  nic->log_name,
		  bp->tx_cons, hw_cons);

	bp->tx_cons = hw_cons;

	/*  There is a queued TX packet that needs to be sent out.  The usual
	 *  case is when stack will send an ARP packet out before sending the
	 *  intended packet */
	if(nic->tx_packet_queue != NULL)
	{
		packet_t *pkt;

		LOG_DEBUG(PFX "%s: sending queued tx packet", nic->log_name);
		pkt = nic_dequeue_tx_packet(nic);

		/*  Got a TX packet buffer of the TX queue and put it onto
		 *  the hardware */
		if(pkt != NULL)
		{
			bnx2_prepare_xmit_packet(nic,
						 pkt->nic_iface,
						 pkt);

			bnx2_start_xmit(nic, pkt->buf_size);

			LOG_DEBUG(PFX "%s: transmitted queued packet %d bytes "
				      "dev->tx_cons: %d, dev->tx_prod: %d, "
				      "dev->tx_bseq:%d",
					  nic->log_name, pkt->buf_size,
					  bp->tx_cons, bp->tx_prod,
					  bp->tx_bseq);

			return -EAGAIN;
		}
	}

	pthread_mutex_unlock(&nic->xmit_mutex);

	return 0;
}

/*******************************************************************************
 * bnx2 NIC op's table
 ******************************************************************************/
struct nic_ops bnx2_op = {
	.description	= "bnx2",
	.open		= bnx2_open,
	.close		= bnx2_close,
	.write		= bnx2_write,
	.get_tx_pkt	= bnx2_get_tx_pkt,
	.start_xmit	= bnx2_start_xmit,
	.read		= bnx2_read,
	.clear_tx_intr	= bnx2_clear_tx_intr,
	.handle_iscsi_path_req = cnic_handle_iscsi_path_req,

	.lib_ops = {
		.get_library_name	= bnx2_get_library_name,
        	.get_pci_table		= bnx2_get_pci_table,
	        .get_library_version	= bnx2_get_library_version,
		.get_build_date		= bnx2_get_build_date,
	        .get_transport_name	= bnx2_get_transport_name,
	        .get_uio_name		= bnx2_get_uio_name,
	},
};
