/* bnx2x.c: bnx2x user space driver
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
#include <linux/types.h>	/* Needed for linux/ethtool.h on RHEL 5.x */
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <fcntl.h>
#include <unistd.h>

#include "config.h"

#include "build_date.h"
#include "bnx2x.h"
#include "cnic.h"
#include "logger.h"
#include "nic.h"
#include "nic_id.h"
#include "nic_utils.h"
#include "options.h"

#define PFX	"bnx2x "

/*  Foward struct declarations */
struct nic_ops bnx2x_op;

/*  Determine is the CNIC kernel module is loaded or not */
int lib_bnx2x_loaded = 0;

/*******************************************************************************
 * NIC Library Strings
 ******************************************************************************/
static const char library_name[] = "bnx2x";
static const char library_version[] = PACKAGE_VERSION;
static const char library_uio_name[] = "bnx2x_cnic";

/*  Template strings used to read RX parameters from sysfs */
static const char cnic_sysfs_buf_size_template[] = "/sys/class/uio/uio%d/device/uio_buf_size";
static const char cnic_sysfs_rx_ring_size_template[] = "/sys/class/uio/uio%d/device/uio_rx_ring_size";
static const char cnic_sysfs_uio_event_template[] = "/sys/class/uio/uio%d/event";

/*  The name that should be returned from /sys/class/uio/uio0/name */
static const char cnic_uio_sysfs_name_tempate[] = "/sys/class/uio/uio%i/name";
static const char bnx2x_uio_sysfs_name[] = "bnx2x_cnic";

static const char cnic_uio_sysfs_resc_tempate[] = "/sys/class/uio/uio%i/device/resource";

/*******************************************************************************
 * String constants used to display human readable adapter name
 ******************************************************************************/
static const char brcm_57710[] = "Broadcom NetXtreme II BCM57710 10-Gigabit";
static const char brcm_57711[] = "Broadcom NetXtreme II BCM57711 10-Gigabit";
static const char brcm_57711e[] = "Broadcom NetXtreme II BCM57711E 10-Gigabit";
static const char brcm_57712[] = "Broadcom NetXtreme II BCM57712 10-Gigabit";
static const char brcm_57712e[] = "Broadcom NetXtreme II BCM57712E 10-Gigabit";
static const char brcm_57713[] = "Broadcom NetXtreme II BCM57713 10-Gigabit";
static const char brcm_57713e[] = "Broadcom NetXtreme II BCM57713E 10-Gigabit";

/*******************************************************************************
 * PCI ID constants
 ******************************************************************************/
#define PCI_VENDOR_ID_BROADCOM		0x14e4
#define PCI_DEVICE_ID_NX2_57710		0x164e
#define PCI_DEVICE_ID_NX2_57711		0x164f
#define PCI_DEVICE_ID_NX2_57711E	0x1650
#define PCI_DEVICE_ID_NX2_57712		0x1662
#define PCI_DEVICE_ID_NX2_57712E	0x1663
#define PCI_DEVICE_ID_NX2_57713		0x1651
#define PCI_DEVICE_ID_NX2_57713E	0x1652
#define PCI_ANY_ID (~0)

/*  This is the table used to match PCI vendor and device ID's to the
 *  human readable string names of the devices */
static const struct pci_device_id bnx2x_pci_tbl[] = {
	{ PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_57710,
	   PCI_ANY_ID, PCI_ANY_ID, brcm_57710 },
	{ PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_57711,
	   PCI_ANY_ID, PCI_ANY_ID, brcm_57711 },
	{ PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_57711E,
	   PCI_ANY_ID, PCI_ANY_ID, brcm_57711e },
	{ PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_57712,
	   PCI_ANY_ID, PCI_ANY_ID, brcm_57712 },
	{ PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_57712E,
	   PCI_ANY_ID, PCI_ANY_ID, brcm_57712e },
	{ PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_57713,
	   PCI_ANY_ID, PCI_ANY_ID, brcm_57713 },
	{ PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_57713E,
	   PCI_ANY_ID, PCI_ANY_ID, brcm_57713e },
};

static struct iro e1_iro[1] = {
	{ 0x45a0,   0x90,    0x8,    0x0,    0x8},
	};

static struct iro e1h_iro[1] = {
	{ 0x1c40,   0xe0,    0x8,    0x0,    0x8},
	};

static struct iro e2_iro[1] = {
	{ 0x6000,   0x20,    0x0,    0x0,    0x8},
	};

/*******************************************************************************
 * BNX2X Library Functions
 ******************************************************************************/
/**
 *  bnx2x_get_library_name() - Used to get the name of this NIC libary
 *  @param name - This function will return the pointer to this NIC
 *                library name
 *  @param name_size
 */
static void bnx2x_get_library_name(char **name,
				  size_t *name_size)
{
	*name = (char *)library_name;
	*name_size = sizeof(library_name);
}

/**
 *  bnx2x_get_library_version() - Used to get the version string of this
 *                                NIC libary
 *  @param version - This function will return the pointer to this NIC
 *                   library version string
 *  @param version_size - This will be set with the version size 
 */
static void bnx2x_get_library_version(char **version,
				     size_t *version_size)
{
	*version = (char *) library_version;
	*version_size = sizeof(library_version);
}

/**
 *  bnx2x_get_build_date() - Used to get the build date string of this library
 *  @param version - This function will return the pointer to this NIC
 *                   library build date string
 *  @param version_size - This will be set with the build date string size 
 */
static void bnx2x_get_build_date(char **build,
				 size_t *build_size)
{
	*build = (char *) build_date;
	*build_size = sizeof(build_date);
}

/**
 *  bnx2x_get_transport_name() - Used to get the transport name associated
 *                              with this this NIC libary
 *  @param transport_name - This function will return the pointer to this NIC
 *                          library's associated transport string
 *  @param transport_name_size - This will be set with the transport name size
 */
static void bnx2x_get_transport_name(char **transport_name,
			    	     size_t *transport_name_size)
{
	*transport_name = (char *) bnx2i_library_transport_name;
	*transport_name_size = bnx2i_library_transport_name_size;
}

/**
 *  bnx2x_get_uio_name() - Used to get the uio name associated with this this 
 *                        NIC libary
 *  @param uio_name - This function will return the pointer to this NIC
 *                    library's associated uio string
 *  @param transport_name_size - This will be set with the uio name size
 */
static void bnx2x_get_uio_name(char **uio_name,
			      size_t *uio_name_size)
{
	*uio_name = (char *) library_uio_name;
	*uio_name_size = sizeof(library_uio_name);
}

/**
 *  bnx2x_get_pci_table() - Used to get the PCI table for this NIC libary to
 *  			    determine which NIC's based off of PCI ID's are
 *  			    supported
 *  @param table - This function will return the pointer to the PCI table
 *  @param entries - This function will return the number of entries in the NIC
 *                   library's PCI table
 */
static void bnx2x_get_pci_table(struct pci_device_id **table,
			       uint32_t *entries)
{
	*table = (struct pci_device_id *) bnx2x_pci_tbl;
	*entries = (uint32_t) (sizeof(bnx2x_pci_tbl)/sizeof(bnx2x_pci_tbl[0]));
}

/**
 *  bnx2x_get_ops() - Used to get the NIC library op table
 *  @param op - The op table of this NIC library
 */
struct nic_ops * bnx2x_get_ops()
{
	return &bnx2x_op;
}

/*******************************************************************************
 * bnx2x Utility Functions
 ******************************************************************************/
/*******************************************************************************
 * Utility Functions Used to read register from the bnx2x device
 ******************************************************************************/
static void bnx2x_set_drv_version_unknown(bnx2x_t *bp)
{
	bp->version.major = BNX2X_UNKNOWN_MAJOR_VERSION;
	bp->version.minor = BNX2X_UNKNOWN_MINOR_VERSION;
	bp->version.sub_minor = BNX2X_UNKNOWN_SUB_MINOR_VERSION;
}

/**
 * bnx2x_get_drv_version() - Used to determine the driver version
 * @param bp - Device used to determine bnx2x driver version
 */
static int bnx2x_get_drv_version(bnx2x_t *bp)
{
	nic_t *nic = bp->parent;
	int fd, rc;
	struct ifreq ifr;
	struct ethtool_drvinfo drvinfo;
	char *tok, *save_ptr = NULL;

	/* Setup our control structures. */
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, nic->eth_device_name);

	/* Open control socket. */
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		LOG_ERR(PFX "%s: Cannot get socket to determine version "
			    "[0x%x %s]",
			nic->log_name, errno, strerror(errno));
		return -EIO;
	}

	drvinfo.cmd = ETHTOOL_GDRVINFO;
	ifr.ifr_data = (caddr_t)&drvinfo;
	rc = ioctl(fd, SIOCETHTOOL, &ifr);
        if (rc < 0) {
		LOG_ERR(PFX "%s: call to ethool IOCTL failed [0x%x %s]",
			nic->log_name, errno, strerror(errno));
                return rc;
        }

	tok = strtok_r(drvinfo.version, ".", &save_ptr);
	if (tok == NULL) {
		rc = -EIO;
		goto error;
	}
	bp->version.major = atoi(tok);

	tok = strtok_r(NULL, ".", &save_ptr);
	if (tok == NULL) {
		rc = -EIO;
		goto error;
	}
	bp->version.minor = atoi(tok);

	tok = strtok_r(NULL, ".", &save_ptr);
	if (tok == NULL) {
		rc = -EIO;
		goto error;
	}
	bp->version.sub_minor = atoi(tok);

	LOG_INFO(PFX "%s: bnx2x driver using version %d.%d.%d",
		nic->log_name,
		bp->version.major, bp->version.minor, bp->version.sub_minor);

	close(fd);

	return 0;

error:
	close(fd);
	bnx2x_set_drv_version_unknown(bp);

	LOG_ERR(PFX "%s: error parsing driver string: '%s'",
		nic->log_name, drvinfo.version);

	return rc;

}

static inline int bnx2x_is_ver60(bnx2x_t *bp)
{
	return (bp->version.major == 1 && bp->version.minor == 60);
}

static void bnx2x_wr32(bnx2x_t *bp, __u32 off, __u32 val)
{
	*((volatile __u32 *)(bp->reg + off)) = val;
}

static void bnx2x_doorbell(bnx2x_t *bp, __u32 off, __u32 val)
{
	*((volatile __u32 *)(bp->reg2 + off)) = val;
}

static __u32 bnx2x_rd32(bnx2x_t *bp, __u32 off)
{
	return *((volatile __u32 *)(bp->reg + off));
}

static int bnx2x_reg_sync(bnx2x_t *bp, __u32 off, __u16 length)
{
	return msync(bp->reg + off, length, MS_SYNC);
}

static void bnx2x_update_rx_prod(bnx2x_t *bp)
{
	struct ustorm_eth_rx_producers rx_prods = {0};
	int i;

	rx_prods.bd_prod = bp->rx_bd_prod;
	rx_prods.cqe_prod = bp->rx_prod;

	barrier();

	for (i = 0; i < sizeof(struct ustorm_eth_rx_producers)/4; i++)
		bnx2x_wr32(bp, bp->rx_prod_io + i * 4,
			   ((__u32 *)&rx_prods)[i]);

	barrier();

	bnx2x_reg_sync(bp, bp->rx_prod_io,
		       sizeof(struct ustorm_eth_rx_producers));
}

/**
 * bnx2x_get_chip_id() - Used to retrive the chip ID from the nic
 * @param dev - Device used to determin NIC type
 * @return Chip ID read from the MISC ID register
 */
static int bnx2x_get_chip_id(bnx2x_t *bp)
{
        int val, id;

        /* Get the chip revision id and number. */
        /* chip num:16-31, rev:12-15, metal:4-11, bond_id:0-3 */
        val = bnx2x_rd32(bp, BNX2X_MISC_REG_CHIP_NUM);
        id = ((val & 0xffff) << 16);
        val = bnx2x_rd32(bp, BNX2X_MISC_REG_CHIP_REV);
        id |= ((val & 0xf) << 12);
        val = bnx2x_rd32(bp, BNX2X_MISC_REG_CHIP_METAL);
        id |= ((val & 0xff) << 4);
        val = bnx2x_rd32(bp, BNX2X_MISC_REG_BOND_ID);
        id |= (val & 0xf); 

        return id;
}


/**
 *  bnx2x_uio_verify()
 *
 */
static int bnx2x_uio_verify(nic_t *nic)
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

	if (strncmp(raw, bnx2x_uio_sysfs_name,
		    sizeof(bnx2x_uio_sysfs_name)) != 0) {
		LOG_ERR(PFX "%s: uio names not equal: "
		            "expecting %s got %s from %s",
			nic->log_name, bnx2x_uio_sysfs_name, raw, temp_path);
		rc = -EIO;
	}

	free(raw);

	LOG_INFO(PFX "%s: Verified is a cnic_uio device", nic->log_name);

      error:
	return rc;
}

static unsigned long cnic_get_bar2(nic_t *nic)
{
        char *raw = NULL, *raw_tmp;
	uint32_t raw_size = 0;
	char temp_path[sizeof(cnic_uio_sysfs_resc_tempate) + 8];
	int rc = 0, i, new_line;
	unsigned long bar = 0;

	/*  Build the path to determine uio name */
	snprintf(temp_path, sizeof(temp_path),
		 cnic_uio_sysfs_resc_tempate, nic->uio_minor);

        rc = capture_file(&raw, &raw_size, temp_path);
        if(rc != 0)
		return 0;

	/* Skip 2 lines to get to BAR2 */
	raw_tmp = raw;
	i = 0;
	new_line = 0;
	while (i++ < raw_size && new_line < 2) {
		if (*raw_tmp == '\n')
			new_line++;
		raw_tmp++;
	}

	if (new_line == 2)
		sscanf(raw_tmp, "%lx ", &bar);

	free(raw);

	return bar;
}

/*******************************************************************************
 * bnx2x Utility Functions to get to the hardware consumer indexes
 ******************************************************************************/
static __u16 bnx2x_get_rx(bnx2x_t *bp)
{
	struct host_def_status_block *sblk = bp->status_blk.def;
	__u16 rx_comp_cons;

	msync(sblk, sizeof(*sblk), MS_SYNC);
	rx_comp_cons = sblk->u_def_status_block.index_values[
			HC_INDEX_DEF_U_ETH_ISCSI_RX_CQ_CONS];
	if ((rx_comp_cons & BNX2X_MAX_RCQ_DESC_CNT) == BNX2X_MAX_RCQ_DESC_CNT)
		rx_comp_cons++;

	return rx_comp_cons;
}

static __u16 bnx2x_get_rx_60(bnx2x_t *bp)
{
	struct host_sp_status_block *sblk = bp->status_blk.sp;
	__u16 rx_comp_cons;

	msync(sblk, sizeof(*sblk), MS_SYNC);
	rx_comp_cons = sblk->sp_sb.index_values[
			HC_SP_INDEX_ETH_ISCSI_RX_CQ_CONS];
	if ((rx_comp_cons & BNX2X_MAX_RCQ_DESC_CNT) == BNX2X_MAX_RCQ_DESC_CNT)
		rx_comp_cons++;

	return rx_comp_cons;
}

static __u16 bnx2x_get_tx(bnx2x_t *bp)
{
	struct host_def_status_block *sblk = bp->status_blk.def;
	__u16 tx_cons;

	msync(sblk, sizeof(*sblk), MS_SYNC);
	tx_cons = sblk->c_def_status_block.index_values[
			HC_INDEX_DEF_C_ETH_ISCSI_CQ_CONS];

	return tx_cons;
}


static __u16 bnx2x_get_tx_60(bnx2x_t *bp)
{
	struct host_sp_status_block *sblk = bp->status_blk.sp;
	__u16 tx_cons;

	msync(sblk, sizeof(*sblk), MS_SYNC);
	tx_cons = sblk->sp_sb.index_values[HC_SP_INDEX_ETH_ISCSI_CQ_CONS];

	return tx_cons;
}

typedef enum {
	CNIC_VLAN_STRIPPING_ENABLED = 1,
	CNIC_VLAN_STRIPPING_DISABLED = 2,
} CNIC_VLAN_STRIPPING_MODE;

/**
 *  bnx2x_strip_vlan_enabled() - This will query the device to determine whether
 *                              VLAN tag stripping is enabled or not
 *  @param dev - device to check stripping or not
 *  @ return CNIC_VLAN_STRIPPING_ENABLED stripping is enabled
 *           CNIC_VLAN_STRIPPING_DISABLED stripping is not enabled
 */
static CNIC_VLAN_STRIPPING_MODE bnx2x_strip_vlan_enabled(bnx2x_t *bp)
{
	return CNIC_VLAN_STRIPPING_DISABLED;
}

/**
 *  bnx2x_alloc() - Used to allocate a CNIC structure
 */
static bnx2x_t * bnx2x_alloc(nic_t *nic)
{
	bnx2x_t *bp = malloc(sizeof(*bp));

	if(bp == NULL)
	{
		LOG_ERR(PFX "%s: Could not allocate BNX2X space",
			nic->log_name);
		return NULL;
	}

	/*  Clear out the CNIC contents */
	memset(bp, 0, sizeof(*bp));

	bp->mem_fd = INVALID_FD;

	bp->parent = nic;
	nic->priv = (void *) bp;

	bnx2x_set_drv_version_unknown(bp);

	return bp;
}

/**
 * bnx2x_open() - This will initialize all the hardware resources underneath
 *               a struct cnic_uio device
 * @param dev - The struct cnic_uio device to attach the hardware with
 * @return 0 on success, on failure a errno will be returned
 */
static int bnx2x_open(nic_t *nic)
{
	bnx2x_t *bp; 
	struct stat uio_stat;
	int i, rc;
	__u32 val;
	unsigned long bar2;

	uint32_t bus;
	uint32_t slot;
	uint32_t func;

	/*  Sanity Check: validate the parameters */
	if(nic == NULL) {
		LOG_ERR(PFX "cnic_open(): nic == NULL");
		return -EINVAL;
	}

	bp = bnx2x_alloc(nic);
	if(bp == NULL)
		return -ENOMEM;

	bnx2x_get_drv_version(bp);

	while(nic->fd < 0) {
		/*  udev might not have created the file yet */
		sleep(1);

		nic->fd = open(nic->uio_device_name, O_RDWR | O_NONBLOCK);
		if (nic->fd != INVALID_FD) {
			LOG_ERR(PFX "%s: uio device has been brought up "
				    "via pid: %d on fd: %d",
				nic->uio_device_name, getpid(), nic->fd);

			rc = bnx2x_uio_verify(nic);
			if(rc != 0)
				continue;

			break;
		} else {
			if( lib_bnx2x_loaded == 0) {
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

				lib_bnx2x_loaded = 1;
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

	bar2 = cnic_get_bar2(nic);
	if (bar2 == 0) {
		LOG_ERR(PFX "%s: Could not read BAR2", nic->log_name);
		return -ENODEV;
	}

	bp->mem_fd = open("/dev/mem", O_RDWR | O_SYNC);
	if (bp->mem_fd < 0) {
		LOG_ERR(PFX "%s: Could not open /dev/mem", nic->log_name);
		return -ENODEV;
	}

	bp->reg2 = mmap(NULL, BNX2X_BAR2_SIZE, PROT_READ | PROT_WRITE,
			MAP_SHARED, bp->mem_fd, (off_t) bar2);

	if (bp->reg2 == MAP_FAILED) {
		LOG_INFO(PFX "%s: Couldn't mmap BAR2 registers: %s",
			 nic->log_name, strerror(errno));
		bp->reg2 = NULL;
		rc = errno;
		goto open_error;
	}

	/*  TODO: hardcoded with the cnic driver */
	bp->rx_ring_size = 15;
	bp->rx_buffer_size = 0x400;

	LOG_DEBUG(PFX "%s: using rx ring size: %d, rx buffer size: %d",
		  nic->log_name, bp->rx_ring_size, bp->rx_buffer_size);

	/*  Determine the number of UIO events that have already occured */
	rc = detemine_initial_uio_events(nic, &nic->intr_count);
	if(rc != 0) {
		LOG_ERR("Could not determine the number ofinitial UIO events");
		nic->intr_count = 0;
	}

	/*  Allocate space for rx pkt ring */
	bp->rx_pkt_ring = malloc(sizeof(void *) * bp->rx_ring_size);
	if(bp->rx_pkt_ring == NULL)
	{
		LOG_ERR(PFX "%s: Could not allocate space for rx_pkt_ring",
			nic->log_name);
		rc = errno;
		goto open_error;
	}

	bp->reg = mmap(NULL, BNX2X_BAR_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
			 nic->fd, (off_t) 0);
	if (bp->reg == MAP_FAILED) {
		LOG_INFO(PFX "%s: Couldn't mmap registers: %s",
			 nic->log_name, strerror(errno));
		bp->reg = NULL;
		rc = errno;
		goto open_error;
	}

	msync(bp->reg, BNX2X_BAR_SIZE, MS_SYNC);

	if (bnx2x_is_ver60(bp))
		bp->status_blk_size = sizeof(struct host_sp_status_block);
	else
		bp->status_blk_size = sizeof(struct host_def_status_block);

	bp->status_blk.def = mmap(NULL, bp->status_blk_size,
		 	     PROT_READ | PROT_WRITE, MAP_SHARED,
			     nic->fd, (off_t) getpagesize());
	if (bp->status_blk.def == MAP_FAILED) {
		LOG_INFO(PFX "%s: Could not mmap status block: %s",
			 nic->log_name, strerror(errno));
		bp->status_blk.def = NULL;
		rc = errno;
		goto open_error;
	}

	bp->tx_ring = mmap(NULL, 4 * getpagesize(),
			    PROT_READ | PROT_WRITE,
			    MAP_SHARED | MAP_LOCKED,
			    nic->fd, (off_t) 2 * getpagesize());
	if (bp->tx_ring == MAP_FAILED) {
		LOG_INFO(PFX "%s: Could not mmap tx ring: %s",
			 nic->log_name, strerror(errno));
		bp->tx_ring = NULL;
		rc = errno;
		goto open_error;
	}

	bp->rx_comp_ring = (union eth_rx_cqe *)
		(((__u8 *) bp->tx_ring) + 2 * getpagesize());

	bp->bufs = mmap(NULL, (bp->rx_ring_size + 1) * bp->rx_buffer_size,
			 PROT_READ | PROT_WRITE,
			 MAP_SHARED | MAP_LOCKED,
			 nic->fd, (off_t) 3 * getpagesize());
	if (bp->bufs == MAP_FAILED) {
		LOG_INFO(PFX "%s: Could not mmap buffers: %s",
			 nic->log_name, strerror(errno));
		bp->bufs = NULL;
		rc = errno;
		goto open_error;
	}

	bp->chip_id = bnx2x_get_chip_id(bp);
	LOG_DEBUG(PFX "Chip ID: %x", bp->chip_id);

	rc = get_bus_slot_func_num(nic, &bus, &slot, &func);
	if(rc != 0) {
		LOG_INFO(PFX "%s: Couldn't determine bus:slot.func",
			 nic->log_name);
		goto open_error;
	}

	bp->func = func;
	bp->port = bp->func % PORT_MAX;

	if (CHIP_IS_E2(bp)) {
		__u32 val = bnx2x_rd32(bp, MISC_REG_PORT4MODE_EN_OVWR);
		if (!(val & 1))
			val = bnx2x_rd32(bp, MISC_REG_PORT4MODE_EN);
		else
			val = (val >> 1) & 1;

		if (val)
			bp->pfid = func >> 1;
		else
			bp->pfid = func & 0x6;
	} else {
		bp->pfid = func;
	}

	if (bnx2x_is_ver60(bp))
		bp->port = bp->pfid & 1;

	if (CHIP_IS_E1(bp))
		bp->iro = e1_iro;
	else if (CHIP_IS_E1H(bp))
		bp->iro = e1h_iro;
	else if (CHIP_IS_E2(bp))
		bp->iro = e2_iro;

	if (bnx2x_is_ver60(bp)) {
		__u32 cl_qzone_id = BNX2X_CL_QZONE_ID(bp, 17);

		bp->rx_prod_io = BAR_USTRORM_INTMEM +
				(CHIP_IS_E2(bp) ?
			 	 USTORM_RX_PRODS_E2_OFFSET(cl_qzone_id) :
			 	 USTORM_RX_PRODS_E1X_OFFSET(bp->port, 17));

		bp->tx_doorbell = 17 * 0x80 + 0x40;

		bp->get_rx_cons = bnx2x_get_rx_60;
		bp->get_tx_cons = bnx2x_get_tx_60;
	} else {
		bp->rx_prod_io = BAR_USTRORM_INTMEM +
				USTORM_RX_PRODS_OFFSET(bp->port, 17);
	
		bp->tx_doorbell = 17 * getpagesize() + 0x40;

		bp->get_rx_cons = bnx2x_get_rx;
		bp->get_tx_cons = bnx2x_get_tx;
	}

	bp->tx_cons = 0;
	bp->tx_prod = 0;
	bp->tx_bd_prod = 0;
	bp->tx_pkt = bp->bufs;

	bp->rx_index = 0;
	bp->rx_cons = 0;
	bp->rx_bd_cons = 0;
	bp->rx_prod = 127;
	bp->rx_bd_prod = bp->rx_ring_size;

	for (i = 0; i < bp->rx_ring_size; i++) {
		void *ptr = bp->bufs + (bp->rx_buffer_size * (i + 1));

		bp->rx_pkt_ring[i] = ptr;
	}

	val = bnx2x_rd32(bp, MISC_REG_SHARED_MEM_ADDR);

	bp->shmem_base = val;
	val = bnx2x_rd32(bp, bp->shmem_base + SHMEM_ISCSI_MAC_UPPER(bp));
	nic->mac_addr[0] = (__u8) (val >> 8);
	nic->mac_addr[1] = (__u8) val;
	val = bnx2x_rd32(bp, bp->shmem_base + SHMEM_ISCSI_MAC_LOWER(bp));
	nic->mac_addr[2] = (__u8) (val >> 24);
	nic->mac_addr[3] = (__u8) (val >> 16);
	nic->mac_addr[4] = (__u8) (val >> 8);
	nic->mac_addr[5] = (__u8) val;

	LOG_INFO(PFX "%s:  Using mac address: %02x:%02x:%02x:%02x:%02x:%02x",
		 nic->log_name,
		 nic->mac_addr[0], nic->mac_addr[1], nic->mac_addr[2],
		 nic->mac_addr[3], nic->mac_addr[4], nic->mac_addr[5]);

	/*  Determine if Hardware VLAN tag stripping is enabled or not */
	if(CNIC_VLAN_STRIPPING_ENABLED == bnx2x_strip_vlan_enabled(bp))
	{
		nic->flags |= NIC_VLAN_STRIP_ENABLED;
	}

	/*  Prepare the multicast addresses */
	rc = enable_multicast(nic);
	if(rc != 0)
		goto open_error;

	msync(bp->reg, BNX2X_BAR_SIZE, MS_SYNC);

	LOG_INFO("%s: bnx2x initialized", nic->log_name);

	bnx2x_update_rx_prod(bp);

	return 0;

open_error:
	if (bp->tx_ring) {
		munmap(bp->tx_ring, 4 * getpagesize());
		bp->tx_ring = NULL;
	}

	if (bp->status_blk.def) {
		munmap(bp->status_blk.def, bp->status_blk_size);
		bp->status_blk.def = NULL;
	}

	if (bp->reg) {
		munmap(bp->reg, BNX2X_BAR_SIZE);
		bp->reg = NULL;
	}

	if (bp->reg2) {
		munmap(bp->reg2, BNX2X_BAR2_SIZE);
		bp->reg2 = NULL;
	}

	if (bp->rx_pkt_ring) {
		free(bp->rx_pkt_ring);
		bp->rx_pkt_ring = NULL;
	}

	if (bp->mem_fd != INVALID_FD) {
		close(bp->mem_fd);
		bp->mem_fd = INVALID_FD;
	}

	return rc;
}

/**
 *  bnx2x_uio_close_resources() - Used to free resource for the NIC/CNIC
 *  @param nic - NIC device to free resource
 *  @param graceful - whether to wait to close gracefully
 *  @return 0 on success, <0 on failure
 */
static int bnx2x_uio_close_resources(nic_t *nic, NIC_SHUTDOWN_T graceful)
{
	bnx2x_t *bp = (bnx2x_t *) nic->priv;
	int rc = 0;

	/*  Remove the multicast addresses if added */
	if((nic->flags & NIC_ADDED_MULICAST) &&
	   (graceful == ALLOW_GRACEFUL_SHUTDOWN))
		disable_multicast(nic);

	/*  Check if there is an assoicated bnx2x device */
	if(bp == NULL) {
		LOG_WARN(PFX "%s: when closing resources there is "
		             "no assoicated bnx2x",
			     nic->log_name);
		return -EIO;
	}

	/*  Clean up allocated memory */

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
		munlock(bp->tx_ring, 4 * getpagesize());
		rc = munmap(bp->tx_ring, 4 * getpagesize());
		if (rc != 0)
			LOG_WARN(PFX "%s: Couldn't unmap tx_rings",
				 nic->log_name);
		bp->tx_ring = NULL;
	}

	if (bp->status_blk.def != NULL) {
		rc = munmap(bp->status_blk.def, bp->status_blk_size);
		if (rc != 0)
			LOG_WARN(PFX "%s: Couldn't unmap status block",
				 nic->log_name);
		bp->status_blk.def = NULL;
	}

	if (bp->reg != NULL) {
		rc = munmap(bp->reg, BNX2X_BAR_SIZE);
		if (rc != 0)
			LOG_WARN(PFX "%s: Couldn't unmap regs",
				 nic->log_name);
		bp->reg = NULL;
	}

	if (bp->reg2 != NULL) {
		rc = munmap(bp->reg2, BNX2X_BAR2_SIZE);
		if (rc != 0)
			LOG_WARN(PFX "%s: Couldn't unmap regs",
				 nic->log_name);
		bp->reg2 = NULL;
	}

	if (bp->mem_fd != INVALID_FD) {
		close(bp->mem_fd);
		bp->mem_fd = INVALID_FD;
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

	bnx2x_set_drv_version_unknown(bp);

	LOG_INFO(PFX "%s: Closed all resources", nic->log_name);

	return 0;
}

/**
 *  cnic_close() - Used to close the NIC device
 *  @param nic - NIC device to close
 *  @param graceful - whether to wait to close gracefully
 *  @return 0 if successful, <0 if there is an error
 */
static int bnx2x_close(nic_t *nic, NIC_SHUTDOWN_T graceful)
{
	/*  Sanity Check: validate the parameters */
	if(nic == NULL) {
		LOG_ERR(PFX "cnic_close(): nic == NULL");
		return -EINVAL;
	}

	LOG_INFO(PFX "Closing NIC device: %s", nic->log_name);

	bnx2x_uio_close_resources(nic, graceful);

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

static void bnx2x_prepare_xmit_packet(nic_t *nic,
				     nic_interface_t *nic_iface,
				     struct packet *pkt)
{
	bnx2x_t *bp = (bnx2x_t *) nic->priv;

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
 *  bnx2x_get_tx_pkt() - This function is used to a TX packet from the NIC
 *  @param nic - The NIC device to send the packet
 */
void * bnx2x_get_tx_pkt(nic_t *nic)
{
	bnx2x_t *bp = (bnx2x_t *) nic->priv;
        return bp->tx_pkt;
}


/**
 *  bnx2x_start_xmit() - This function is used to send a packet of data
 *  @param nic - The NIC device to send the packet
 *  @param len - the length of the TX packet
 *
 */
void bnx2x_start_xmit(nic_t *nic, size_t len)
{
	bnx2x_t *bp = (bnx2x_t *) nic->priv;
	uint16_t ring_prod;
	struct eth_tx_start_bd *txbd;
	struct eth_tx_bd *txbd2;

	ring_prod = BNX2X_TX_RING_IDX(bp->tx_bd_prod);
	txbd = &bp->tx_ring[ring_prod];

	txbd->vlan = bp->tx_prod;

	bp->tx_prod++;
	bp->tx_bd_prod = BNX2X_NEXT_TX_BD(bp->tx_bd_prod);
	bp->tx_bd_prod = BNX2X_NEXT_TX_BD(bp->tx_bd_prod);

	ring_prod = BNX2X_TX_RING_IDX(bp->tx_bd_prod);
	txbd2 = (struct eth_tx_bd *) &bp->tx_ring[ring_prod];

	txbd2->nbytes = len - 0x10;
	txbd2->total_pkt_bytes = len;

	bp->tx_bd_prod = BNX2X_NEXT_TX_BD(bp->tx_bd_prod);

	barrier();
	bnx2x_doorbell(bp, bp->tx_doorbell, 0x02 | (bp->tx_bd_prod << 16));

	LOG_DEBUG(PFX "%s: sent %d bytes using bp->tx_prod: %d",
		      nic->log_name, len, bp->tx_prod);
}

/**
 *  bnx2x_write() - Used to write the data to the hardware
 *  @param nic - NIC hardware to read from
 *  @param pkt - The packet which will hold the data to be sent on the wire
 *  @return 0 if successful, <0 if failed
 */
int bnx2x_write(nic_t *nic, nic_interface_t *nic_iface,
		packet_t *pkt)
{
	bnx2x_t *bp = (bnx2x_t *) nic->priv;
	struct uip_stack *uip = &nic_iface->ustack;

	/* Sanity Check: validate the parameters */
	if(nic == NULL || nic_iface == NULL || pkt == NULL) {
		LOG_ERR(PFX "%s: cnic_write() nic == 0x%p || "
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

	bnx2x_prepare_xmit_packet(nic, nic_iface,
				 pkt);
	bnx2x_start_xmit(nic, pkt->buf_size);

	/*  bump the cnic dev send statistics */
	nic->stats.tx.packets++;
	nic->stats.tx.bytes += uip->uip_len;

	LOG_DEBUG(PFX "%s: transmitted %d bytes "
		      "dev->tx_cons: %d, dev->tx_prod: %d, dev->tx_bd_prod:%d",
		  nic->log_name, pkt->buf_size,
		  bp->tx_cons, bp->tx_prod, bp->tx_bd_prod);

	return 0;
}

/**
 *  bnx2x_read() - Used to read the data from the hardware
 *  @param nic - NIC hardware to read from
 *  @param pkt - The packet which will hold the data
 *  @return 0 if successful, <0 if failed
 */
static int bnx2x_read(nic_t *nic, packet_t *pkt)
{
	bnx2x_t *bp = (bnx2x_t *) nic->priv;
	int rc = 0;
	uint16_t hw_cons, sw_cons, bd_cons, bd_prod;

	/* Sanity Check: validate the parameters */
	if(nic == NULL || pkt == NULL) {
		LOG_ERR(PFX "%s: bnx2x_read() nic == 0x%p || "
			    " pkt == 0x%x", nic, pkt);
		return -EINVAL;
	}

	hw_cons = bp->get_rx_cons(bp);
	sw_cons = bp->rx_cons;
	bd_cons = bp->rx_bd_cons;
	bd_prod = bp->rx_bd_prod;

	if (sw_cons != hw_cons) {
		uint16_t comp_ring_index = sw_cons & BNX2X_MAX_RCQ_DESC_CNT;
		uint8_t ring_index;
		union eth_rx_cqe *cqe;
		__u8 cqe_fp_flags;
		void *rx_pkt;
		int len, pad = 0;;

		cqe = &bp->rx_comp_ring[comp_ring_index];
		cqe_fp_flags = cqe->fast_path_cqe.type_error_flags;

		LOG_DEBUG(PFX "%s: clearing rx interrupt: %d %d",
			  nic->log_name,
			  sw_cons, hw_cons);

		msync(cqe, sizeof(*cqe), MS_SYNC); 
		if (!(cqe_fp_flags & ETH_FAST_PATH_RX_CQE_TYPE)) {
			ring_index = bd_cons % 15;
			len = cqe->fast_path_cqe.pkt_len;
			if (bnx2x_is_ver60(bp))
				pad = cqe->fast_path_cqe.placement_offset;
			rx_pkt = bp->rx_pkt_ring[ring_index] + pad;

			/*  Doto query MTU size of physical device */
			/*  Ensure len is valid */
			if(len > pkt->max_buf_size)
				LOG_DEBUG(PFX "%s: bad BD length: %d",
					  nic->log_name, len);

			if (len > 0) {
				msync(rx_pkt, len, MS_SYNC); 
				/*  Copy the data */
				memcpy(pkt->buf, rx_pkt, len);
				pkt->buf_size = len;

				/*  Properly set the packet flags */
				/*  check if there is VLAN tagging */
				if (cqe->fast_path_cqe.vlan_tag != 0) {
					pkt->vlan_tag = cqe->fast_path_cqe.vlan_tag;
					pkt->flags |= VLAN_TAGGED;
				} else {
 	                               pkt->vlan_tag = 0;
				}

				rc = 1;

				LOG_DEBUG(PFX "%s: processing packet length: %d",
					  nic->log_name, len);

				/*  bump the cnic dev recv statistics */
				nic->stats.rx.packets++;
				nic->stats.rx.bytes += pkt->buf_size;
			}

			bd_cons = BNX2X_NEXT_RX_IDX(bd_cons);
			bd_prod = BNX2X_NEXT_RX_IDX(bd_prod);

		}
		sw_cons = BNX2X_NEXT_RCQ_IDX(bd_cons);
		bp->rx_prod = BNX2X_NEXT_RCQ_IDX(bp->rx_prod);
	}
	bp->rx_cons = sw_cons;
	bp->rx_bd_cons = bd_cons;
	bp->rx_bd_prod = bd_prod;

	bnx2x_update_rx_prod(bp);

	return rc;
}
/*******************************************************************************
 * Clearing TX interrupts
 ******************************************************************************/
/**
 *  bnx2x_clear_tx_intr() - This routine is called when a TX interrupt occurs
 *  @param nic - the nic the interrupt occured on
 *  @return  0 on success
 */
static int bnx2x_clear_tx_intr(nic_t *nic)
{
	bnx2x_t *bp = (bnx2x_t *) nic->priv;
	uint16_t hw_cons = bp->get_tx_cons(bp);

	/* Sanity check: ensure the parameters passed in are valid */
	if(unlikely(nic == NULL)) {
		LOG_ERR(PFX "bnx2x_read() nic == NULL");
		return -EINVAL;
	}

	if(bp->tx_cons == hw_cons)
		return 0;

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
			bnx2x_prepare_xmit_packet(nic,
						  pkt->nic_iface,
						  pkt);

			bnx2x_start_xmit(nic, pkt->buf_size);

			LOG_DEBUG(PFX "%s: transmitted queued packet %d bytes "
				      "dev->tx_cons: %d, dev->tx_prod: %d, dev->tx_bd_prod:%d",
					  nic->log_name, pkt->buf_size,
					  bp->tx_cons, bp->tx_prod, bp->tx_bd_prod);

			return 0;
		}
	}

	pthread_mutex_unlock(&nic->xmit_mutex);

	return 0;
}

/*******************************************************************************
 * bnx2x NIC op's table
 ******************************************************************************/
struct nic_ops bnx2x_op = {
	.description	= "bnx2x",
	.open		= bnx2x_open,
	.close		= bnx2x_close,
	.write		= bnx2x_write,
	.get_tx_pkt	= bnx2x_get_tx_pkt,
	.start_xmit	= bnx2x_start_xmit,
	.read		= bnx2x_read,
	.clear_tx_intr	= bnx2x_clear_tx_intr,
	.handle_iscsi_path_req = cnic_handle_iscsi_path_req,

	.lib_ops = {
		.get_library_name	= bnx2x_get_library_name,
        	.get_pci_table		= bnx2x_get_pci_table,
	        .get_library_version	= bnx2x_get_library_version,
		.get_build_date		= bnx2x_get_build_date,
	        .get_transport_name	= bnx2x_get_transport_name,
	        .get_uio_name		= bnx2x_get_uio_name,
	},
};
