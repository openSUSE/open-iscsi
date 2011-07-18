#!/bin/bash
#%stage: device
#%depends: network
#%programs: /sbin/iscsid /sbin/iscsiadm
#%modules: iscsi_tcp crc32c scsi_transport_iscsi
#%if: "$root_iscsi" -o "$TargetAddress"
#
##### iSCSI initialization
##
## This script initializes iSCSI (SCSI over IP).
## To be able to use this script, the network has to be setup. 
## When everything worked as expected, the iSCSI devices will show
## up as real SCSI devices.
##
## Command line parameters
## -----------------------
##
## TargetAddress		the address of the iscsi server
## TargetPort		the port of the iscsi server (defaults to 3260)
## TargetName		the iscsi target name (connect to all if empty)
## iSCSI_ignoreNodes	if set all stored nodes will be ignored (only 
##			iBFT and commandline nodes get parsed)
## 

### iSCSI_warning_InitiatorName <new InitiatorName> <Origin>
# shows a warning about iSCSI InitiatorName differences
# Origin should be something like "commandline" or "iBFT"
iSCSI_warning_InitiatorName() {
	echo "iSCSI:       WARNING"
	echo "iSCSI: ======================="
	echo "iSCSI: "
	echo "iSCSI: InitiatorName given on $2 and internally stored Initiator are different."
	echo "iSCSI: New:    $1"
	echo "iSCSI: Stored: $InitiatorName"
	echo "iSCSI: "
	echo "iSCSI: using the $2 version"
}

if [ "$iSCSI_ignoreNodes" ]; then
	# make us forget we have to initialize stored nodes
	echo "iSCSI: removing node information..."
	iscsi_sessions=
	rm -rf /etc/iscsi/nodes
	mkdir /etc/iscsi/nodes
fi

# get the command line InitiatorName
tmp_InitiatorName="$(get_param InitiatorName)"
# reads the InitiatorName variable
. /etc/iscsi/initiatorname.iscsi

load_modules

# Check of iBFT settings
if [ -d /sys/firmware/ibft/initiator ] ; then
    # only use the iBFT InitiatorName if the commandline argument is not "default"
    read iSCSI_INITIATOR_NAME < /sys/firmware/ibft/initiator/initiator-name
    if [ "$iSCSI_INITIATOR_NAME" -a "$tmp_InitiatorName" != "default" ] ; then
    	iSCSI_warning_InitiatorName "$iSCSI_INITIATOR_NAME" "iBFT"
        InitiatorName=$iSCSI_INITIATOR_NAME
    fi
fi

if [ "$tmp_InitiatorName" != "$InitiatorName" -a "$tmp_InitiatorName" != "default" -a "$tmp_InitiatorName" ]; then
    	iSCSI_warning_InitiatorName "$tmp_InitiatorName" "cmdline"
	InitiatorName=$tmp_InitiatorName
fi

# store the detected InitiatorName permanently
echo "InitiatorName=$InitiatorName" > /etc/iscsi/initiatorname.iscsi

unset iSCSI_warning_InitiatorName

echo "Starting iSCSI daemon"
/sbin/iscsid -n

if [ -d /sys/firmware/ibft/initiator ] ; then
    # log into iBFT nodes
    /sbin/iscsiadm -m fw -l
fi

# Check for command line sessions
if [ -n "$TargetAddress" -a -n "$TargetName" ] ; then

    # try to detect and connect to the iscsi server
    echo -n "Starting discovery on ${TargetAddress},${TargetName}: "
    if /sbin/iscsiadm -m discovery -t st -p ${TargetAddress}:${TargetPort} 2> /dev/null ; then
	echo "ok."
    else
	echo "failed."
    fi
    # Mark this node as 'onboot'
    /sbin/iscsiadm -m node -p $TargetAddress:$TargetPort -T $TargetName -o update -n node.conn[0].startup -v onboot
fi

# Activate all 'onboot' sessions
/sbin/iscsiadm -m node -L onboot
