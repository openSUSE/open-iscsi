#!/bin/bash
#
#%stage: device
#
function verify_path()
{
    local devname="$1" path="$2"

    if [[ ! -d "${path}" ]] ; then
	if [[ "${path}" =~ .+\ .+ ]] ; then
	    error 2 "iSCSI device ${devname} is connected to more than one iSCSI target!"
	    # not reached
	else
	    # does not seem to be an iSCSI attached device
	    return 1
	    
	fi
    fi
    return 0
}

function check_iscsi()
{
    local devname="$1" retval=1
    local sysfs_path=$(/sbin/udevadm info -q path -n "${devname}" 2>/dev/null)
    local ip target startup

    # do we have a valid device?
    [[ -z "${sysfs_path}" ]] && sysfs_path="/block${devname##/dev}"
    sysfs_path="/sys${sysfs_path}"
    [[ ! -d "${sysfs_path}" ]] && return 1              # no, return false

    # Do we have a valid device link?
    [[ ! -d "${sysfs_path}/device" ]] && sysfs_path="${sysfs_path%/*}"
    [[ ! -d "${sysfs_path}/device" ]] && return 1	# no, return false

    # Is device an iSCSI device?
    sysfs_path="${sysfs_path}/device/../.."

    ip="$(echo ${sysfs_path}/connection*)"
    verify_path "${devname}" "${ip}" || return 1	# no, return false

    ip="${ip}/iscsi_connection/${ip##*/}/persistent_"
    [[ ! -r "${ip}address" || ! -r "${ip}port" ]] &&
	error 2 "iSCSI device ${devname} connected to iSCSI target without any persistent_{address,port}!"
    ip="$(cat "${ip}address"):$(cat "${ip}port")"

    target=$(echo ${sysfs_path}/iscsi_session/*)
    verify_path "${devname}" "${target}" || return 1	# no, return false

    target="${target}/targetname"
    [[ ! -r "${target}" ]] &&
	error 2 "iSCSI device ${devname} connected to iSCSI target without any targetname!"
    target="$(cat ${target})"

    # figure out whether it has been correctly configured
    [[ ! -x "${_iadm_}" ]] &&
	error 2 "iSCSI device ${devname} connected to iSCSI target, but no ${_iadm_} command available!"

    startup="$(
	${_iadm_} -m node -p "${ip}" -T "${target}" 2>/dev/null | grep 'node.conn\[0\].startup'
    )"
    startup="${startup##* }"
    startup="${startup%% *}"
    if [[ "${startup}" != "onboot" ]] ; then
	[[ -z "${startup}" ]] && return 1	# Oops, no parameter - not an iSCSI, return false

	## Either:
	#echo >&2 "WARNING: iSCSI device ${devname} is using 'node.conn[0].startup = ${startup}',"
	#echo >&2 "WARNING: setting it to 'onboot' instead."
	#${_iadm_} -m node -p "${ip}" -T "${target}" -o update -n 'node.conn[0].startup' -v onboot

	## or:
	echo >&2 "WARNING: iSCSI device ${devname} is using 'node.conn[0].startup = ${startup}'!"
	echo >&2 "WARNING: System not bootable with this setting, need to be set to 'onboot' instead, using:"
	echo >&2 "
	${_iadm_} -m node -p '${ip}' -T '${target}' -o update -n 'node.conn[0].startup' -v onboot"
    fi

    # attached to an iSCSI device
    return 0
}



_iadm_="/sbin/iscsiadm"

# Are system device(s) attached to iSCSI devices?
# In case they are, ensure:
# (1) the iSCSI gets included in "initrd", and
# (2) the iSCSI sessions have been configured with
#     "node.conn[0].startup = onboot".
for bd in $blockdev ; do
    update_blockdev $bd
    check_iscsi $bd && root_iscsi=1
done

# Are any of the defined file partitions to be mounted at system boot
# attached to iSCSI devices? In case they are, ensure:
# (1) the iSCSI gets included in "initrd", and
# (2) the iSCSI sessions have been configured with
#     "node.conn[0].startup = onboot".
for bd in $(awk '/^[[:space:]]*(\/dev\/|(LABEL|UUID)=)/ { print $1 }' /etc/fstab)
do
    bd="${bd/LABEL=//dev/disk/by-label/}"
    bd="${bd/UUID=//dev/disk/by-uuid/}"
    update_blockdev $bd
    check_iscsi $bd && root_iscsi=1
done

# Include the iSCSI stack, when at least one active iSCSI session has
# been configured with "node.conn[0].startup = onboot", even if it was
# not used for a system device or mounted partition.
if [[ -x "${_iadm_}" ]] ; then
    for node in $(${_iadm_} -m node 2>/dev/null | sed -e 's/ /,/g') ; do
	[[ "$(
		${_iadm_} -m node -T "${node##*,}" -p "${node%%,*}" 2>/dev/null |
		grep "node.conn\[0\].startup"
	    )" =~ [[:space:]]*=[[:space:]]*onboot ]] && root_iscsi=1
    done
fi

unset _iadm_

save_var root_iscsi

if [ "${root_iscsi}" ]; then
    # copy the iscsi configuration
    cp -rp /etc/iscsi etc/

    if [ -z "$interface" ] ; then
	interface="default"				# needed?
    fi

    # In case target port was not defined via command line, assign default port
    save_var TargetPort 3260
fi


