#
# spec file for package open-iscsi
#
# Copyright (c) 2011 SUSE LINUX Products GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#

# norootforbuild


Name:           open-iscsi
BuildRequires:  autoconf bison db-devel flex
Url:            http://www.open-iscsi.org
License:        GPL v2 or later
Group:          Productivity/Networking/Other
PreReq:         %fillup_prereq %insserv_prereq
AutoReqProv:    on
Version:        2.0.871
Release:        0.<RELEASE26>
Provides:       linux-iscsi
Obsoletes:      linux-iscsi
%define iscsi_release 865
Summary:        Linux* Open-iSCSI Software Initiator
Source:         %{name}-2.0-871.tar.bz2
Source11:       iscsi-gen-initiatorname.sh
Patch1:         %{name}-git-update
Patch2:         %{name}-update-init-script
Patch3:         %{name}-add-mkinitrd-scriptlets
Patch4:         %{name}-install-mkinitrd-scriptlets
Patch5:         %{name}-add-ibft-scriptlet
Patch6:         %{name}-allow-onboot-for-loginall
Patch7:         %{name}-option-no-pid-file
Patch8:         %{name}-set-LOCK_DIR-during-compilation
Patch9:         %{name}-fixup-onboot-for-loginall
Patch10:        %{name}-remove-dump-char
Patch11:        %{name}-allow-empty-usernames-for-chap
Patch12:        %{name}-overflow-search-ibft
Patch13:        %{name}-synchronize-startup-settings
Patch14:        %{name}-do-not-use-temp-file-in-iscsi_discovery
Patch15:        %{name}-do-not-build-modules-without-kernel-source
Patch16:        %{name}-fixup-init-scripts
Patch17:        %{name}-ibft-upstream-kernel-compat
Patch18:        %{name}-dont-modify-network-with-no-ibft
Patch19:        %{name}-use-correct-ibft-origin-value
Patch20:        %{name}-add-brcm-uip
Patch21:        %{name}-brcm-uip-build-fixes
Patch22:        %{name}-start-brcm-uip-conditionally
Patch23:        %{name}-missing-include
Patch24:        %{name}-dont-close-sessions-if-umount-fails
Patch25:        %{name}-update-brcm-uip-to-0.5.7
Patch26:        %{name}-load-transport-modules-if-configured
Patch27:        %{name}-do-not-umount-rootfs
Patch28:        %{name}-set-nettype-correctly-when-dhcp-failed
Patch29:        %{name}-correct-shutdown-messages
Patch30:        %{name}-remove-ibft-mkinitrd-scripts
Patch31:        %{name}-set-correct-interface-variable-for-mkinitrd
Patch32:        %{name}-no-SIGTERM-to-pid-0
Patch33:        %{name}-start-multipath-before-iscsi
Patch34:        %{name}-init-script-returns-failure-on-stop
Patch35:        %{name}-extract-correct-session-information-from-firmware
Patch36:        %{name}-start-multipathd-before-open-iscsi
Patch37:        %{name}-handle-offload-sessions
Patch38:        %{name}-teardown-block-devices-on-stop
Patch39:        %{name}-dont-show-failed-for-root-on-iscsi-fix
Patch40:        %{name}-fix-iSCSI-actor-list-corruption
BuildRoot:      %{_tmppath}/%{name}-%{version}-build

%description
Open-iSCSI is a high-performance, transport independent, multi-platform
implementation of RFC3720 iSCSI.

Open-iSCSI is partitioned into user and kernel parts.

The kernel portion of Open-iSCSI is a from-scratch code licensed under
GPL. The kernel part implements iSCSI data path (that is, iSCSI Read
and iSCSI Write), and consists of two loadable modules: iscsi_if.ko and
iscsi_tcp.ko.

User space contains the entire control plane: configuration manager,
iSCSI Discovery, Login and Logout processing, connection-level error
processing, Nop-In and Nop-Out handling, and (in the future:) Text
processing, iSNS, SLP, Radius, etc.

The user space Open-iSCSI consists of a daemon process called iscsid,
and a management utility iscsiadm.



Authors:
--------
    open-iscsi@googlegroups.com

%prep
%setup -n %{name}-2.0-871
%patch1 -p1
%patch2 -p1
%patch3 -p1
%patch4 -p1
%patch5 -p1
%patch6 -p1
%patch7 -p1
%patch8 -p1
%patch9 -p1
%patch10 -p1
%patch11 -p1
%patch12 -p1
%patch13 -p1
%patch14 -p1
%patch15 -p1
%patch16 -p1
%patch17 -p1
%patch18 -p1
%patch19 -p1
%patch20 -p1
%patch21 -p1
%patch22 -p1
%patch23 -p1
%patch24 -p1
%patch25 -p1
%patch26 -p1
%patch27 -p1
%patch28 -p1
%patch29 -p1
%patch30 -p1
%patch31 -p1
%patch32 -p1
%patch33 -p1
%patch34 -p1
%patch35 -p1
%patch36 -p1
%patch37 -p1
%patch38 -p1
%patch39 -p1
%patch40 -p1

%build
%{__make} OPTFLAGS="${RPM_OPT_FLAGS} -DLOCK_DIR=\\\"/etc/iscsi\\\"" user
cd brcm_iscsi_uio
touch NEWS
touch AUTHORS
autoreconf --install
%configure --sbindir=/sbin
make CFLAGS="${RPM_OPT_FLAGS}"

%install
make DESTDIR=${RPM_BUILD_ROOT} install_user
make DESTDIR=${RPM_BUILD_ROOT} install_initd_suse
(cd brcm_iscsi_uio; make DESTDIR=${RPM_BUILD_ROOT} install)
install -D -m 755 %{S:11} ${RPM_BUILD_ROOT}/sbin/iscsi-gen-initiatorname
(cd ${RPM_BUILD_ROOT}/sbin; ln -sf /etc/init.d/open-iscsi rcopen-iscsi)
(cd ${RPM_BUILD_ROOT}/etc; ln -sf iscsi/iscsid.conf iscsid.conf)

%clean
[ "${RPM_BUILD_ROOT}" != "/" -a -d ${RPM_BUILD_ROOT} ] && rm -rf ${RPM_BUILD_ROOT}

%post
[ -x /sbin/mkinitrd_setup ] && mkinitrd_setup
%{fillup_and_insserv -Y boot.open-iscsi}
if [ ! -f /etc/iscsi/initiatorname.iscsi ] ; then
    /sbin/iscsi-gen-initiatorname
fi

%postun
[ -x /sbin/mkinitrd_setup ] && mkinitrd_setup
%{insserv_cleanup}

%preun
%{stop_on_removal open-iscsi}

%files
%defattr(-,root,root)
%dir /etc/iscsi
%attr(0600,root,root) %config(noreplace) /etc/iscsi/iscsid.conf
%dir /etc/iscsi/ifaces
%config /etc/iscsi/ifaces/iface.example
/etc/iscsid.conf
%config /etc/init.d/open-iscsi
%config /etc/init.d/boot.open-iscsi
/sbin/*
%dir /lib/mkinitrd
%dir /lib/mkinitrd/scripts
/lib/mkinitrd/scripts/setup-iscsi.sh
/lib/mkinitrd/scripts/boot-iscsi.sh
/lib/mkinitrd/scripts/boot-killiscsi.sh
%doc COPYING README
%doc %{_mandir}/man8/*

%changelog
