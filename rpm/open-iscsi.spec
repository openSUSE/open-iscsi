#
# spec file for package open-iscsi
#
# Copyright (c) 2016 SUSE LINUX GmbH, Nuernberg, Germany.
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


Name:           open-iscsi
BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  bison
BuildRequires:  db-devel < 5
BuildRequires:  flex
BuildRequires:  libtool
BuildRequires:  make
BuildRequires:  openssl-devel
BuildRequires:  open-isns-devel
%if 0%{?suse_version} >= 1230
BuildRequires:  systemd
%else
PreReq:         %fillup_prereq %insserv_prereq
%endif
%if 0%{?suse_version} >= 1320
BuildRequires:  suse-module-tools
%endif
BuildRequires:  libmount-devel
Url:            http://www.open-iscsi.org
Version:        2.0.874
Release:        0
%{?systemd_requires}
%define iscsi_release 874
Summary:        Linux* Open-iSCSI Software Initiator
License:        GPL-2.0+
Group:          Productivity/Networking/Other
Source:         %{name}-2.0-%{iscsi_release}.tar.bz2
Patch1:         %{name}-SUSE-latest.diff.bz2
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

%package -n iscsiuio
Summary:        Linux Broadcom NetXtremem II iscsi server
Group:          Productivity/Networking/Other
Version:        0.7.8.2
Release:        0
Requires:       logrotate

%description -n iscsiuio
This tool is to be used in conjunction with the Broadcom NetXtreme II Linux
driver (Kernel module name: 'bnx2' and 'bnx2x'), Broadcom CNIC driver,
and the Broadcom iSCSI driver (Kernel module name: 'bnx2i').
This user space tool is used in conjunction with the following
Broadcom Network Controllers:
  bnx2:  BCM5706, BCM5708, BCM5709 devices
  bnx2x: BCM57710, BCM57711, BCM57711E, BCM57712, BCM57712E,
         BCM57800, BCM57810, BCM57840 devices

This utility will provide the ARP and DHCP functionality for the iSCSI offload.
The communication to the driver is done via Userspace I/O (Kernel module name
'uio').

%prep
%setup -n %{name}-2.0-%{iscsi_release}
%patch1 -p1

%build
%{__make} OPTFLAGS="${RPM_OPT_FLAGS} -fno-strict-aliasing -DOFFLOAD_BOOT_SUPPORTED -DLOCK_DIR=\\\"/etc/iscsi\\\"" LDFLAGS="" user
cd iscsiuio
touch NEWS
touch AUTHORS
autoreconf --install
%configure --sbindir=/sbin
make CFLAGS="${RPM_OPT_FLAGS}"

%install
make DESTDIR=${RPM_BUILD_ROOT} install_user
%if 0%{?suse_version} < 1320
make DESTDIR=${RPM_BUILD_ROOT} install_mkinitrd_suse
%endif
# install service files
%if 0%{?suse_version} >= 1230
make DESTDIR=${RPM_BUILD_ROOT} install_service_suse
# create rc symlinks
[ -d ${RPM_BUILD_ROOT}/usr/sbin ] || mkdir -p ${RPM_BUILD_ROOT}/usr/sbin
ln -s %{_sbindir}/service %{buildroot}%{_sbindir}/rciscsi
ln -s %{_sbindir}/service %{buildroot}%{_sbindir}/rciscsid
ln -s %{_sbindir}/service %{buildroot}%{_sbindir}/rciscsiuio
%else
make DESTDIR=${RPM_BUILD_ROOT} install_initd_suse
# rename open-iscsi service to iscsid for openSUSE
mv ${RPM_BUILD_ROOT}/etc/init.d/boot.open-iscsi \
	${RPM_BUILD_ROOT}/etc/init.d/boot.iscsid-early
mv ${RPM_BUILD_ROOT}/etc/init.d/open-iscsi \
	${RPM_BUILD_ROOT}/etc/init.d/iscsid
# create rc shortcut
[ -d ${RPM_BUILD_ROOT}/usr/sbin ] || mkdir -p ${RPM_BUILD_ROOT}/usr/sbin
ln -sf ../../etc/init.d/iscsid ${RPM_BUILD_ROOT}/usr/sbin/rciscsid
%endif
(cd ${RPM_BUILD_ROOT}/etc; ln -sf iscsi/iscsid.conf iscsid.conf)
touch ${RPM_BUILD_ROOT}/etc/iscsi/initiatorname.iscsi
install -m 0755 usr/iscsistart %{buildroot}/sbin
make DESTDIR=${RPM_BUILD_ROOT} -C iscsiuio install

%post
%if 0%{?suse_version} < 1320
[ -x /sbin/mkinitrd_setup ] && mkinitrd_setup
%else
%{?regenerate_initrd_post}
%endif
if [ ! -f /etc/iscsi/initiatorname.iscsi ] ; then
    /sbin/iscsi-gen-initiatorname
fi
%if 0%{?suse_version} >= 1230
%{service_add_post iscsid.socket iscsid.service iscsi.service}
%else
%{fillup_and_insserv -Y boot.iscsid-early}
%endif

%posttrans
%if 0%{?suse_version} >= 1320
%{?regenerate_initrd_posttrans}
%endif

%postun
%if 0%{?suse_version} < 1320
[ -x /sbin/mkinitrd_setup ] && mkinitrd_setup
%endif
%if 0%{?suse_version} >= 1230
%{service_del_postun iscsid.socket iscsid.service iscsi.service}
%else
%{insserv_cleanup}
%endif

%pre
%if 0%{?suse_version} >= 1230
%{service_add_pre iscsid.socket iscsid.service iscsi.service}
%endif

%preun
%if 0%{?suse_version} >= 1230
%{service_del_preun iscsid.socket iscsid.service iscsi.service}
%else
%{stop_on_removal iscsid}
%endif

%post -n iscsiuio
%if 0%{?suse_version} >= 1230
%{service_add_post iscsiuio.socket iscsiuio.service}
%endif

%postun -n iscsiuio
%if 0%{?suse_version} >= 1230
%{service_del_postun iscsiuio.socket iscsiuio.service}
%endif

%pre -n iscsiuio
%if 0%{?suse_version} >= 1230
%{service_add_pre iscsiuio.socket iscsiuio.service}
%endif

%preun -n iscsiuio
%if 0%{?suse_version} >= 1230
%{service_del_preun iscsiuio.socket iscsiuio.service}
%else
%{stop_on_removal iscsiuio}
%endif

%files
%defattr(-,root,root)
%dir /etc/iscsi
%attr(0600,root,root) %config(noreplace) /etc/iscsi/iscsid.conf
%ghost /etc/iscsi/initiatorname.iscsi
%dir /etc/iscsi/ifaces
%config /etc/iscsi/ifaces/iface.example
/etc/iscsid.conf
%if 0%{?suse_version} >= 1230
%{_unitdir}/iscsid.service
%{_unitdir}/iscsid.socket
%{_unitdir}/iscsi.service
%{_libexecdir}/systemd/system-generators/ibft-rule-generator
%{_sbindir}/rciscsi
%else
%config /etc/init.d/iscsid
%config /etc/init.d/boot.iscsid-early
%endif
%{_sbindir}/rciscsid
/sbin/iscsid
/sbin/iscsiadm
/sbin/iscsi-iname
/sbin/iscsistart
/sbin/iscsi-gen-initiatorname
/sbin/iscsi_offload
/sbin/iscsi_discovery
%if 0%{?suse_version} < 1320
%dir /lib/mkinitrd
%dir /lib/mkinitrd/scripts
/lib/mkinitrd/scripts/setup-iscsi.sh
/lib/mkinitrd/scripts/boot-iscsi.sh
/lib/mkinitrd/scripts/boot-killiscsi.sh
%endif
%doc COPYING README
%doc %{_mandir}/man8/iscsiadm.8.gz
%doc %{_mandir}/man8/iscsid.8.gz
%doc %{_mandir}/man8/iscsi_discovery.8.gz
%doc %{_mandir}/man8/iscsistart.8.gz
%doc %{_mandir}/man8/iscsi-iname.8.gz
%doc %{_mandir}/man8/iscsi_fw_login.8.gz
%dir %{_sysconfdir}/udev
%dir %{_sysconfdir}/udev/rules.d
%config %{_sysconfdir}/udev/rules.d/50-iscsi-firmware-login.rules

%files -n iscsiuio
%defattr(-,root,root)
/sbin/iscsiuio
/sbin/brcm_iscsiuio
%doc %{_mandir}/man8/iscsiuio.8.gz
%config /etc/logrotate.d/iscsiuiolog
%if 0%{?suse_version} >= 1230
%{_unitdir}/iscsiuio.service
%{_unitdir}/iscsiuio.socket
%{_sbindir}/rciscsiuio
%endif

%changelog
