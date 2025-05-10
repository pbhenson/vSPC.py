%define name vspc
%define version 0.8.2
%define release 1%{dist}

Summary: vSPC is a virtual Serial Port Concentrator for VMware ESXi virtual serial ports
Name: %{name}
Version: %{version}
Release: %{release}
Source0: %{name}-%{version}.tar.gz
License: BSD
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: noarch
Url: https://github.com/pbhenson/vSPC.py
Requires: python3
BuildRequires: python3

%description
vSPC is a virtual Serial Port Concentrator for VMware ESXi virtual serial ports

%prep
%setup -n vSPC.py-%{version}

%build
python3 setup.py build

%install
python3 setup.py install --single-version-externally-managed -O1 --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES

install -d -m 755 $RPM_BUILD_ROOT%{_unitdir}

( cat << EOF
[Unit]
Description=virtual Serial Port Concentrator for VMware ESXi

[Service]
EnvironmentFile=-/etc/default/vspc
ExecStart=/usr/bin/vSPCServer --no-fork --stdout \$VSPC_OPTIONS
ExecReload=/bin/kill -HUP \$MAINPID

[Install]
WantedBy=multi-user.target
EOF
) > $RPM_BUILD_ROOT%{_unitdir}/vspc.service

install -d -m 755 $RPM_BUILD_ROOT/etc/default
( cat << EOF
VSPC_OPTIONS="--no-vm-port --ssl --cert /etc/ssl/certs/vspc.pem --backend Logging -l /var/log/consoles -m 0644"
EOF
) > $RPM_BUILD_ROOT/etc/default/vspc

%clean
rm -rf $RPM_BUILD_ROOT

%files -f INSTALLED_FILES
%defattr(-,root,root)
%{_unitdir}/vspc.service
/etc/default/vspc
