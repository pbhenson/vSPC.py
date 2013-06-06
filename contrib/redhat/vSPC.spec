%define name vSPC
%define version 0.2
%define unmangled_version 0.2
%define release 2.%{dist}

Summary: vSPC is a virtual Serial Port Concentrator for VMware virtual serial ports,available in ESXi 4.1+.
Name: %{name}
Version: %{version}
Release: %{release}
Source0: %{name}-%{unmangled_version}.tar.gz
License: BSD
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: noarch
Vendor: Zach Loafman <zmerlynn@sf.net>
Url: https://github.com/isnotajoke/vSPC.py
Requires: python26
BuildRequires: python26
BuildRequires: python26-distribute

%description
vSPC is a virtual Serial Port Concentrator for VMware virtual serial ports, available in ESXi
4.1+.

%prep
%setup -n %{name}-%{unmangled_version} -n %{name}-%{unmangled_version}

%build
python26 setup.py build

%install
python26 setup.py install --single-version-externally-managed -O1 --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES

%clean
rm -rf $RPM_BUILD_ROOT

%post
/sbin/chkconfig --add vSPCServer

%preun
if [ "$1" = 0 ]; then
	/sbin/chkconfig vSPCServer off
	/sbin/service vSPCServer stop
	/sbin/chkconfig --del vSPCServer
fi

%postun
if [ "$1" -ge 1 ]; then
	/sbin/service vSPCServer restart
fi

%files -f INSTALLED_FILES
%defattr(-,root,root)

