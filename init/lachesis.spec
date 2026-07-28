Name:           lachesis
Version:        %{version}
Release:        1%{?dist}.%{build_number}
Summary:        Per-tenant eBPF network telemetry agent for CubeCOS

License:        Apache License 2.0
URL:            https://github.com/bigstack-oss/lachesis
Source0:        https://github.com/bigstack-oss/lachesis/tree/%{build_number}

BuildRequires: systemd golang clang llvm libbpf-devel kernel-headers

%description
Per-tenant network telemetry for OpenStack compute nodes. A TC classifier
attached to each VM tap counts bytes and packets per flow and classifies the
destination zone; the userspace agent resolves Neutron metadata and exports
billing-grade per-tenant counters on /metrics.

%prep
# Clear all entries incl. hidden: bare `rm -rf ./*` skips dotfiles, so a hidden
# entry flattened from ./source/ survives and collides on the next mv.
find . -mindepth 1 -maxdepth 1 -exec rm -rf {} +
cp %{_topdir}/SOURCES/"lachesis-%{version}.tar.gz" .
tar -xzf "lachesis-%{version}.tar.gz"
rm "lachesis-%{version}.tar.gz"
find ./source/ -mindepth 1 -maxdepth 1 -name '*' -exec mv -t . {} +
rmdir source

%build
# .include is the normalized include root the go:generate directives point at.
# A `-target bpf` compile does not resolve the platform's asm/ on its own, and
# the layout differs by distro (el9 keeps asm/ at /usr/include/asm; Debian, used
# by the repo's Docker builder, puts it under a multiarch path). Flattening both
# here is what lets one -I serve every build environment.
#
# Nothing below needs BTF or bpftool: the BPF programs use only UAPI types and
# take no CO-RE relocation, so this compiles unprivileged.
mkdir -p .include
cp -r /usr/include/bpf .include/bpf
cp -r /usr/include/asm .include/asm
cp -r /usr/include/asm-generic .include/asm-generic
cp -r /usr/include/linux .include/linux

GOWORK=off go generate ./...
GOWORK=off GOOS=linux GOARCH=amd64 go build -o %{name} -v ./cmd/agent

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/local/bin
mv %{name} $RPM_BUILD_ROOT/usr/local/bin
mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/cube/lachesis
cp ./deploy/agent/config.example.yaml $RPM_BUILD_ROOT/%{_sysconfdir}/cube/lachesis/lachesis.yaml
mkdir -p $RPM_BUILD_ROOT/%{_unitdir}
cp ./init/lachesis.service $RPM_BUILD_ROOT/%{_unitdir}
mkdir -p $RPM_BUILD_ROOT/%{_datadir}/cube/lachesis
cp LICENSE $RPM_BUILD_ROOT/%{_datadir}/cube/lachesis
# WAL state and log directories, owned by the package so the unit is runnable
# straight from `rpm -i` without depending on the CubeCOS rootfs recipe to have
# created them first. /var/log/lachesis must exist before first start: the unit
# routes stdout/stderr to a file in it via systemd's append:, and systemd will
# not create the parent directory.
mkdir -p $RPM_BUILD_ROOT/var/lib/lachesis
mkdir -p $RPM_BUILD_ROOT/var/log/lachesis

%files
/usr/local/bin/%{name}
%config(noreplace) %{_sysconfdir}/cube/lachesis/lachesis.yaml
%{_unitdir}/lachesis.service
%{_datadir}/cube/lachesis/LICENSE
%dir /var/lib/lachesis
%dir /var/log/lachesis
