
EAPI=7

PYTHON_COMPAT=( python3_{6..9} )
inherit distutils-r1

DESCRIPTION="A VMware virtual serial port concentrator written in python"
HOMEPAGE="https://github.com/pbhenson/vSPC.py"
SRC_URI="https://github.com/pbhenson/vSPC.py/archive/v${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="BSD-2"
SLOT="0"
IUSE=""
KEYWORDS="amd64"

DEPEND="dev-python/setuptools"
RDEPEND=""

src_unpack() {
	unpack ${A}
	mv vSPC.py-* ${P} || die
}

src_install() {
	distutils-r1_src_install

	newinitd contrib/gentoo/vspc-init vspc
	newconfd contrib/gentoo/vspc-conf vspc
}
