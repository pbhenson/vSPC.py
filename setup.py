#!/usr/bin/python

import os
from setuptools import setup
from lib import __version__

def read(fname):
	return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "vSPC",
    version = __version__,
    author = "Zach Loafman",
    author_email = "zmerlynn@sf.net",
    description = ("vSPC is a virtual Serial Port Concentrator for VMware virtual serial ports,"
                   "available in ESXi 4.1+."),
    license = "BSD",
    keywords = "ESX VMWare serial port concentrator",
    url = "https://github.com/pbhenson/vSPC.py",
    package_dir = {'vSPC': 'lib'},
    scripts = [ 'vSPCClient', 'vSPCServer' ],
    # Don't blindly install Red Hat specific files
    # Python-fu welcomed to make this only run on Red Hat boxes
    #data_files = [('/etc/init.d', ['util/sysvinit/vSPCServer'])],
    packages=['vSPC'],
    #apparently this doesn't always work need to look into this
    #long_description=read('README.md'),
    classifiers=[
      "Development Status :: 3 - Alpha",
      "Topic :: Utilities",
      "License :: OSI Approved :: BSD License",
    ],
)
