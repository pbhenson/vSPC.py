import os
from setuptools import setup

def read(fname):
	return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "vSPC",
    version = "0.1",
    author = "Zach Loafman",
    author_email = "zmerlynn@sf.net",
    description = ("vSPC is a virtual Serial Port Concentrator for VMware virtual serial ports,"
	                 "available in ESXi 4.1+."),
    license = "BSD",
    keywords = "ESX VMWare serial port concentrator",
    url = "https://github.com/isnotajoke/vSPC.py",
    package_dir = {'vSPC': 'lib'},
	  scripts = [ 'vSPCClient', 'vSPCServer' ],
    packages=['vSPC'],
    #long_description=read('README.md'),
    classifiers=[
      "Development Status :: 3 - Alpha",
      "Topic :: Utilities",
      "License :: OSI Approved :: BSD License",
    	],
)

















