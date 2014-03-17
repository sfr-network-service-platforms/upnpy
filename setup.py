from distutils.core import setup

def readme():
    with open('README.md') as f:
        return f.read()

setup(name='upnpy',
      version='0.9',
      description='A fully featured UPnP python stack',
      long_description=readme(),
      classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: GNU Library or Lesser General Public License (LGPL)',
        'Programming Language :: Python :: 2.7',
        'Topic :: Home Automation',
      ],
      keywords='UPnP',
      url='https://github.com/sfr-network-service-platforms/upnpy',
      author='Antoine Monnet',
      author_email='antoine.monnet@sfr.com',
      license='LGPL',
      packages=['upnpy'],
      # extras_requires={
      #   'openssl':['OpenSSL'],
      #   'm2crypto':['M2Crypto'],
      #   'console_browser':['urwid', 'bpython'],
      #   },
      #include_package_data=True,
      #zip_safe=False,
      )

