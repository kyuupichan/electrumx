import setuptools
version = '1.12.0'

setuptools.setup(
    name='electrumX',
    version=version,
    scripts=['electrumx_server', 'electrumx_rpc', 'electrumx_compact_history'],
    python_requires='>=3.6',
    install_requires=['aiorpcX>=0.18.1,<0.19', 'attrs',
                      'plyvel', 'pylru', 'aiohttp>=3.3'],
    extras_require={
        'rocksdb': ['python-rocksdb>=0.6.9'],
        'uvloop': ['uvloop>=0.12.2'],   # Bump when the uvloop connection_lost bug is fixed
        # For various coins
        'blake256': ['blake256>=0.1.1'],
        'crypto': ['pycryptodomex>=3.8.1'],
        'groestl': ['groestlcoin-hash>=1.0.1'],
        'tribus-hash': ['tribus-hash>=1.0.2'],
        'xevan-hash': ['xeven-hash'],
        'x11-hash': ['x11-hash>=1.4'],
    },
    packages=setuptools.find_packages(include=('electrumx*',)),
    description='ElectrumX Server',
    author='Neil Booth',
    author_email='kyuupichan@gmail.com',
    license='MIT Licence',
    url='https://github.com/kyuupichan/electrumx',
    long_description='Server implementation for the Electrum protocol',
    download_url=('https://github.com/kyuupichan/electrumX/archive/'
                  f'{version}.tar.gz'),
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Framework :: AsyncIO',
        'License :: OSI Approved :: MIT License',
        'Operating System :: Unix',
        "Programming Language :: Python :: 3.6",
        "Topic :: Database",
        'Topic :: Internet',
    ],
)
