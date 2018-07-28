import setuptools
version = '1.7.1'

setuptools.setup(
    name='electrumX',
    version=version,
    scripts=['electrumx_server', 'electrumx_rpc'],
    python_requires='>=3.6',
    # via environment variables, in which case I've tested with 15.0.4
    # "x11_hash" package (1.4) is required to sync DASH network.
    # "tribus_hash" package is required to sync Denarius network.
    # "blake256" package is required to sync Decred network.
    # "xevan_hash" package is required to sync Xuez network.
    install_requires=['aiorpcX == 0.5.8', 'attrs>=15',
                      'plyvel', 'pylru', 'aiohttp >= 2'],
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
