from setuptools import setup, find_packages
from server.version import VERSION

setup(
    name='electrumx',
    version=VERSION.split()[-1],
    scripts=['electrumx_server.py', 'electrumx_rpc.py'],
    python_requires='>=3.6',
    # "irc" package is only required if IRC connectivity is enabled
    # via environment variables, in which case I've tested with 15.0.4
    # "x11_hash" package (1.4) is required to sync DASH network.
    install_requires=['plyvel', 'pylru', 'irc', 'aiohttp >= 1'],
    packages=find_packages(exclude=['tests']),
    description='ElectrumX Server',
    author='Neil Booth',
    author_email='kyuupichan@gmail.com',
    license='MIT Licence',
    url='https://github.com/kyuupichan/electrumx/',
    long_description='Server implementation for the Electrum wallet',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Topic :: Internet',
        'License :: OSI Approved :: MIT License',
        'Operating System :: Unix',
    ],
)
