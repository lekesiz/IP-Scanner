from setuptools import setup

APP = ['scanner.py']
OPTIONS = {
    'argv_emulation': True,
    'includes': ['scapy', 'requests']
}

setup(
    app=APP,
    options={'py2app': OPTIONS},
    setup_requires=['py2app'],
)
