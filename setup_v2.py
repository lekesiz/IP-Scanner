from setuptools import setup

APP = ['scanner_v2.py']
OPTIONS = {
    'argv_emulation': True,
    'includes': ['scapy', 'requests', 'tkinter', 'threading', 'json', 'csv', 'datetime', 'socket', 're'],
    'packages': ['scapy', 'requests'],
    'iconfile': None,  # Icon dosyası eklenebilir
    'plist': {
        'CFBundleName': 'IP Scanner V2',
        'CFBundleDisplayName': 'IP Scanner V2 - Gelişmiş Ağ Tarama',
        'CFBundleGetInfoString': 'Ağ tarama uygulaması',
        'CFBundleIdentifier': 'com.lekesiz.ipscanner.v2',
        'CFBundleVersion': '2.0.0',
        'CFBundleShortVersionString': '2.0.0',
        'NSHumanReadableCopyright': '© 2025 lekesiz'
    }
}

setup(
    app=APP,
    options={'py2app': OPTIONS},
    setup_requires=['py2app'],
    install_requires=[
        'scapy>=2.5.0',
        'requests>=2.28.0'
    ],
    name='ip-scanner-v2',
    version='2.0.0',
    description='Gelişmiş ağ tarama uygulaması',
    author='lekesiz',
    author_email='',
    url='https://github.com/lekesiz/IP-Scanner',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
        'Topic :: System :: Networking :: Monitoring',
        'Topic :: System :: Networking :: Security',
    ],
    python_requires='>=3.7',
) 