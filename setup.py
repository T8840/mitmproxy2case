from setuptools import setup

setup(
    name='mitmproxy2case',
    version='0.1',
    py_modules=['mitmproxy2case'],
    install_requires=[
        'Click',
        'mitmproxy',
        'yaml'
    ],
    entry_points='''
        [console_scripts]
        mitmproxy2case=mitmproxy2case:cli
    ''',
)