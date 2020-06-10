from setuptools import setup,find_packages

setup(
    name='mitmproxy2case',
    version='0.3.2',
    author='T8840',
    author_email='qinmimi100@126.com',
    url='https://github.com/T8840/mitmproxy2case',
    packages=find_packages(),
    install_requires=[
        'Click',
        'mitmproxy',
        'PyYaml'
    ],
    entry_points={
        'console_scripts': [
            'mitmproxy2case = mitmproxy2case.mitmproxy2case:cli'
        ]
    }

)