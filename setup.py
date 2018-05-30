from setuptools import setup
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='RoboSslyze',
    version='0.9',
    packages=[''],
    package_dir={'': 'robosslyze'},
    url='https://www.github.com/we45/RoboSslyze',
    license='MIT',
    author='we45',
    author_email='info@we45.com',
    description='Robot Framework Library for the SSLyze Python Script',
    install_requires=[
        'sslyze',
        'robotframework==3.0.4'
    ],
    long_description = long_description,
    long_description_content_type='text/markdown'
)
