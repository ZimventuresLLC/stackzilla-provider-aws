"""Setuptools configuration file."""
import os
from setuptools import setup

# Meta information
dirname = os.path.dirname(os.path.realpath(__file__))
version = open(os.path.join(dirname, '<provider_name>'), encoding='utf-8').read().strip()

# Read in all of the requirements to install/run <provider_name>
install_requirements = []
with open('requirements.txt', encoding='utf-8') as requirements:
    for package in requirements.readlines():
        install_requirements.append(package)

# Read in all of the requirements to run the tests on the <provider_name> codebase
testing_requirements = []
with open('requirements-testing.txt', encoding='utf-8') as testing_req_fh:
    for package in testing_req_fh.readlines():
        testing_requirements.append(package)

dev_requirements = []
with open('requirements-dev.txt', encoding='utf-8') as dev_req_fh:
    for package in dev_req_fh.readlines():
        dev_requirements.append(package)

setup(
    # Basic package info
    name='<provider_name>',
    version=version,
    author='<provider_name>, LLC',
    author_email='yourname@yourdomain.com',
    url='https://github.com/Stackzilla/<provider_name>',
    description='An ORM for your application stack.',
    long_description=open('README.md', encoding='utf-8').read(),
    license='GNU Affero General Public License v3',
    classifiers=[
        'Development Status :: 3 - Alpha',
        "Environment :: Console",
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU Affero General Public License v3',
        'Operating System :: POSIX',
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        'Topic :: Software Development :: Libraries',
    ],

    # Packages and dependencies
    packages=['stackzilla.provider.<provider_name>'],
    python_requires='>3.7',
    include_package_data=True,
    install_requires=install_requirements,
    extras_require={
        'test': testing_requirements,
        'dev': dev_requirements,
    },

    # Data files
    package_data={},

    # Other configurationss
    zip_safe=False,
    platforms='any',
)
