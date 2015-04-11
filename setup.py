from setuptools import setup, find_packages
import os

#get package version
version = {}
with open(os.path.join('ifalg', 'version.py'), 'r') as fd:
    exec(fd.read(), version);


longDescription = ''
try:
    with open('README.rst', 'r') as fd:
        longDescription = fd.read()
except IOError:
    pass



setup(
    name='ifalg',
    version=version['__version__'],
    description='Library to interface with the Linux kernel crypto API',
    long_description=longDescription,
    url='https://github.com/manologab/python-ifalg',
    author='Manolo Ramirez T.',
    author_email='manologab@gmail.com',
    license='MIT',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Security :: Cryptography',
        'Topic :: System :: Operating System Kernels :: Linux',
        'Operating System :: POSIX :: Linux',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
    ],

    keywords='linux crypto AF_ALG if_alg',
    packages=find_packages(exclude=['contrib', 'docs', 'tests*']),

    install_requires=[
        'cffi>=0.9.2',
        'six>=1.9.0'
    ]
)
