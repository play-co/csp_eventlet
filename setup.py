from setuptools import setup, find_packages
import os, sys


setup(
    name='csp_eventlet',
    version='0.3.0',
    author='Michael Carter',
    author_email='CarterMichael@gmail.com',
    url='http://github.com/mcarter/csp_eventlet',
    license='MIT License',
    description='An implemention of the Comet Session protocol specification for eventlet: http://orbited.org/blog/files/cps.html',
    long_description='This csp implementation provides a socket object that allows you to use existing eventlet network code, but listen for csp connections in addition to tcp/ip.',
    packages= find_packages(),
    zip_safe = True,
    install_requires = [ 'eventlet' ],
    classifiers = [
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],        
)

