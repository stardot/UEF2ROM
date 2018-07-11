#!/usr/bin/env python

# Run this script to create a shared C library version of the compression
# module used by UEF2ROM.py:
#
# python setup.py build_ext --inplace

from distutils.core import setup
from Cython.Build import cythonize

setup(
    ext_modules = cythonize("compressors/distance_pair.pyx")
    )
