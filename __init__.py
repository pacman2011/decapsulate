##
# Python Imports
import os
import sys

my_path = os.path.realpath(__file__)    # Get the non-symlink path to this file
my_dir  = os.path.dirname(my_path)      # Get the directory this file is in


##
# Correct the python-path
path = os.path.abspath(my_dir)
if path not in sys.path:
    sys.path.append(path)
