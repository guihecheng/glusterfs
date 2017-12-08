#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from subprocess import PIPE, Popen
from errno import EEXIST, ENOENT
import xml.etree.cElementTree as etree
import logging
import os
from datetime import datetime

ParseError = etree.ParseError if hasattr(etree, 'ParseError') else SyntaxError
cache_data = {}

def cache_output(func):
    def wrapper(*args, **kwargs):
        global cache_data
        if cache_data.get(func.func_name, None) is None:
            cache_data[func.func_name] = func(*args, **kwargs)

        return cache_data[func.func_name]
    return wrapper

def human_time(ts):
    return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")


def setup_logger(logger, path, debug=False):
    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    # create the logging file handler
    fh = logging.FileHandler(path)

    formatter = logging.Formatter("[%(asctime)s] %(levelname)s "
                                  "[%(module)s - %(lineno)s:%(funcName)s] "
                                  "- %(message)s")

    fh.setFormatter(formatter)

    # add handler to logger object
    logger.addHandler(fh)

def mkdirp(path, exit_on_err=False, logger=None):
    """
    Try creating required directory structure
    ignore EEXIST and raise exception for rest of the errors.
    Print error in stderr and exit if exit_on_err is set, else
    raise exception.
    """
    try:
        os.makedirs(path)
    except (OSError, IOError) as e:
        if e.errno == EEXIST and os.path.isdir(path):
            pass
        else:
            if exit_on_err:
                fail("Fail to create dir %s: %s" % (path, e), logger=logger)
            else:
                raise

def fail(msg, code=1, logger=None):
    """
    Write error to stderr and exit
    """
    if logger:
        logger.error(msg)
    sys.stderr.write("%s\n" % msg)
    sys.exit(code)


def execute(cmd, exit_msg=None, logger=None):
    """
    If failure_msg is not None then return returncode, out and error.
    If failure msg is set, write to stderr and exit.
    """
    p = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE, close_fds=True)

    (out, err) = p.communicate()
    if p.returncode != 0 and exit_msg is not None:
        fail("%s: %s" % (exit_msg, err), p.returncode, logger=logger)

    return (p.returncode, out, err)
