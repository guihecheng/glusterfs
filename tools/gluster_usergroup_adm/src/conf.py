#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import ConfigParser

config = ConfigParser.ConfigParser()
config.read(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "ugadm.conf"))

def get_opt(opt):
    return config.get("vars", opt)
