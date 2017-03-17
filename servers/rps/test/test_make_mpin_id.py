import json
import mock
import os
import pytest
import re
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(BASE_DIR + '/..')

import rps

def test_makeMPinIDMobileNone():
    userId = "root@localhost"
    mobile = None

    mpinId = rps.makeMPinID(userId, mobile)
    mpinIdJson = json.loads(mpinId.decode("hex"))
    timeFormat = re.compile("^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{6}$")
    saltFormat = re.compile("^[0-9a-z]{32}$", re.IGNORECASE)
    assert timeFormat.match(mpinIdJson["issued"])
    assert mpinIdJson["userID"] == userId
    assert mpinIdJson["mobile"] == 0
    assert saltFormat.match(mpinIdJson["salt"])

def test_makeMPinIDMobile1():
    userId = "root@localhost"
    mobile = 1

    mpinId = rps.makeMPinID(userId, mobile)
    mpinIdJson = json.loads(mpinId.decode("hex"))
    timeFormat = re.compile("^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{6}$")
    saltFormat = re.compile("^[0-9a-z]{32}$", re.IGNORECASE)
    assert timeFormat.match(mpinIdJson["issued"])
    assert mpinIdJson["userID"] == userId
    assert mpinIdJson["mobile"] == mobile
    assert saltFormat.match(mpinIdJson["salt"])
