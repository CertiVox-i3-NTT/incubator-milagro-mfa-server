import json
import mock
import os
import pytest
import re
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(BASE_DIR + '/..')

import rps

def test_addNonce():
    mpinId = "mpinId"
    nonce = "nonce"

    rps.options.parse_config_file(rps.options.configFile)
    storage_cls = rps.get_storage_cls()
    storage = storage_cls(
        rps.tornado.ioloop.IOLoop.instance(),
        "stage,mpinId",
        "stage,mpinId,nonce",
        "stage,authOTT",
        "stage,wid",
        "stage,webOTT",
        "time_permit_id,time_permit_date"
    )

    rps.add_nonce(storage, mpinId, nonce)
    nonceListCheck = storage.find(stage="empin-auth-nonce-list-check", mpinId=mpinId)
    isoFormat = re.compile("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}$")
    assert nonceListCheck._expires == None
    assert nonceListCheck.stage == "empin-auth-nonce-list-check"
    assert nonceListCheck.mpinId == mpinId
    assert nonceListCheck.nonce_list == [nonce]
    nonceCheck = storage.find(stage="empin-auth-nonce-check", mpinId=mpinId, nonce=nonce)
    assert isoFormat.match(nonceCheck._expires)
    assert nonceCheck.stage == "empin-auth-nonce-check"
    assert nonceCheck.mpinId == mpinId
    assert nonceCheck.nonce == nonce

def test_addNonceAddList():
    mpinId = "mpinId"
    nonce = "nonce"

    rps.options.parse_config_file(rps.options.configFile)
    storage_cls = rps.get_storage_cls()
    storage = storage_cls(
        rps.tornado.ioloop.IOLoop.instance(),
        "stage,mpinId",
        "stage,mpinId,nonce",
        "stage,authOTT",
        "stage,wid",
        "stage,webOTT",
        "time_permit_id,time_permit_date"
    )
    storage.add(stage="empin-auth-nonce-list-check", mpinId=mpinId, nonce_list=[nonce])

    rps.add_nonce(storage, mpinId, nonce)
    nonceListCheck = storage.find(stage="empin-auth-nonce-list-check", mpinId=mpinId)
    isoFormat = re.compile("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}$")
    assert nonceListCheck._expires == None
    assert nonceListCheck.stage == "empin-auth-nonce-list-check"
    assert nonceListCheck.mpinId == mpinId
    assert nonceListCheck.nonce_list == [nonce, nonce]
    nonceCheck = storage.find(stage="empin-auth-nonce-check", mpinId=mpinId, nonce=nonce)
    assert isoFormat.match(nonceCheck._expires)
    assert nonceCheck.stage == "empin-auth-nonce-check"
    assert nonceCheck.mpinId == mpinId
    assert nonceCheck.nonce == nonce
