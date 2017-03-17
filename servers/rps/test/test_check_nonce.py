import json
import mock
import os
import pytest
import re
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(BASE_DIR + '/..')

import rps

def test_checkNonce():
    mpinId = "mpinId"
    nonce = "nonce"

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

    assert rps.check_nonce(storage, mpinId, nonce) == True

def test_checkNonceFindNonce():
    mpinId = "mpinId"
    nonce = "nonce"

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
    storage.add(expire_time="2100-04-01T12:00:00", stage="empin-auth-nonce-check", mpinId=mpinId, nonce=nonce)

    assert rps.check_nonce(storage, mpinId, nonce) == False
