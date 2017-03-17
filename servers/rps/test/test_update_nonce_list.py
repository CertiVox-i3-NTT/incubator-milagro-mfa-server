import json
import mock
import os
import pytest
import re
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(BASE_DIR + '/..')

import rps

def test_updateNonceListNotFind():
    mpinId = "mpinId"

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

    assert rps.update_nonce_list(storage, mpinId) == []

def test_updateNonceListFind():
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
    storage.add(expire_time="2100-04-01T12:00:00", stage="empin-auth-nonce-check", mpinId=mpinId, nonce=nonce)

    assert rps.update_nonce_list(storage, mpinId) == [nonce]
    nonceListCheck = storage.find(stage="empin-auth-nonce-list-check", mpinId=mpinId)
    assert nonceListCheck.nonce_list == [nonce]

def test_updateNonceListFindDel1():
    mpinId = "mpinId"
    nonce = "nonce"
    nonce2 = "nonce2"

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
    storage.add(stage="empin-auth-nonce-list-check", mpinId=mpinId, nonce_list=[nonce, nonce2])
    storage.add(expire_time="2100-04-01T12:00:00", stage="empin-auth-nonce-check", mpinId=mpinId, nonce=nonce2)

    assert rps.update_nonce_list(storage, mpinId) == [nonce2]
    nonceListCheck = storage.find(stage="empin-auth-nonce-list-check", mpinId=mpinId)
    assert nonceListCheck.nonce_list == [nonce2]

def test_updateNonceListFindDel2():
    mpinId = "mpinId"
    nonce = "nonce"
    nonce2 = "nonce2"

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
    storage.add(stage="empin-auth-nonce-list-check", mpinId=mpinId, nonce_list=[nonce, nonce2])
    storage.add(expire_time="2100-04-01T12:00:00", stage="empin-auth-nonce-check", mpinId=mpinId, nonce=nonce)

    assert rps.update_nonce_list(storage, mpinId) == [nonce]
    nonceListCheck = storage.find(stage="empin-auth-nonce-list-check", mpinId=mpinId)
    assert nonceListCheck.nonce_list == [nonce]

def test_updateNonceListFindDelAll():
    mpinId = "mpinId"
    nonce = "nonce"
    nonce2 = "nonce2"

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
    storage.add(stage="empin-auth-nonce-list-check", mpinId=mpinId, nonce_list=[nonce, nonce2])

    assert rps.update_nonce_list(storage, mpinId) == []
    nonceListCheck = storage.find(stage="empin-auth-nonce-list-check", mpinId=mpinId)
    assert nonceListCheck.nonce_list == []
