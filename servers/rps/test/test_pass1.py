#coding:utf-8
import datetime
import json
import mock
import os
import pytest
import re
import sys
import urllib
from mpin_utils import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(BASE_DIR + '/..')

import rps

http_server = None

@pytest.fixture
def app(httpserver):
    rps.options.parse_config_file(rps.options.configFile)

    # Set Log level
    #rps.log.setLevel(rps.getLogLevel(rps.options.logLevel))
    #rps.log.setLevel("DEBUG")

    #rps.detectProxy()

    # Load the credentials from file
    rps.credentialsFile = rps.options.credentialsFile
    rps.Keys.loadFromFile(rps.credentialsFile)

    # TMP fix for 'ValueError: I/O operation on closed epoll fd'
    # Fixed in Tornado 4.2
    rps.tornado.ioloop.IOLoop.instance()

    # Sync time to CertiVox time server
    mockResponse = {"Fallback": False, "Format": "u", "Epoch": "1459436400.000", "Time": "2016-04-01 00:00:00Z"}
    httpserver.serve_content(json.dumps(mockResponse), 200)
    with mock.patch("rps.Keys.timeServer", return_value="{0}/".format(httpserver.url)):
        if rps.options.syncTime:
            rps.Time.getTime(wait=True)

    #rps.Keys.getAPISettings(wait=True)
    rps.Keys.timePermitsStorageURL = "https://timepermits.certivox.net"

    '''
    appId : 828aab3a428811e6b23b06df5546c0ed
    appKey : 95735f53a8a7acfb68748c3d47924a4f
    salt : 031207be1551ef9e
    DTA Backup Server Key : {"ciphertext": "cb32284ec3c6abce7f996486c689974b93834a63d9056abf09d5ce02f0d54083", "tag": "4bd72e6dd92003114f44fecb7ee3d095", "startTime": "2016-10-26T02:18:06Z", "IV": "0738ea4ab92331de7f73e371"}
    '''

    with mock.patch.object(rps.options.mockable(), "EntropySources", "dev_urandom:100".decode("utf-8")), mock.patch("rps.secrets.ServerSecret._get_server_secret", return_value="0cccc683768027e33eca50e19c703f7ba4b4d8dbf9641d442e1599ec4618e51212f05d93383b4d211e5318d5a0ed5678311bd2bf8a1bf5f052d28c9d02c50b641586f306074e0b67ee1bc43d586f742fade452fcf1cdeaf25ce3099f0447085c1ebbecba449442aa66123ab7e29783fae6c35a11bcc412f60869d6dc15e01ed0".decode("hex")):
        global http_server
        http_server = rps.Application()

        return http_server

@pytest.mark.gen_test
def test_Pass1Handler(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut = "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"
    pass1 = 1

    body = {
        "mpin_id": mpinId,
        "U": u,
        "UT": ut
    }

    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass1".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )
    mockPass1Value = "1d0ea8985f8dce746d5d504cbf1f90349739ba14dece6e8efa5a1e395c877799"
    mockTime1 = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")

    mockTime2 = "2100-04-01T12:00:15Z"
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime1), mocker.patch("rps.Time.syncedISO", return_value=mockTime2), mocker.patch("rps.secrets.ServerSecret.get_pass1_value", return_value=mockPass1Value), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        print response.body
        responseJson = json.loads(response.body)
        assert responseJson["version"] == "0.3"
        assert responseJson["y"] == "1d0ea8985f8dce746d5d504cbf1f90349739ba14dece6e8efa5a1e395c877799"
        assert responseJson["pass"] == 1
        assert responseJson["message"] == "OK"

        auth = http_server.storage.find(stage="pass1", mpinId=mpinId)
        print auth
        assert auth.mpinId == mpinId
        assert auth.ut == ut
        assert auth.u == u
        assert auth.y == mockPass1Value
        assert auth._expires == "2100-04-01T12:00:15Z"

        mockLog.assert_called_with("200 POST {0}/pass1 127.0.0.1 {1} {2} {3} {4}".format(baseURL, xForwardedFor, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass1HandlerContainOptionalKey(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut = "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"
    pass1 = 1

    body = {
        "mpin_id": mpinId,
        "U": u,
        "UT": ut,
        "pass":pass1
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass1".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockPass1Value = "1d0ea8985f8dce746d5d504cbf1f90349739ba14dece6e8efa5a1e395c877799"
    mockTime1 = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")

    mockTime2 = "2100-04-01T12:00:15Z"
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime1), mocker.patch("rps.Time.syncedISO", return_value=mockTime2), mocker.patch("rps.secrets.ServerSecret.get_pass1_value", return_value=mockPass1Value), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        print response.body
        responseJson = json.loads(response.body)
        assert responseJson["version"] == "0.3"
        assert responseJson["y"] == "1d0ea8985f8dce746d5d504cbf1f90349739ba14dece6e8efa5a1e395c877799"
        assert responseJson["pass"] == 1
        assert responseJson["message"] == "OK"

        auth = http_server.storage.find(stage="pass1", mpinId=mpinId)
        print auth
        assert auth.mpinId == mpinId
        assert auth.ut == ut
        assert auth.u == u
        assert auth.y == mockPass1Value
        assert auth._expires == "2100-04-01T12:00:15Z"

        mockLog.assert_called_with("200 POST {0}/pass1 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass1HandlerCapital(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6F62696c65223A20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    u = "041Ad385Ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut = "040715065Fc621457974f20c976A1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"
    pass1 = 1

    body = {
        "mpin_id": mpinId,
        "U": u,
        "UT": ut,
        "pass":pass1
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass1".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockPass1Value = "1d0ea8985f8dce746d5d504cbf1f90349739ba14dece6e8efa5a1e395c877799"
    mockTime1 = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockTime2 = "2100-04-01T12:00:15Z"
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime1), mocker.patch("rps.Time.syncedISO", return_value=mockTime2), mocker.patch("rps.secrets.ServerSecret.get_pass1_value", return_value=mockPass1Value), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        print response.body
        responseJson = json.loads(response.body)
        assert responseJson["version"] == "0.3"
        assert responseJson["y"] == "1d0ea8985f8dce746d5d504cbf1f90349739ba14dece6e8efa5a1e395c877799"
        assert responseJson["pass"] == 1
        assert responseJson["message"] == "OK"

        auth = http_server.storage.find(stage="pass1", mpinId=mpinId)
        assert auth == None

        mockLog.assert_called_with("200 POST {0}/pass1 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass1HandlerUnnecessaryKeyError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7B226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    u = "041Ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut = "040715065Fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"
    pass1 = 1

    body = {
        "unnecessaryKey":"test",
        "mpin_id": mpinId,
        "U": u,
        "UT": ut,
        "pass":pass1
    }
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass1".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with  mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass1 127.0.0.1 {1} {2} {3} {4} Invalid data received. unnecessaryKey argument unnecessary {5}".format(baseURL, xForwardedFor, "", "", "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_Pass1HandlerUKeyError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7B226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    u = "041Ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut = "040715065Fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"
    pass1 = 1

    body = {
        "mpin_id": mpinId,
        "UT": ut,
        "pass":pass1
    }
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass1".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with  mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass1 127.0.0.1 {1} {2} {3} {4} Invalid data received. U argument missing {5}".format(baseURL, xForwardedFor, mpinId, "root@localhost.localdomain", "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_Pass1HandlerUTKeyError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7B226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    u = "041Ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut = "040715065Fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"
    pass1 = 1

    body = {
        "mpin_id": mpinId,
        "U":u,
        "pass":pass1
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass1".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with  mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass1 127.0.0.1  {1} {2} {3} Invalid data received. UT argument missing unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass1HandlerMpinIdKeyError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7B226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    u = "041Ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut = "040715065Fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"
    pass1 = 1

    body = {
        "U": u,
        "UT": ut,
        "pass":pass1
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass1".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with  mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass1 127.0.0.1  {1} {2} {3} Invalid data received. mpin_id argument missing unknown".format(baseURL, "", "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass1HandlerMpinIdInvalidLengthError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227df"
    u = "041Ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut = "040715065Fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"
    pass1 = 1

    body = {
        "mpin_id": mpinId,
        "U": u,
        "UT": ut,
        "pass":pass1
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass1".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with  mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass1 127.0.0.1  {1} {2} {3} Invalid data received. Odd-length string unknown".format(baseURL, mpinId, "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass1HandlerMpinIdInvalidCharacterFullError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7B226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227Ａ"
    u = "041Ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut = "040715065Fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"
    pass1 = 1

    body = {
        "mpin_id": mpinId,
        "U": u,
        "UT": ut,
        "pass":pass1
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass1".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with  mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass1 127.0.0.1  {1} {2} {3} Invalid data received.  unknown".format(baseURL, "", "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass1HandlerMpinIdInvalidCharacterNotHexError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227g"
    u = "041Ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut = "040715065Fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"
    pass1 = 1

    body = {
        "mpin_id": mpinId,
        "U": u,
        "UT": ut,
        "pass":pass1
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass1".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with  mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass1 127.0.0.1  {1} {2} {3} Invalid data received. Non-hexadecimal digit found unknown".format(baseURL, mpinId, "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass1HandlerMpinIdInvalidCharacterNotHexCapitalError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227G"
    u = "041Ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut = "040715065Fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"
    pass1 = 1

    body = {
        "mpin_id": mpinId,
        "U": u,
        "UT": ut,
        "pass":pass1
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass1".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with  mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass1 127.0.0.1  {1} {2} {3} Invalid data received. Non-hexadecimal digit found unknown".format(baseURL, mpinId, "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass1HandlerMpinIdInvalidCharacterSymbolsError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7B226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227/"
    u = "041Ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut = "040715065Fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"
    pass1 = 1

    body = {
        "mpin_id": mpinId,
        "U": u,
        "UT": ut,
        "pass":pass1
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass1".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with  mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass1 127.0.0.1  {1} {2} {3} Invalid data received. Non-hexadecimal digit found unknown".format(baseURL, mpinId, "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass1HandlerUInvalidLength131Error(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7B226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    u = "041Ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1af"
    ut = "040715065Fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"
    pass1 = 1

    body = {
        "mpin_id": mpinId,
        "U": u,
        "UT": ut,
        "pass":pass1
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass1".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with  mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass1 127.0.0.1  {1} {2} {3} Invalid data received. U argument invalid length unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass1HandlerUInvalidLength129Error(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7B226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    u = "041Ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1"
    ut = "040715065Fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"
    pass1 = 1

    body = {
        "mpin_id": mpinId,
        "U": u,
        "UT": ut,
        "pass":pass1
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass1".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with  mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass1 127.0.0.1  {1} {2} {3} Invalid data received. U argument invalid length unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass1HandlerUTInvalidLength131Error(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7B226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    u = "041Ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut = "040715065Fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7f"
    pass1 = 1

    body = {
        "mpin_id": mpinId,
        "U": u,
        "UT": ut,
        "pass":pass1
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass1".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with  mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass1 127.0.0.1  {1} {2} {3} Invalid data received. UT argument invalid length unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass1HandlerUTInvalidLength129Error(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7B226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    u = "041Ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut = "040715065Fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb"
    pass1 = 1

    body = {
        "mpin_id": mpinId,
        "U": u,
        "UT": ut,
        "pass":pass1
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass1".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with  mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass1 127.0.0.1  {1} {2} {3} Invalid data received. UT argument invalid length unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass1HandlerUInvalidCharacterFullError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7B226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    u = "041Ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1Ａ"
    ut = "040715065Fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"
    pass1 = 1

    body = {
        "mpin_id": mpinId,
        "U": u,
        "UT": ut,
        "pass":pass1
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass1".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with  mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass1 127.0.0.1  {1} {2} {3} Invalid data received. U argument contains invalid characters unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass1HandlerUInvalidCharacterNotHexError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7B226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    u = "041Ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1g"
    ut = "040715065Fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"
    pass1 = 1

    body = {
        "mpin_id": mpinId,
        "U": u,
        "UT": ut,
        "pass":pass1
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass1".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with  mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass1 127.0.0.1  {1} {2} {3} Invalid data received. U argument contains invalid characters unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass1HandlerUInvalidCharacterNotHexCapitalError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7B226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    u = "041Ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1G"
    ut = "040715065Fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"
    pass1 = 1

    body = {
        "mpin_id": mpinId,
        "U": u,
        "UT": ut,
        "pass":pass1
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass1".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with  mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass1 127.0.0.1  {1} {2} {3} Invalid data received. U argument contains invalid characters unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass1HandlerUInvalidCharacterSymbolsError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7B226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    u = "041Ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1/"
    ut = "040715065Fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"
    pass1 = 1

    body = {
        "mpin_id": mpinId,
        "U": u,
        "UT": ut,
        "pass":pass1
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass1".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with  mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass1 127.0.0.1  {1} {2} {3} Invalid data received. U argument contains invalid characters unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass1HandlerUTInvalidCharacterFullError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7B226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    u = "041Ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut = "040715065Fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbbＡ"
    pass1 = 1

    body = {
        "mpin_id": mpinId,
        "U": u,
        "UT": ut,
        "pass":pass1
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass1".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with  mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass1 127.0.0.1  {1} {2} {3} Invalid data received. UT argument contains invalid characters unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass1HandlerUTInvalidCharacterNotHexError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7B226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    u = "041Ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut = "040715065Fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbbg"
    pass1 = 1

    body = {
        "mpin_id": mpinId,
        "U": u,
        "UT": ut,
        "pass":pass1
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass1".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with  mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass1 127.0.0.1  {1} {2} {3} Invalid data received. UT argument contains invalid characters unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass1HandlerUTInvalidCharacterNotHexCapitalError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7B226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    u = "041Ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut = "040715065Fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbbG"
    pass1 = 1

    body = {
        "mpin_id": mpinId,
        "U": u,
        "UT": ut,
        "pass":pass1
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass1".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with  mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass1 127.0.0.1  {1} {2} {3} Invalid data received. UT argument contains invalid characters unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass1HandlerUTInvalidCharacterSymbolsError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7B226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    u = "041Ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut = "040715065Fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb/"
    pass1 = 1

    body = {
        "mpin_id": mpinId,
        "U": u,
        "UT": ut,
        "pass":pass1
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass1".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with  mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass1 127.0.0.1  {1} {2} {3} Invalid data received. UT argument contains invalid characters unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass1HandlerUserIDGetError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut = "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id": mpinId,
        "U": u,
        "UT": ut
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass1".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockPass1Value = "1d0ea8985f8dce746d5d504cbf1f90349739ba14dece6e8efa5a1e395c877799"
    mockTime1 = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")

    mockTime2 = "2100-04-01T12:00:15Z"
    mockLog = mocker.Mock()
    mockWarnLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime1), mocker.patch("rps.Time.syncedISO", return_value=mockTime2), mocker.patch("rps.secrets.ServerSecret.get_pass1_value", return_value=mockPass1Value), mock.patch.object(rps.log, "info", mockLog), mock.patch.object(rps.log, "warn", mockWarnLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        print response.body
        responseJson = json.loads(response.body)
        assert responseJson["version"] == "0.3"
        assert responseJson["y"] == "1d0ea8985f8dce746d5d504cbf1f90349739ba14dece6e8efa5a1e395c877799"
        assert responseJson["pass"] == 1
        assert responseJson["message"] == "OK"

        auth = http_server.storage.find(stage="pass1", mpinId=mpinId)
        print auth
        assert auth.mpinId == mpinId
        assert auth.ut == ut
        assert auth.u == u
        assert auth.y == mockPass1Value
        assert auth._expires == "2100-04-01T12:00:15Z"

        mockWarnLog.assert_called_with("{0}/pass1 127.0.0.1  {1} {2} {3} fail to get userID unknown".format(baseURL, mpinId, "", "").decode("utf-8"))
        mockLog.assert_called_with("200 POST {0}/pass1 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass1HandlerSecretsError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut = "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"
    pass1 = 1

    body = {
        "mpin_id": mpinId,
        "U": u,
        "UT": ut
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass1".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockTime1 = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")

    mockTime2 = "2100-04-01T12:00:15Z"
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime1), mocker.patch("rps.Time.syncedISO", return_value=mockTime2), mock.patch.object(rps.log, "error", mockLog), mocker.patch("rps.secrets.ServerSecret.get_pass1_value", side_effect=secrets.SecretsError("error")):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass1 127.0.0.1  {1} {2} {3} error unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))
