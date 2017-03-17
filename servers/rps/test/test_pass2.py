#coding:utf-8
import datetime
import json
import mock
import os
import pytest
import re
import sys
import urllib

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
def test_Pass2Handler(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    wid = "7684363"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440a"
    pass2 = 2
    otp = 0
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
    }

    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )
    mockPass2Value = "3e4519917c611339c7d0c509a9eede9c6cd5a980aefb4bc0ebacc8b2a9a47243"
    y = "1d0ea8985f8dce746d5d504cbf1f90349739ba14dece6e8efa5a1e395c877799"

    http_server.storage.add(stage="pass1", mpinId=mpinId, u=u, ut=ut, y=y)
    mockLog = mocker.Mock()
    with mocker.patch("rps.secrets.generate_auth_ott", return_value=mockPass2Value), mock.patch.object(rps.log, "info", mockLog):
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
        assert responseJson["pass"] == 2
        assert responseJson["authOTT"] == mockPass2Value

        mockLog.assert_called_with("200 POST {0}/pass2 127.0.0.1 {1} {2} {3} {4}".format(baseURL, xForwardedFor, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerContainOptionalKey(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    wid = "7684363"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440a"
    pass2 = 2
    otp = 0
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockPass2Value = "3e4519917c611339c7d0c509a9eede9c6cd5a980aefb4bc0ebacc8b2a9a47243"
    y = "1d0ea8985f8dce746d5d504cbf1f90349739ba14dece6e8efa5a1e395c877799"

    http_server.storage.add(stage="pass1", mpinId=mpinId, u=u, ut=ut, y=y)
    mockLog = mocker.Mock()
    with mocker.patch("rps.secrets.generate_auth_ott", return_value=mockPass2Value), mock.patch.object(rps.log, "info", mockLog):
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
        assert responseJson["pass"] == 2
        assert responseJson["authOTT"] == mockPass2Value

        mockLog.assert_called_with("200 POST {0}/pass2 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerWIDOne(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    wid = "0"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440a"
    pass2 = 2
    otp = 0
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockPass2Value = "3e4519917c611339c7d0c509a9eede9c6cd5a980aefb4bc0ebacc8b2a9a47243"
    y = "1d0ea8985f8dce746d5d504cbf1f90349739ba14dece6e8efa5a1e395c877799"

    http_server.storage.add(stage="pass1", mpinId=mpinId, u=u, ut=ut, y=y)
    mockLog = mocker.Mock()
    with mocker.patch("rps.secrets.generate_auth_ott", return_value=mockPass2Value), mock.patch.object(rps.log, "info", mockLog):
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
        assert responseJson["pass"] == 2
        assert responseJson["authOTT"] == mockPass2Value

        mockLog.assert_called_with("200 POST {0}/pass2 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerWIDAccessNumberUseCheckSumFalseValidLength6(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    wid = "768436"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440a"
    pass2 = 2
    otp = 0
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockPass2Value = "3e4519917c611339c7d0c509a9eede9c6cd5a980aefb4bc0ebacc8b2a9a47243"
    y = "1d0ea8985f8dce746d5d504cbf1f90349739ba14dece6e8efa5a1e395c877799"

    http_server.storage.add(stage="pass1", mpinId=mpinId, u=u, ut=ut, y=y)
    mockLog = mocker.Mock()
    with mock.patch.object(rps.options.mockable(), "accessNumberUseCheckSum", False), mocker.patch("rps.secrets.generate_auth_ott", return_value=mockPass2Value), mock.patch.object(rps.log, "info", mockLog):
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
        assert responseJson["pass"] == 2
        assert responseJson["authOTT"] == mockPass2Value

        mockLog.assert_called_with("200 POST {0}/pass2 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerOTPOne(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    wid = "7684363"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440a"
    pass2 = 2
    otp = 1
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockPass2Value = "3e4519917c611339c7d0c509a9eede9c6cd5a980aefb4bc0ebacc8b2a9a47243"
    y = "1d0ea8985f8dce746d5d504cbf1f90349739ba14dece6e8efa5a1e395c877799"

    http_server.storage.add(stage="pass1", mpinId=mpinId, u=u, ut=ut, y=y)
    mockLog = mocker.Mock()
    with mocker.patch("rps.secrets.generate_auth_ott", return_value=mockPass2Value), mock.patch.object(rps.log, "info", mockLog):
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
        assert responseJson["pass"] == 2
        assert responseJson["authOTT"] == mockPass2Value

        mockLog.assert_called_with("200 POST {0}/pass2 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerCapital(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6F62696c65223A20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    wid = "7684363"
    v = "0418b36ec021bA3Fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440a"
    pass2 = 2
    otp = 0
    u = "041Ad385Ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065Fc621457974f20c976A1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockPass2Value = "3e4519917c611339c7d0c509a9eede9c6cd5a980aefb4bc0ebacc8b2a9a47243"
    y = "1d0ea8985f8dce746d5d504cbf1f90349739ba14dece6e8efa5a1e395c877799"
    mockLog = mocker.Mock()
    http_server.storage.add(stage="pass1", mpinId=mpinId, u=u, ut=ut, y=y)

    with mocker.patch("rps.secrets.generate_auth_ott", return_value=mockPass2Value), mock.patch.object(rps.log, "info", mockLog):
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
        assert responseJson["pass"] == 2
        assert responseJson["authOTT"] == mockPass2Value

        mockLog.assert_called_with("200 POST {0}/pass2 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerUnncessaryKeyError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    wid = "7684363"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440a"
    pass2 = 2
    otp = 0
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "unnecessaryKey":"test",
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
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

            mockLog.assert_called_with("{0}/pass2 127.0.0.1 {1} {2} {3} {4} Invalid data received. unnecessaryKey argument unnecessary {5}".format(baseURL, xForwardedFor, "", "", "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerMpinIdKeyError(http_client, base_url, mocker):
    baseURL = "/rps"
    wid = "7684363"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440a"
    pass2 = 2
    otp = 0
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "WID": wid,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass2 127.0.0.1 {1} {2} {3} {4} Invalid data received. mpin_id argument missing {5}".format(baseURL, xForwardedFor, "", "", "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerWIDKeyError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440a"
    pass2 = 2
    otp = 0
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass2 127.0.0.1 {1} {2} {3} {4} Invalid data received. WID argument missing {5}".format(baseURL, xForwardedFor, mpinId, "root@localhost.localdomain", "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerOTPKeyError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    wid = "7684363"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440a"
    pass2 = 2
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "pass":pass2
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass2 127.0.0.1  {1} {2} {3} Invalid data received. OTP argument missing unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerVKeyError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    wid = "7684363"
    pass2 = 2
    otp = 0
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "OTP": otp,
        "pass":pass2
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass2 127.0.0.1  {1} {2} {3} Invalid data received. V argument missing unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerMpinIdInvalidLengthError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227dd"
    wid = "7684363"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440a"
    pass2 = 2
    otp = 0
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass2 127.0.0.1  {1} {2} {3} Invalid data received. Odd-length string unknown".format(baseURL, mpinId, "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerMpinIdInvalidCharacterFullError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227Ａ"
    wid = "7684363"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440a"
    pass2 = 2
    otp = 0
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass2 127.0.0.1  {1} {2} {3} Invalid data received.  unknown".format(baseURL, "", "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerMpinIdInvalidCharacterNotHexError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227g"
    wid = "7684363"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440a"
    pass2 = 2
    otp = 0
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass2 127.0.0.1  {1} {2} {3} Invalid data received. Non-hexadecimal digit found unknown".format(baseURL, mpinId, "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerMpinIdInvalidCharacterNotHexCapitalError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227G"
    wid = "7684363"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440a"
    pass2 = 2
    otp = 0
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass2 127.0.0.1  {1} {2} {3} Invalid data received. Non-hexadecimal digit found unknown".format(baseURL, mpinId, "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerMpinIdInvalidCharacterSymbolsError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227/"
    wid = "7684363"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440a"
    pass2 = 2
    otp = 0
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass2 127.0.0.1  {1} {2} {3} Invalid data received. Non-hexadecimal digit found unknown".format(baseURL, mpinId, "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerVInvalidLength131Error(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    wid = "7684363"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440af"
    pass2 = 2
    otp = 0
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass2 127.0.0.1  {1} {2} {3} Invalid data received. V argument invalid length unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerVInvalidLength129Error(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    wid = "7684363"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440"
    pass2 = 2
    otp = 0
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass2 127.0.0.1  {1} {2} {3} Invalid data received. V argument invalid length unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerVInvalidCharacterFullError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    wid = "7684363"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440Ａ"
    pass2 = 2
    otp = 0
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass2 127.0.0.1 {1} {2} {3} {4} Invalid data received.  {5}".format(baseURL, xForwardedFor, mpinId, "root@localhost.localdomain", "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerVInvalidCharacterNotHexError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    wid = "7684363"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440g"
    pass2 = 2
    otp = 0
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass2 127.0.0.1  {1} {2} {3} Invalid data received. Non-hexadecimal digit found unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerVInvalidCharacterNotHexCapitalError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    wid = "7684363"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440G"
    pass2 = 2
    otp = 0
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass2 127.0.0.1  {1} {2} {3} Invalid data received. Non-hexadecimal digit found unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerVInvalidCharacterSymbolsError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    wid = "7684363"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440/"
    pass2 = 2
    otp = 0
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass2 127.0.0.1  {1} {2} {3} Invalid data received. Non-hexadecimal digit found unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerOTPInvalidNumber2Error(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    wid = "7684363"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440a"
    pass2 = 2
    otp = 2
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass2 127.0.0.1  {1} {2} {3} Invalid data received. OTP argument invalid number unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerOTPInvalidCharacterAlphaError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    wid = "7684363"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440a"
    pass2 = 2
    otp = "a"
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass2 127.0.0.1  {1} {2} {3} Invalid data received. invalid literal for int() with base 10: 'a' unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerOTPInvalidCharacterSymbolsError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    wid = "7684363"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440a"
    pass2 = 2
    otp = "/"
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass2 127.0.0.1  {1} {2} {3} Invalid data received. invalid literal for int() with base 10: '/' unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerOTPInvalidCharacterFullError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    wid = "7684363"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440a"
    pass2 = 2
    otp = "Ａ"
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass2 127.0.0.1  {1} {2} {3} Invalid data received.  unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerOTPInvalidValueError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    wid = "7684363"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440a"
    pass2 = 2
    otp = {}
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
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

            mockLog.assert_called_with("{0}/pass2 127.0.0.1  {1} {2} {3} Invalid data received. int() argument must be a string or a number, not 'dict' unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerWIDAccessNumberUseCheckSumTrueInvalidLength8Error(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    wid = "76843631"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440a"
    pass2 = 2
    otp = 2
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass2 127.0.0.1  {1} {2} {3} Invalid data received. WID argument invalid length unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerWIDAccessNumberUseCheckSumTrueInvalidLength6Error(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    wid = "768436"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440a"
    pass2 = 2
    otp = 1
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass2 127.0.0.1  {1} {2} {3} Invalid data received. WID argument invalid length unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerWIDAccessNumberUseCheckSumFalseInvalidLength7Error(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    wid = "7684363"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440a"
    pass2 = 2
    otp = 2
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mock.patch.object(rps.options.mockable(), "accessNumberUseCheckSum", False), mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass2 127.0.0.1  {1} {2} {3} Invalid data received. WID argument invalid length unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerWIDAccessNumberUseCheckSumFalseInvalidLength5Error(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    wid = "76843"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440a"
    pass2 = 2
    otp = 1
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mock.patch.object(rps.options.mockable(), "accessNumberUseCheckSum", False),mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass2 127.0.0.1  {1} {2} {3} Invalid data received. WID argument invalid length unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerWIDInvalidCharacterSymbolsError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    wid = "768436/"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440a"
    pass2 = 2
    otp = 1
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass2 127.0.0.1  {1} {2} {3} Invalid data received. WID argument contains invalid characters unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerWIDInvalidCharacterAlphaError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    wid = "768436a"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440a"
    pass2 = 2
    otp = "a"
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass2 127.0.0.1  {1} {2} {3} Invalid data received. WID argument contains invalid characters unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerWIDInvalidCharacterFullError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    wid = "Ａ"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440a"
    pass2 = 2
    otp = 2
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
        "pass":pass2
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass2 127.0.0.1  {1} {2} {3} Invalid data received. WID argument invalid length unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerUserIDGetError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    wid = "7684363"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440a"
    otp = 0
    u = "041ad385ff968261fcc21cba44953bd4c35be6593160408109761c51b81bda9b3219fdd9fbba5679f29901091cc913c5a63056c9ff0558df0acf574e9f52e05e1a"
    ut= "040715065fc621457974f20c976a1bcd7795e25b89c599a626d2e71afa231386bb081d5cb5586b481b3035d3ac0b6bd7dedbb6fa6aef855a9baf92992c4338bbb7"

    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockPass2Value = "3e4519917c611339c7d0c509a9eede9c6cd5a980aefb4bc0ebacc8b2a9a47243"
    y = "1d0ea8985f8dce746d5d504cbf1f90349739ba14dece6e8efa5a1e395c877799"

    http_server.storage.add(stage="pass1", mpinId=mpinId, u=u, ut=ut, y=y)
    mockLog = mocker.Mock()
    mockWarnLog = mocker.Mock()
    with mocker.patch("rps.secrets.generate_auth_ott", return_value=mockPass2Value), mock.patch.object(rps.log, "info", mockLog), mock.patch.object(rps.log, "warn", mockWarnLog):
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
        assert responseJson["pass"] == 2
        assert responseJson["authOTT"] == mockPass2Value

        mockLog.assert_called_with("200 POST {0}/pass2 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, "", "").decode("utf-8"))
        mockWarnLog.assert_called_with("{0}/pass2 127.0.0.1  {1} {2} {3} fail to get userID unknown".format(baseURL, mpinId, "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_Pass2HandlerPass1Invalid(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c2022757365724944223a2022726f6f74406c6f63616c686f73742e6c6f63616c646f6d61696e222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    wid = "7684363"
    v = "0418b36ec021ba3fc7c62f25642011bd231a768a828a2db4ceda0178e88a206d1b1248add9b3e5c3a87f2ef591ef52f43a024c1230760f598a75a4d58d32e8440a"
    otp = 0
    body = {
        "mpin_id":mpinId,
        "WID": wid,
        "V": v,
        "OTP": otp,
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/pass2".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/pass2 127.0.0.1  {1} {2} {3} Invalid pass one data unknown".format(baseURL, mpinId, "root@localhost.localdomain", "").decode("utf-8"))
