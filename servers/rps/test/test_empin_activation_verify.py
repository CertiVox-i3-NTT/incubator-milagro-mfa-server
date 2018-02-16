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
    DTA Backup Server Key : {"ciphertext": "cb32284ec3c6abce7f996486c689974b93834a63d9056abf09d5ce02f0d54083", "tag": "4bd72e6dd92003114f44fecb7ee3d095", "startTime": "2016-10-26T02:18:06Z", "IV": "0738ea4ab92331de7f73e371"
    '''

    with mock.patch.object(rps.options.mockable(), "EntropySources", "dev_urandom:100".decode("utf-8")), mock.patch("rps.secrets.ServerSecret._get_server_secret", return_value="0cccc683768027e33eca50e19c703f7ba4b4d8dbf9641d442e1599ec4618e51212f05d93383b4d211e5318d5a0ed5678311bd2bf8a1bf5f052d28c9d02c50b641586f306074e0b67ee1bc43d586f742fade452fcf1cdeaf25ce3099f0447085c1ebbecba449442aa66123ab7e29783fae6c35a11bcc412f60869d6dc15e01ed0".decode("hex")):
        global http_server
        http_server = rps.Application()

        return http_server

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandler(http_client, base_url, mocker):
    baseURL = "/rps"

    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030343a31363a32322e353138313933222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227d"
    body = {
        "MpinId": mpinId,
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b98216",
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24f"
    }
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        responseJson = json.loads(response.body)
        assert responseJson["version"] == "0.3"
        assert responseJson["result"] == True
        assert responseJson["message"] == "eMpin Activation is valid."

        mockLog.assert_called_with("200 POST {0}/eMpinActivationVerify 127.0.0.1 {1} {2} {3} {4}".format(baseURL, xForwardedFor, mpinId, "root@localhost", "").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerDelAttemptsCount(http_client, base_url, mocker):
    baseURL = "/rps"

    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030343a31363a32322e353138313933222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227d"

    body = {
        "MpinId": mpinId,
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b98216",
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24f"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    http_server.storage.add(stage="empin-auth-attempts", mpinId=mpinId.decode("hex"), attemptsCount=rps.options.maxInvalidLoginAttempts - 1)
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"
        attempts = http_server.storage.find(stage="empin-auth-attempts", mpinId=mpinId.decode("hex"))
        assert attempts == None
        responseJson = json.loads(response.body)
        assert responseJson["version"] == "0.3"
        assert responseJson["result"] == True
        assert responseJson["message"] == "eMpin Activation is valid."

        mockLog.assert_called_with("200 POST {0}/eMpinActivationVerify 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, "root@localhost", "").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerJsonError(http_client, base_url, mocker):
    baseURL = "/rps"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    jsonError = "jsonError"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        jsonError
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Invalid data received. No JSON object could be decoded"

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, "", "", "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerJsonErrorUserAgentEmpty(http_client, base_url, mocker):
    baseURL = "/rps"

    jsonError = "jsonError"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
        "POST",
        None,
        jsonError
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Invalid data received. No JSON object could be decoded"

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1  {1} {2} {3} {4} {5}".format(baseURL, "", "", "", responseJson["message"], "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerKeyError(http_client, base_url, mocker):
    baseURL = "/rps"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b98216",
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24f"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
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
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Invalid data received. MpinId argument missing"

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, "", "", "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerKeyErrorUserAgentEmpty(http_client, base_url, mocker):
    baseURL = "/rps"

    body = {
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b98216",
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24f"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
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
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Invalid data received. MpinId argument missing"

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1  {1} {2} {3} {4} {5}".format(baseURL, "", "", "", responseJson["message"], "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerDecodeErrorUserAgentEmpty(http_client, base_url, mocker):
    baseURL = "/rps"

    body = {
        "MpinId": "decodeError",
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b98216",
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24f"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
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
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Invalid data received. Odd-length string"

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1  {1} {2} {3} {4} {5}".format(baseURL, "decodeError", "", "", responseJson["message"], "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerMaxAttemptsCountError(http_client, base_url, mocker):
    baseURL = "/rps"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030343a31363a32322e353138313933222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227d"
    userId = "root@localhost"

    body = {
        "MpinId": mpinId,
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b98216",
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24f"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    http_server.storage.add(stage="empin-auth-attempts", mpinId=mpinId.decode('hex'), attemptsCount=rps.options.maxInvalidLoginAttempts)
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 410

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Activation code attempts count is the limit."

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerMaxAttemptsCountErrorUserAgentEmpty(http_client, base_url, mocker):
    baseURL = "/rps"

    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030343a31363a32322e353138313933222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227d"
    userId = "root@localhost"

    body = {
        "MpinId": mpinId,
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b98216",
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24f"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    http_server.storage.add(stage="empin-auth-attempts", mpinId=mpinId.decode('hex'), attemptsCount=rps.options.maxInvalidLoginAttempts)
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 410

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Activation code attempts count is the limit."

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1  {1} {2} {3} {4} {5}".format(baseURL, mpinId, userId, "", responseJson["message"], "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerVerifError(http_client, base_url, mocker):
    baseURL = "/rps"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030343a31363a32322e353138313933222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227d"
    userId = "root@localhost"

    body = {
        "MpinId": mpinId,
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b9821d",
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24f"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
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
            assert e.response.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["result"] == False
            assert responseJson["message"] == "Invalid signature received."

            attempts = http_server.storage.find(stage="empin-auth-attempts", mpinId=mpinId.decode('hex'))
            assert attempts.attemptsCount == 1

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerVerifErrorUserAgentEmpty(http_client, base_url, mocker):
    baseURL = "/rps"

    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030343a31363a32322e353138313933222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227d"
    userId = "root@localhost"

    body = {
        "MpinId": mpinId,
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b9821d",
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24f"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
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
            assert e.response.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["result"] == False
            assert responseJson["message"] == "Invalid signature received."

            attempts = http_server.storage.find(stage="empin-auth-attempts", mpinId=mpinId.decode('hex'))
            assert attempts.attemptsCount == 1

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1  {1} {2} {3} {4} {5}".format(baseURL, mpinId, userId, "", responseJson["message"], "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerVerifMaxAttemptsCountError(http_client, base_url, mocker):
    baseURL = "/rps"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030343a31363a32322e353138313933222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227d"
    userId = "root@localhost"

    body = {
        "MpinId": mpinId,
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b9821d",
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24f"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    http_server.storage.add(stage="empin-auth-attempts", mpinId=mpinId.decode('hex'), attemptsCount=rps.options.maxInvalidLoginAttempts - 1)
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 410

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Activation code attempts count is the limit."

            attempts = http_server.storage.find(stage="empin-auth-attempts", mpinId=mpinId.decode('hex'))
            assert attempts.attemptsCount == rps.options.maxInvalidLoginAttempts

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerVerifMaxAttemptsCountErrorUserAgentEmpty(http_client, base_url, mocker):
    baseURL = "/rps"

    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030343a31363a32322e353138313933222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227d"
    userId = "root@localhost"

    body = {
        "MpinId": mpinId,
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b9821d",
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24f"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    http_server.storage.add(stage="empin-auth-attempts", mpinId=mpinId.decode('hex'), attemptsCount=rps.options.maxInvalidLoginAttempts - 1)
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 410

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Activation code attempts count is the limit."

            attempts = http_server.storage.find(stage="empin-auth-attempts", mpinId=mpinId.decode('hex'))
            assert attempts.attemptsCount == rps.options.maxInvalidLoginAttempts

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1  {1} {2} {3} {4} {5}".format(baseURL, mpinId, userId, "", responseJson["message"], "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerMPinIdMax(http_client, base_url, mocker):
    baseURL = "/rps"

    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d32392030363a30323a32392e363036333235222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227d"
    body = {
        "MpinId": mpinId,
        "U": "040c3fddd552a9f43609e38c753ccacd90c33918dfd4d384b18b0b5dfe8cd3b13b03ded4c0e84371040646fee2f4874faf217d0b7a23dfb07a1db039fc3ca3b128",
        "V": "04087cebf95b3eb8a39d903b8409165cfbb9469ae7e89dea8a4874288e392de19213da371750f4de522760bfeec29397dc35652858772981c176f64bbd7a1bc1d2"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        responseJson = json.loads(response.body)
        assert responseJson["version"] == "0.3"
        assert responseJson["result"] == True
        assert responseJson["message"] == "eMpin Activation is valid."

        mockLog.assert_called_with("200 POST {0}/eMpinActivationVerify 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, "root@localhost", "").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerMPinIdMin(http_client, base_url, mocker):
    baseURL = "/rps"

    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d32392030363a30353a32322e383839303137222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20223030303030303030303030303030303030303030303030303030303030303030227d"
    body = {
        "MpinId": mpinId,
        "U": "042364c49be5bc14d3d62d312d3635f497cc2f05ae00724f34beb69974b6667046123fd4d45edd41965ce8ded2ca7ad1c38fc6452c06886bd87ea86ec253bfc118",
        "V": "0415c28b0973bd2f699be755df4f898673839d588ef0c041386ff84aee9b98430807afcc5fb9dba638d487efe0aeb141906834e3baf5fd509a35d65f25ea99713d"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        responseJson = json.loads(response.body)
        assert responseJson["version"] == "0.3"
        assert responseJson["result"] == True
        assert responseJson["message"] == "eMpin Activation is valid."

        mockLog.assert_called_with("200 POST {0}/eMpinActivationVerify 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, "root@localhost", "").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerXValueMax(http_client, base_url, mocker):
    baseURL = "/rps"

    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30312030393a34323a35362e363337393135222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20223561323836336333376630633832373463623039636632366238666262623462227d"
    body = {
        "MpinId": mpinId,
        "U": "0419ec15f9bb5061b0a5f6a969ec287f6d68ce5d4ddf2267ef431e6d4b849ba58c15e1c1633507417698d2851eba6934c16bcc75757bb977d51a10f4063570ee1a",
        "V": "040d63cbfcb6a5d9b0a7a2766c2ab91f7dd1a3a2ea02ca4baca1510a3b95bdaba60e81d782dc751a2ead1155957866bc5da665ba57a8102d367a5fe2494d437be6"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        responseJson = json.loads(response.body)
        assert responseJson["version"] == "0.3"
        assert responseJson["result"] == True
        assert responseJson["message"] == "eMpin Activation is valid."

        mockLog.assert_called_with("200 POST {0}/eMpinActivationVerify 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, "root@localhost", "").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerXValueMin(http_client, base_url, mocker):
    baseURL = "/rps"

    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030343a33383a30312e313832383530222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20223030303030303030303030303030303030303030303030303030303030303030227d"
    body = {
        "MpinId": mpinId,
        "U": "0415f4dc516e5e6787ee7ffe92a47a462660a56887de260df8f449ba1b8325ab480f565df2fe9a2001dacc7a928ce279f0b130fd01747103c25c03e786fc796760",
        "V": "0423da0a2badfa7120a216d19872a9358ec938aca25778a3a95b4f90ec874f9a26006be88144ed52dbbd61b73a23142c3508f2709bd120894e71701877f54c3060"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        responseJson = json.loads(response.body)
        assert responseJson["version"] == "0.3"
        assert responseJson["result"] == True
        assert responseJson["message"] == "eMpin Activation is valid."

        mockLog.assert_called_with("200 POST {0}/eMpinActivationVerify 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, "root@localhost", "").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerActivationCodeMax(http_client, base_url, mocker):
    baseURL = "/rps"

    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030353a32373a31382e373239343231222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226237636164376366396131666262663262653630656335313930303064343866227d"
    body = {
        "MpinId": mpinId,
        "U": "0421f3b45579ba12dbd0d9cb591f5e396fa7202b41c52b999afd404d198475cfe103d32f7a254c20a12a6687a88271807db345e866b7d595e88e4bea8ec5e9316b",
        "V": "040425cb31a4b17060f06fb778dee18bce96e69b3b9039582234a1409b64240a2d17099c8362318d3f9a8852f7da7e6a3df616ddf39bb179b4e7d816d3731d52fe"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        responseJson = json.loads(response.body)
        assert responseJson["version"] == "0.3"
        assert responseJson["result"] == True
        assert responseJson["message"] == "eMpin Activation is valid."

        mockLog.assert_called_with("200 POST {0}/eMpinActivationVerify 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, "root@localhost", "").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerActivationCodeMin(http_client, base_url, mocker):
    baseURL = "/rps"

    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031372d30312d32302030373a33323a35312e323831313537222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20223963613339626333646232366531326264366534323637373733326263663430227d"
    body = {
        "MpinId": mpinId,
        "U": "040fc020b652106111a4b114f722dfe0e56247989c0a124acc7f7799f67702dba81758b15dc3e12de295b0b86183a3c03c5ddd25695074fbbc471aff1abf1351e6",
        "V": "0400209c437d113a0e721b80bb20d2fc7e80766c7f638bf357091ca2a6c8b1fdb90d9d040ba27a8cd95d4af7f15d3bc1eb3f1a5a849407b115cc095d0b2c2fbf8c"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        responseJson = json.loads(response.body)
        assert responseJson["version"] == "0.3"
        assert responseJson["result"] == True
        assert responseJson["message"] == "eMpin Activation is valid."

        mockLog.assert_called_with("200 POST {0}/eMpinActivationVerify 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, "root@localhost", "").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerCapital(http_client, base_url, mocker):
    baseURL = "/rps"

    mpinId = "7B226D6F62696C65223A20302C2022697373756564223A2022323031362D31322D30322030343A31363A32322E353138313933222C2022757365724944223A2022726F6F74406C6F63616C686F7374222C202273616C74223A20226666666666666666666666666666666666666666666666666666666666666666227D"
    body = {
        "MpinId": mpinId,
        "U": "040c48F778964A3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b98216",
        "V": "0412e06e5b53cAd204b765ee70509797b87208d212F1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24f"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        responseJson = json.loads(response.body)
        assert responseJson["version"] == "0.3"
        assert responseJson["result"] == True
        assert responseJson["message"] == "eMpin Activation is valid."

        mockLog.assert_called_with("200 POST {0}/eMpinActivationVerify 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, "root@localhost", "").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerCapitalError(http_client, base_url, mocker):
    baseURL = "/rps"
    userAgent = "unknown"
    mpinId = "7B226D6F62696C65223A20302C2022697373756564223A2022323031372D30322D30312030333A34333A35322E333939303437222C2022757365724944223A2022726F6F74406C6F63616C686F7374222C202273616C74223A20223036656536633932333033646135366233636231623430666666376534613766227D"
    userId = "root@localhost"
    body = {
        "MpinId": mpinId,
        "U": "041FcA29c0f395a6918434891879c681796a77d05934eafe74e88fcfb48338698a0da510cc7dde415f12e5a262b5aa875a5ad43b0e355840df3b79d95e4a051bc3",
        "V": "0406cb9229eA70a8c80c7cbc14dea48cc6da7130b73039eaceeb8c14ae63b2a0aa1d36166be2046e50794488457834e5bdde0c653Ff7847d8d44d500402bdc9a9d"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
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
            assert e.response.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Invalid signature received."

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1  {1} {2} {3} {4} {5}".format(baseURL, mpinId, userId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerUnnessesaryKeyError(http_client, base_url, mocker):
    baseURL = "/rps"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030343a31363a32322e353138313933222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227d"
    body = {
        "unnecessaryKey":"test",
        "MpinId": mpinId,
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b98216",
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24f"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
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
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Invalid data received. unnecessaryKey argument unnecessary"

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, "", "", "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerUKeyError(http_client, base_url, mocker):
    baseURL = "/rps"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030343a31363a32322e353138313933222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227d"
    userId = "root@localhost"
    body = {
        "MpinId": mpinId,
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24f"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
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
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Invalid data received. U argument missing"

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerVKeyError(http_client, base_url, mocker):
    baseURL = "/rps"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030343a31363a32322e353138313933222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227d"
    userId = "root@localhost"
    body = {
        "MpinId": mpinId,
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b98216"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
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
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Invalid data received. V argument missing"

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerMpinIdInvalidLengthError(http_client, base_url, mocker):
    baseURL = "/rps"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030343a31363a32322e353138313933222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227"
    body = {
        "MpinId": mpinId,
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24f",
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b98216"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
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
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Invalid data received. Odd-length string"

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, "", "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerMpinIdInvalidCharacterFullError(http_client, base_url, mocker):
    baseURL = "/rps"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030343a31363a32322e353138313933222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227dＡ"
    body = {
        "MpinId": mpinId,
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24f",
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b98216"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
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
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Invalid data received. "

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, "", "", "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerMpinIdInvalidCharacterNotHexError(http_client, base_url, mocker):
    baseURL = "/rps"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030343a31363a32322e353138313933222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227g"
    body = {
        "MpinId": mpinId,
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24f",
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b98216"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
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
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Invalid data received. Non-hexadecimal digit found"

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, "", "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerMpinIdInvalidCharacterNotHexCapitalError(http_client, base_url, mocker):
    baseURL = "/rps"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030343a31363a32322e353138313933222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227G"
    body = {
        "MpinId": mpinId,
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24f",
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b98216"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
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
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Invalid data received. Non-hexadecimal digit found"

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, "", "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerMpinIdInvalidCharacterSymbolsError(http_client, base_url, mocker):
    baseURL = "/rps"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030343a31363a32322e353138313933222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227/"
    body = {
        "MpinId": mpinId,
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24f",
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b98216"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
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
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Invalid data received. Non-hexadecimal digit found"

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, "", "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerUInvalidLength131Error(http_client, base_url, mocker):
    baseURL = "/rps"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030343a31363a32322e353138313933222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227d"
    body = {
        "MpinId": mpinId,
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24f",
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b98216f"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
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
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Invalid data received. U argument invalid length"

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, "root@localhost", "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerUInvalidLength129Error(http_client, base_url, mocker):
    baseURL = "/rps"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030343a31363a32322e353138313933222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227d"
    body = {
        "MpinId": mpinId,
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24f",
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b9821"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
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
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Invalid data received. U argument invalid length"

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, "root@localhost", "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerVInvalidLength131Error(http_client, base_url, mocker):
    baseURL = "/rps"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030343a31363a32322e353138313933222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227d"
    body = {
        "MpinId": mpinId,
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24ff",
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b98216"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
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
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Invalid data received. V argument invalid length"

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, "root@localhost", "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerVInvalidLength129Error(http_client, base_url, mocker):
    baseURL = "/rps"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030343a31363a32322e353138313933222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227d"
    body = {
        "MpinId": mpinId,
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24",
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b98216"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
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
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Invalid data received. V argument invalid length"

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, "root@localhost", "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerUInvalidCharacterFullError(http_client, base_url, mocker):
    baseURL = "/rps"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030343a31363a32322e353138313933222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227d"
    userId = "root@localhost"
    body = {
        "MpinId": mpinId,
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24f",
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b9821Ａ"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
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
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Invalid data received. "

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerUInvalidCharacterNotHexError(http_client, base_url, mocker):
    baseURL = "/rps"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030343a31363a32322e353138313933222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227d"
    userId = "root@localhost"
    body = {
        "MpinId": mpinId,
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24f",
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b9821g"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
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
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Invalid data received. Non-hexadecimal digit found"

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerUInvalidCharacterNotHexCapitalError(http_client, base_url, mocker):
    baseURL = "/rps"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030343a31363a32322e353138313933222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227d"
    userId = "root@localhost"
    body = {
        "MpinId": mpinId,
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24f",
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b9821G"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
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
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Invalid data received. Non-hexadecimal digit found"

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerUInvalidCharacterSymbolsError(http_client, base_url, mocker):
    baseURL = "/rps"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030343a31363a32322e353138313933222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227d"
    userId = "root@localhost"
    body = {
        "MpinId": mpinId,
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24f",
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b9821/"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
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
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Invalid data received. Non-hexadecimal digit found"

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerVInvalidCharacterFullError(http_client, base_url, mocker):
    baseURL = "/rps"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030343a31363a32322e353138313933222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227d"
    userId = "root@localhost"
    body = {
        "MpinId": mpinId,
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24Ａ",
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b98216"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
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
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Invalid data received. "

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerVInvalidCharacterNotHexError(http_client, base_url, mocker):
    baseURL = "/rps"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030343a31363a32322e353138313933222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227d"
    userId = "root@localhost"
    body = {
        "MpinId": mpinId,
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24g",
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b98216"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
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
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Invalid data received. Non-hexadecimal digit found"

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerVInvalidCharacterNotHexCapitalError(http_client, base_url, mocker):
    baseURL = "/rps"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030343a31363a32322e353138313933222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227d"
    userId = "root@localhost"
    body = {
        "MpinId": mpinId,
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24G",
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b98216"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
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
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Invalid data received. Non-hexadecimal digit found"

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerVInvalidCharacterSymbolsError(http_client, base_url, mocker):
    baseURL = "/rps"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030343a31363a32322e353138313933222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227d"
    userId = "root@localhost"
    body = {
        "MpinId": mpinId,
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24/",
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b98216"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
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
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Invalid data received. Non-hexadecimal digit found"

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerMpinIdInvalidValueError(http_client, base_url, mocker):
    baseURL = "/rps"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    mpinId = {}

    body = {
        "MpinId": mpinId,
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b9821d",
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24f"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
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
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["message"] == "Invalid data received. Non-hexadecimal digit found"

            mockLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, "", "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationVerifyHandlerUserIDGetError(http_client, base_url, mocker):
    baseURL = "/rps"

    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    body = {
        "MpinId": mpinId,
        "U": "040c48f778964a3eaf54fb44538795ce3df778fd8e29b6583cb73e3d863e3139380f3cfaa9b7f9a48c0ada77bb7da68b7faa94fc46b5af834fd6d6354513b98216",
        "V": "0412e06e5b53cad204b765ee70509797b87208d212f1111e03d6b278db2bbcb8361039b9c389f9c016946de574d3df49aadee883109c14e438c1f1b76f8b14e24f"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivationVerify".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockWarnLog = mocker.Mock()
    mockErrLog = mocker.Mock()
    with mock.patch.object(rps.log, "warn", mockWarnLog), mock.patch.object(rps.log, "error", mockErrLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["version"] == "0.3"
            assert responseJson["result"] == False
            assert responseJson["message"] == "Invalid signature received."

            attempts = http_server.storage.find(stage="empin-auth-attempts", mpinId=mpinId.decode('hex'))
            assert attempts.attemptsCount == 1

            mockWarnLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1  {1} {2} {3} fail to get userID {4}".format(baseURL, mpinId, "", "", "unknown").decode("utf-8"))
            mockErrLog.assert_called_with("{0}/eMpinActivationVerify 127.0.0.1  {1} {2} {3} {4} {5}".format(baseURL, mpinId, "", "", responseJson["message"], "unknown").decode("utf-8"))
