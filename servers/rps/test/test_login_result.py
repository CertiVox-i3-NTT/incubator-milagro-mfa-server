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
    salt :
    DTA Backup Server Key :

    '''

    with mock.patch.object(rps.options.mockable(), "EntropySources", "dev_urandom:100".decode("utf-8")), mock.patch("rps.secrets.ServerSecret._get_server_secret", return_value="019449d771da50bb07d52426d55cbb5a83a0e905e78070bf447930735f5b91681d58c999ddd965fd48f5843742f0d91b3884b3a06577e63052d9d93145c026fa1781eedd973d15838188b3eb8ea82e3b5144465d05797790df6658756cc33dcb1799188be80b52b7ac1546725e6401c6730746987865eea9ba1c9bf34aab3e02".decode("hex")):
        global http_server
        http_server = rps.Application()

        return http_server

@pytest.mark.gen_test
def test_LoginResultHandler(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    userId = "1root@localhost"
    logoutURL = "/logout"
    body = {
        "authOTT": authOTT,
        "status" : 200,
    }

    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/loginResult".format(base_url),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authOTT=authOTT)
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)
        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

        auth = http_server.storage.find(stage="auth", authOTT=authOTT)
        assert auth.logoutData == None
        assert auth.logoutURL == logoutURL
        assert auth.browserReady == True

        mockLog.assert_called_with("200 POST /loginResult 127.0.0.1 {0} {1} {2} {3}".format(xForwardedFor, "", "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_LoginResultHandlerContainOptionalKey(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    userId = "1root@localhost"
    logoutURL = "http://1test.loguoutURL/"
    logoutData = {"userId" : userId}
    body = {
        "authOTT": authOTT,
        "status" : 200,
        "message" : "Test message1/",
        "logoutURL" : logoutURL,
        "logoutData" : logoutData
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/loginResult".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authOTT=authOTT)
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)
        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

        auth = http_server.storage.find(stage="auth", authOTT=authOTT)
        assert auth.logoutData == logoutData
        assert auth.logoutURL == logoutURL
        assert auth.browserReady == True

        mockLog.assert_called_with("200 POST /loginResult 127.0.0.1  {0} {1} {2}".format("", userId, "").decode("utf-8"))

@pytest.mark.gen_test
def test_LoginResultHandlerCapital(http_client, base_url, mocker):
    authOTT = "9F86d081884c7d659a2feAa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    userId = "root@localhost"
    body = {
        "authOTT": authOTT,
        "status" : 200,
        "message" : "message1/",
        "logoutURL" : "http://test.loguoutURL/",
        "logoutData" : {
                    "userId" : userId
                    }
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/loginResult".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authOTT=authOTT)
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)
        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

        mockLog.assert_called_with("200 POST /loginResult 127.0.0.1  {0} {1} {2}".format("", userId, "").decode("utf-8"))

@pytest.mark.gen_test
def test_LoginResultHandlerStatusValidNumber999(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    userId = "1root@localhost"
    status = 999
    message = "test message"
    body = {
        "authOTT": authOTT,
        "status" : status,
        "message": message
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/loginResult".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authOTT=authOTT, message="")
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)
        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

        auth = http_server.storage.find(stage="auth", authOTT=authOTT)
        assert auth.status == status
        assert auth.message == message
        assert auth.browserReady == True

        mockLog.assert_called_with("999 POST /loginResult 127.0.0.1  {0} {1} {2}".format("", "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_LoginResultHandlerStatusValidNumber100(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    userId = "1root@localhost"
    status = 100
    message = "test message"
    body = {
        "authOTT": authOTT,
        "status" : status,
        "message": message

    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/loginResult".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authOTT=authOTT, message="")
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)
        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

        auth = http_server.storage.find(stage="auth", authOTT=authOTT)
        assert auth.status == status
        assert auth.message == message
        assert auth.browserReady == True

        mockLog.assert_called_with("100 POST /loginResult 127.0.0.1  {0} {1} {2}".format("", "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_LoginResultHandlerJsonError(http_client, base_url, mocker):

    xForwardedFor = "127.0.0.1"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/loginResult".format(base_url),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        "jsonError"
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

            mockLog.assert_called_with("/loginResult 127.0.0.1 {0} {1} {2} {3} Cannot decode body as JSON. {4}".format(xForwardedFor, "", "", "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_LoginResultHandlerJsonErrorUserAgentEmpty(http_client, base_url, mocker):

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/loginResult".format(base_url),
        "POST",
        None,
        "jsonError"
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

            mockLog.assert_called_with("/loginResult 127.0.0.1  {0} {1} {2} Cannot decode body as JSON. {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_LoginResultHandlerUnnessesaryKeyError(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    userId = "root@localhost"
    body = {
        "unnecessaryKey":"test",
        "authOTT": authOTT,
        "status" : 200,
        "message" : "message",
        "logoutURL" : "http://test.loguoutURL/",
        "logoutData" : {
                    "userId" : userId
                    }
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/loginResult".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authOTT=authOTT)
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("/loginResult 127.0.0.1  {0} {1} {2} Invalid data received. unnecessaryKey argument unnecessary {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_LoginResultHandlerAuthOTTKeyError(http_client, base_url, mocker):
    userId = "root@localhost"
    body = {
        "status" : 200,
        "message" : "message",
        "logoutURL" : "http://test.loguoutURL/",
        "logoutData" : {
                    "userId" : userId
                    }
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/loginResult".format(base_url),
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

            mockLog.assert_called_with("/loginResult 127.0.0.1  {0} {1} {2} Invalid JSON data structure {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_LoginResultHandlerKeyErrorUserAgentEmpty(http_client, base_url, mocker):
    userId = "root@localhost"
    body = {
        "status" : "200",
        "logoutURL" : "http://test.loguoutURL/",
        "logoutData" : {
                    "userId" : userId
                    }
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/loginResult".format(base_url),
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

            mockLog.assert_called_with("/loginResult 127.0.0.1  {0} {1} {2} Invalid JSON data structure {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_LoginResultHandlerStatusKeyError(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    userId = "root@localhost"
    body = {
        "authOTT": authOTT,
        "message" : "message",
        "logoutURL" : "http://test.loguoutURL/",
        "logoutData" : {
                    "userId" : userId
                    }
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/loginResult".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authOTT=authOTT)
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

            mockLog.assert_called_with("/loginResult 127.0.0.1  {0} {1} {2} Invalid JSON data structure {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_LoginResultHandlerAuthOTTInvalidLength65Error(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08f"
    userId = "root@localhost"
    body = {
        "authOTT": authOTT,
        "status" : 200,
        "message" : "message",
        "logoutURL" : "http://test.loguoutURL/",
        "logoutData" : {
                    "userId" : userId
                    }
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/loginResult".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authOTT=authOTT)
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("/loginResult 127.0.0.1  {0} {1} {2} Invalid data received. authOTT argument invalid length {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_LoginResultHandlerAuthOTTInvalidLength63Error(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a0"
    userId = "root@localhost"
    body = {
        "authOTT": authOTT,
        "status" : 200,
        "message" : "message",
        "logoutURL" : "http://test.loguoutURL/",
        "logoutData" : {
                    "userId" : userId
                    }
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/loginResult".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authOTT=authOTT)
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("/loginResult 127.0.0.1  {0} {1} {2} Invalid data received. authOTT argument invalid length {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_LoginResultHandlerAuthOTTInvalidCharacterFullError(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a0Ａ"
    userId = "root@localhost"
    body = {
        "authOTT": authOTT,
        "status" : 200,
        "message" : "message",
        "logoutURL" : "http://test.loguoutURL/",
        "logoutData" : {
                    "userId" : userId
                    }
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/loginResult".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authOTT=authOTT)
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("/loginResult 127.0.0.1  {0} {1} {2} Invalid data received. authOTT argument contains invalid characters {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_LoginResultHandlerAuthOTTInvalidCharacterNotHexError(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a0g"
    userId = "root@localhost"
    body = {
        "authOTT": authOTT,
        "status" : 200,
        "message" : "message",
        "logoutURL" : "http://test.loguoutURL/",
        "logoutData" : {
                    "userId" : userId
                    }
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/loginResult".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authOTT=authOTT)
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("/loginResult 127.0.0.1  {0} {1} {2} Invalid data received. authOTT argument contains invalid characters {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_LoginResultHandlerAuthOTTInvalidCharacterNotHexCapitalError(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a0G"
    userId = "root@localhost"
    body = {
        "authOTT": authOTT,
        "status" : 200,
        "message" : "message",
        "logoutURL" : "http://test.loguoutURL/",
        "logoutData" : {
                    "userId" : userId
                    }
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/loginResult".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authOTT=authOTT)
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("/loginResult 127.0.0.1  {0} {1} {2} Invalid data received. authOTT argument contains invalid characters {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_LoginResultHandlerAuthOTTInvalidCharacterSymbolsError(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a0/"
    userId = "root@localhost"
    body = {
        "authOTT": authOTT,
        "status" : 200,
        "message" : "message",
        "logoutURL" : "http://test.loguoutURL/",
        "logoutData" : {
                    "userId" : userId
                    }
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/loginResult".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authOTT=authOTT)
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("/loginResult 127.0.0.1  {0} {1} {2} Invalid data received. authOTT argument contains invalid characters {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_LoginResultHandlerStatusInvalidValue(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    userId = "root@localhost"
    body = {
        "authOTT": authOTT,
        "status" : {},
        "message" : "message",
        "logoutURL" : "http://test.loguoutURL/",
        "logoutData" : {
                    "userId" : userId
                    }
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/loginResult".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authOTT=authOTT)
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

            mockLog.assert_called_with("/loginResult 127.0.0.1  {0} {1} {2} Cannot decode body as JSON. {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_LoginResultHandlerStatusInvalidNumber1000Error(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    userId = "root@localhost"
    body = {
        "authOTT": authOTT,
        "status" : 1000,
        "message" : "message",
        "logoutURL" : "http://test.loguoutURL/",
        "logoutData" : {
                    "userId" : userId
                    }
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/loginResult".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authOTT=authOTT)
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("/loginResult 127.0.0.1  {0} {1} {2} Invalid data received. status argument invalid number {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_LoginResultHandlerStatusInvalidNumber99Error(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    userId = "root@localhost"
    body = {
        "authOTT": authOTT,
        "status" : 99,
        "message" : "message",
        "logoutURL" : "http://test.loguoutURL/",
        "logoutData" : {
                    "userId" : userId
                    }
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/loginResult".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authOTT=authOTT)
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("/loginResult 127.0.0.1  {0} {1} {2} Invalid data received. status argument invalid number {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_LoginResultHandlerStatusInvalidCharacterFullError(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    userId = "root@localhost"
    body = {
        "authOTT": authOTT,
        "status" : "ＡＡＡ",
        "message" : "message",
        "logoutURL" : "http://test.loguoutURL/",
        "logoutData" : {
                    "userId" : userId
                    }
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/loginResult".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authOTT=authOTT)
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

            mockLog.assert_called_with("/loginResult 127.0.0.1  {0} {1} {2} Cannot decode body as JSON. {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_LoginResultHandlerStatusInvalidCharacterAlphaError(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    userId = "root@localhost"
    body = {
        "authOTT": authOTT,
        "status" : "aaa",
        "message" : "message",
        "logoutURL" : "http://test.loguoutURL/",
        "logoutData" : {
                    "userId" : userId
                    }
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/loginResult".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authOTT=authOTT)
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

            mockLog.assert_called_with("/loginResult 127.0.0.1  {0} {1} {2} Cannot decode body as JSON. {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_LoginResultHandlerStatusInvalidCharacterSymbolsError(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    userId = "root@localhost"
    body = {
        "authOTT": authOTT,
        "status" : "///",
        "message" : "message",
        "logoutURL" : "http://test.loguoutURL/",
        "logoutData" : {
                    "userId" : userId
                    }
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/loginResult".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authOTT=authOTT)
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

            mockLog.assert_called_with("/loginResult 127.0.0.1  {0} {1} {2} Cannot decode body as JSON. {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_LoginResultHandlerMessageInvalidCharacterFullError(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    userId = "root@localhost"
    body = {
        "authOTT": authOTT,
        "status" : 200,
        "message" : "messageＡ",
        "logoutURL" : "http://test.loguoutURL/",
        "logoutData" : {
                    "userId" : userId
                    }
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/loginResult".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authOTT=authOTT)
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("/loginResult 127.0.0.1  {0} {1} {2} Invalid data received. message argument contains invalid characters {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_LoginResultHandlerLogoutURLInvalidCharacterFullError(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    userId = "root@localhost"
    body = {
        "authOTT": authOTT,
        "status" : 200,
        "message" : "message",
        "logoutURL" : "Ａ",
        "logoutData" : {
                    "userId" : userId
                    }
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/loginResult".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authOTT=authOTT)
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("/loginResult 127.0.0.1  {0} {1} {2} Invalid data received. logoutURL argument contains invalid characters {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_LoginResultHandlerAuthOTTExpired(http_client, base_url, mocker):

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    userId = "root@localhost"
    body = {
        "authOTT": authOTT,
        "status" : "200",
        "logoutURL" : "http://test.loguoutURL/",
        "logoutData" : {
                    "userId" : userId
                    }
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/loginResult".format(base_url),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    http_server.storage.add(stage="auth", expire_time="2000-04-01T12:00:00", authOTT=authOTT)
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False

        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 408

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("/loginResult 127.0.0.1 {0} {1} {2} {3} Invalid or expired authOTT {4}".format(xForwardedFor, "", "", "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_LoginResultHandlerAuthOTTExpiredUserAgentEmpty(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    userId = "root@localhost"
    body = {
        "authOTT": authOTT,
        "status" : "200",
        "logoutURL" : "http://test.loguoutURL/",
        "logoutData" : {
                    "userId" : userId
                    }
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/loginResult".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    http_server.storage.add(stage="auth", expire_time="2000-04-01T12:00:00", authOTT=authOTT)
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False

        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 408

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("/loginResult 127.0.0.1  {0} {1} {2} Invalid or expired authOTT {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_LoginResultHandlerUserIDGetFailed(http_client, base_url, mocker):
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    body = {
        "authOTT": authOTT,
        "status" : "200",
        "logoutURL" : "http://test.loguoutURL/",
        "logoutData" : {
                    }
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/loginResult".format(base_url),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authOTT=authOTT)
    mockLog1 = mocker.Mock()
    mockLog2 = mocker.Mock()
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "info", mockLog1), mock.patch.object(rps.log, "warn", mockLog2):
        response = yield http_client.fetch(request)
        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

        mockLog1.assert_called_with("200 POST /loginResult 127.0.0.1 {0} {1} {2} {3}".format(xForwardedFor, "", "", "").decode("utf-8"))
        mockLog2.assert_called_with("/loginResult 127.0.0.1 {0} {1} {2} {3} fail to get userId {4}".format(xForwardedFor, "", "", "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_LoginResultHandlerUserIDGetFailedUserAgentEmpty(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    body = {
        "authOTT": authOTT,
        "status" : "200",
        "logoutURL" : "http://test.loguoutURL/",
        "logoutData" : {
                    }
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/loginResult".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authOTT=authOTT)
    mockLog1 = mocker.Mock()
    mockLog2 = mocker.Mock()
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "info", mockLog1), mock.patch.object(rps.log, "warn", mockLog2):
        response = yield http_client.fetch(request)
        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

        mockLog1.assert_called_with("200 POST /loginResult 127.0.0.1  {0} {1} {2}".format("", "", "").decode("utf-8"))
        mockLog2.assert_called_with("/loginResult 127.0.0.1  {0} {1} {2} fail to get userId {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_LoginResultHandlerWaitForLoginResultFalse(http_client, base_url, mocker):

    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    userId = "root@localhost"
    body = {
        "authOTT": authOTT,
        "status" : "200",
        "logoutURL" : "http://test.loguoutURL/",
        "logoutData" : {
                    "userId" : userId
                    }
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/loginResult".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    with mock.patch.object(rps.options.mockable(), "waitForLoginResult", False), mocker.patch("rps.Time.syncedNow", return_value=mockTime):
        try:
            response = yield http_client.fetch(request)
            assert False

        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 404

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
