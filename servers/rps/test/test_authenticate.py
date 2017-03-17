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
def test_AuthenticateHandler(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    body = {
        "authOTT": authOTT,
    }

    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/authenticate".format(base_url),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    message = "Authentication successful"
    userId = "root@localhost"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    authToken = {
        "mpin_id" : mpinId.decode("hex")
    }

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authToken=authToken, authOTT=authOTT,status=200,message="Authentication successful")
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)
        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

        responseJson = json.loads(response.body)
        assert responseJson["message"] == message
        assert responseJson["userId"] == userId
        assert responseJson["mpinId"] == mpinId

        mockLog.assert_called_with("200 POST /authenticate 127.0.0.1 {0} {1} {2} {3}".format(xForwardedFor, mpinId, userId, "").decode("utf-8"))

@pytest.mark.gen_test
def test_AuthenticateHandlerJsonError(http_client, base_url, mocker):
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/authenticate".format(base_url),
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

            mockLog.assert_called_with("/authenticate 127.0.0.1 {0} {1} {2} {3} Cannot decode body as JSON. {4}".format(xForwardedFor, "", "", "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_AuthenticateHandlerJsonErrorUserAgentEmpty(http_client, base_url, mocker):

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/authenticate".format(base_url),
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

            mockLog.assert_called_with("/authenticate 127.0.0.1  {0} {1} {2} Cannot decode body as JSON. {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_AuthenticateHandlerContainOptionalKey(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    body = {
        "authOTT": authOTT,
        "logoutData": "logoutData",
        "logoutURL": "http://1testtest.test.test"
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/authenticate".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    message = "Authentication successful"
    userId = "root@localhost"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    authToken = {
        "mpin_id" : mpinId.decode("hex")
    }

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authToken=authToken, authOTT=authOTT,status=200,message="Authentication successful")
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)
        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

        responseJson = json.loads(response.body)
        assert responseJson["message"] == message
        assert responseJson["userId"] == userId
        assert responseJson["mpinId"] == mpinId

        mockLog.assert_called_with("200 POST /authenticate 127.0.0.1  {0} {1} {2}".format(mpinId, userId, "").decode("utf-8"))

@pytest.mark.gen_test
def test_AuthenticateHandlerCapital(http_client, base_url, mocker):
    authOTT = "9F86d081884c7d659A2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    body = {
        "authOTT": authOTT,
        "logoutData": "logoutData",
        "logoutURL": "http://testtest.test.test"
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/authenticate".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    message = "Authentication successful"
    userId = "root@localhost"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    authToken = {
        "mpin_id" : mpinId.decode("hex")
    }

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authToken=authToken, authOTT=authOTT,status=200,message="Authentication successful")
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)
        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

        responseJson = json.loads(response.body)
        assert responseJson["message"] == message
        assert responseJson["userId"] == userId
        assert responseJson["mpinId"] == mpinId

        mockLog.assert_called_with("200 POST /authenticate 127.0.0.1  {0} {1} {2}".format(mpinId, userId, "").decode("utf-8"))

@pytest.mark.gen_test
def test_AuthenticateHandlerUnnessesaryKeyError(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    body = {
        "unnecessaryKey":"test",
        "authOTT": authOTT,
        "logoutData": "logoutData",
        "logoutURL": "logoutURL"
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/authenticate".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    message = "Authentication successful"
    userId = "root@localhost"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    authToken = {
        "mpin_id" : mpinId.decode("hex")
    }

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authToken=authToken, authOTT=authOTT,status=200,message="Authentication successful")
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("/authenticate 127.0.0.1  {0} {1} {2} Invalid data received. unnecessaryKey argument unnecessary {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_AuthenticateHandlerAuthOTTKeyError(http_client, base_url, mocker):
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    body = {
        "logoutData": "logoutData",
        "logoutURL": "logoutURL"
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/authenticate".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    message = "Authentication successful"
    userId = "root@localhost"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    authToken = {
        "mpin_id" : mpinId.decode("hex")
    }

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authToken=authToken, authOTT=authOTT,status=200,message="Authentication successful")
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("/authenticate 127.0.0.1  {0} {1} {2} Invalid JSON data structure {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_AuthenticateHandlerAuthOTTKeyErrorUserAgentEmpty(http_client, base_url, mocker):

    body = {
        "logoutData": "logoutData"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/authenticate".format(base_url),
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

            mockLog.assert_called_with("/authenticate 127.0.0.1  {0} {1} {2} Invalid JSON data structure {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_AuthenticateHandlerAuthOTTInvalidLength65Error(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08f"
    body = {
        "authOTT": authOTT,
        "logoutData": "logoutData",
        "logoutURL": "logoutURL"
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/authenticate".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    message = "Authentication successful"
    userId = "root@localhost"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    authToken = {
        "mpin_id" : mpinId.decode("hex")
    }

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authToken=authToken, authOTT=authOTT,status=200,message="Authentication successful")
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("/authenticate 127.0.0.1  {0} {1} {2} Invalid data received. authOTT argument invalid length {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_AuthenticateHandlerAuthOTTInvalidLength63Error(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a0"
    body = {
        "authOTT": authOTT,
        "logoutData": "logoutData",
        "logoutURL": "logoutURL"
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/authenticate".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    message = "Authentication successful"
    userId = "root@localhost"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    authToken = {
        "mpin_id" : mpinId.decode("hex")
    }

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authToken=authToken, authOTT=authOTT,status=200,message="Authentication successful")
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("/authenticate 127.0.0.1  {0} {1} {2} Invalid data received. authOTT argument invalid length {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_AuthenticateHandlerAuthOTTInvalidCharacterFullError(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a0Ａ"
    body = {
        "authOTT": authOTT,
        "logoutData": "logoutData",
        "logoutURL": "logoutURL"
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/authenticate".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    message = "Authentication successful"
    userId = "root@localhost"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    authToken = {
        "mpin_id" : mpinId.decode("hex")
    }

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authToken=authToken, authOTT=authOTT,status=200,message="Authentication successful")
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("/authenticate 127.0.0.1  {0} {1} {2} Invalid data received. authOTT argument contains invalid characters {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_AuthenticateHandlerAuthOTTInvalidCharacterNotHexError(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a0g"
    body = {
        "authOTT": authOTT,
        "logoutData": "logoutData",
        "logoutURL": "logoutURL"
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/authenticate".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    message = "Authentication successful"
    userId = "root@localhost"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    authToken = {
        "mpin_id" : mpinId.decode("hex")
    }

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authToken=authToken, authOTT=authOTT,status=200,message="Authentication successful")
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("/authenticate 127.0.0.1  {0} {1} {2} Invalid data received. authOTT argument contains invalid characters {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_AuthenticateHandlerAuthOTTInvalidCharacterNotHexCapitalError(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a0G"
    body = {
        "authOTT": authOTT,
        "logoutData": "logoutData",
        "logoutURL": "logoutURL"
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/authenticate".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    message = "Authentication successful"
    userId = "root@localhost"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    authToken = {
        "mpin_id" : mpinId.decode("hex")
    }

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authToken=authToken, authOTT=authOTT,status=200,message="Authentication successful")
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("/authenticate 127.0.0.1  {0} {1} {2} Invalid data received. authOTT argument contains invalid characters {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_AuthenticateHandlerAuthOTTInvalidCharacterSymbolsError(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a0/"
    body = {
        "authOTT": authOTT,
        "logoutData": "logoutData",
        "logoutURL": "logoutURL"
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/authenticate".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    message = "Authentication successful"
    userId = "root@localhost"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    authToken = {
        "mpin_id" : mpinId.decode("hex")
    }

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authToken=authToken, authOTT=authOTT,status=200,message="Authentication successful")
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("/authenticate 127.0.0.1  {0} {1} {2} Invalid data received. authOTT argument contains invalid characters {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_AuthenticateHandlerLogoutURLInvalidCharacterFullError(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    body = {
        "authOTT": authOTT,
        "logoutData": "logoutData",
        "logoutURL": "logoutURLＡ"
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/authenticate".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )

    message = "Authentication successful"
    userId = "root@localhost"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    authToken = {
        "mpin_id" : mpinId.decode("hex")
    }

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authToken=authToken, authOTT=authOTT,status=200,message="Authentication successful")
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("/authenticate 127.0.0.1  {0} {1} {2} Invalid data received. logoutURL argument contains invalid characters {3}".format("", "", "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_AuthenticateHandlerAuthOTTExpired(http_client, base_url, mocker):
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    body = {
        "authOTT": authOTT,
        "logoutData": "logoutData"
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/authenticate".format(base_url),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )
    message = "Expired authentication request"
    userId = ""
    mpinId = ""

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockWarnLog = mocker.Mock()
    mockErrLog = mocker.Mock()
    http_server.storage.add(stage="auth", expire_time="2000-04-01T12:00:00", authOTT=authOTT)
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "warn", mockWarnLog), mock.patch.object(rps.log, "error", mockErrLog):
        try:
            response = yield http_client.fetch(request)
            assert False

        except rps.tornado.httpclient.HTTPError as e:

            assert e.response.code == 408
            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            responseJson = json.loads(e.response.body)
            assert responseJson["message"] == message
            assert responseJson["userId"] == userId
            assert responseJson["mpinId"] == mpinId

            mockErrLog.assert_called_with("/authenticate 127.0.0.1 {0} {1} {2} {3} Invalid or expired authOTT: {4} {5}".format(xForwardedFor, mpinId, userId, "", authOTT, userAgent).decode("utf-8"))
            mockWarnLog.assert_called_with("/authenticate 127.0.0.1 {0} {1} {2} {3} Wrong PIN. {4}".format(xForwardedFor, mpinId, userId, "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_AuthenticateHandlerAuthOTTExpiredUserAgentEmpty(http_client, base_url, mocker):
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    body = {
        "authOTT": authOTT,
        "logoutData": "logoutData"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/authenticate".format(base_url),
        "POST",
        None,
        json.dumps(body)
    )
    message = "Expired authentication request"
    userId = ""
    mpinId = ""
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockWarnLog = mocker.Mock()
    mockErrLog = mocker.Mock()
    http_server.storage.add(stage="auth", expire_time="2000-04-01T12:00:00", authOTT=authOTT)
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.log, "warn", mockWarnLog), mock.patch.object(rps.log, "error", mockErrLog):
        try:
            response = yield http_client.fetch(request)
            assert False

        except rps.tornado.httpclient.HTTPError as e:

            assert e.response.code == 408
            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            responseJson = json.loads(e.response.body)
            assert responseJson["message"] == message
            assert responseJson["userId"] == userId
            assert responseJson["mpinId"] == mpinId

            mockErrLog.assert_called_with("/authenticate 127.0.0.1  {0} {1} {2} Invalid or expired authOTT: {3} {4}".format(mpinId, userId, "", authOTT, "unknown").decode("utf-8"))
            mockWarnLog.assert_called_with("/authenticate 127.0.0.1  {0} {1} {2} Wrong PIN. {3}".format(mpinId, userId, "", "unknown").decode("utf-8"))
