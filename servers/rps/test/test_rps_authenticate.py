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
def test_RPSAuthenticateHandler(http_client, base_url, mocker):
    baseURL = "/rps"

    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    authToken = {
        "mpin_id" : mpinId.decode("hex"),
        "successCode": 0,
        "pinError": 0,
        "expires": "2100-04-01T12:00:00Z"
    }
    userId = "root@localhost"
    logoutURL = "http://test.loguoutURL/"
    logoutData = {"userId" : userId}
    body = {
        "mpinResponse": {
            "authOTT": authOTT
        }
    }

    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/authenticate".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )
    mockLog = mocker.Mock()
    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authOTT=authOTT, authToken=authToken, browserReady=True)
    with mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)
        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

        auth = http_server.storage.find(stage="auth", authOTT=authOTT)
        assert auth == None

        mockLog.assert_called_with("200 POST {0}/authenticate 127.0.0.1 {1} {2} {3} {4}".format(baseURL, xForwardedFor, mpinId, userId, "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSAuthenticateHandlerContainOptionalKey(http_client, base_url, mocker):
    baseURL = "/rps"

    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    authToken = {
        "mpin_id" : mpinId.decode("hex"),
        "successCode": 0,
        "pinError": 0,
        "expires": "2100-04-01T12:00:00Z"
    }
    userId = "root@localhost"
    logoutURL = "http://test.loguoutURL/"
    logoutData = {"userId" : userId}
    body = {
        "mpinResponse": {
            "authOTT": authOTT,
            "version":"version",
            "pass":"pass"
        }
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/authenticate".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authOTT=authOTT, authToken=authToken, browserReady=True)
    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)
        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

        auth = http_server.storage.find(stage="auth", authOTT=authOTT)
        assert auth == None

        mockLog.assert_called_with("200 POST {0}/authenticate 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, userId, "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSAuthenticateHandlerCapital(http_client, base_url, mocker):
    baseURL = "/rps"

    authOTT = "9F86d081884c7d659A2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    authToken = {
        "mpin_id" : mpinId.decode("hex"),
        "successCode": 0,
        "pinError": 0,
        "expires": "2100-04-01T12:00:00Z"
    }
    userId = "root@localhost"
    logoutURL = "http://test.loguoutURL/"
    logoutData = {"userId" : userId}
    body = {
        "mpinResponse": {
            "authOTT": authOTT
        }
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/authenticate".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockLog = mocker.Mock()
    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", authOTT=authOTT, authToken=authToken, browserReady=True)
    with mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)
        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

        auth = http_server.storage.find(stage="auth", authOTT=authOTT)
        assert auth == None

        mockLog.assert_called_with("200 POST {0}/authenticate 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, userId, "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSAuthenticateHandlerMpinResponseKeyError(http_client, base_url, mocker):
    baseURL = "/rps"
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    body = {
    }
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/authenticate".format(base_url,baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

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

            mockLog.assert_called_with("{0}/authenticate 127.0.0.1 {1} {2} {3} {4} Invalid JSON data structure {5}".format(baseURL, xForwardedFor, "", "", "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSAuthenticateHandlerUnnessesaryKeyError(http_client, base_url, mocker):
    baseURL = "/rps"
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    body = {
        "mpinResponse":{
            "unnecessaryKey":"test",
            "authOTT":authOTT,
            "version":"version",
            "pass":"pass"
         },
         "unnecessaryKey":"test"
    }
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/authenticate".format(base_url,baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

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

            mockLog.assert_called_with("{0}/authenticate 127.0.0.1 {1} {2} {3} {4} Invalid data received. unnecessaryKey argument unnecessary {5}".format(baseURL, xForwardedFor, "", "", "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSAuthenticateHandlerMpinResponseUnnessesaryKeyError(http_client, base_url, mocker):
    baseURL = "/rps"
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    body = {
        "mpinResponse":{
            "unnecessaryKey":"test",
            "authOTT":authOTT,
            "version":"version",
            "pass":"pass"
         }
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/authenticate".format(base_url,baseURL),
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
            assert e.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/authenticate 127.0.0.1  {1} {2} {3} Invalid data received. unnecessaryKey argument unnecessary unknown".format(baseURL, "", "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSAuthenticateHandlerAuthOTTKeyError(http_client, base_url, mocker):
    baseURL = "/rps"
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    body = {
        "mpinResponse":{
            "version":"version",
            "pass":"pass"
         }
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/authenticate".format(base_url,baseURL),
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
            assert e.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/authenticate 127.0.0.1  {1} {2} {3} Invalid JSON data structure unknown".format(baseURL, "", "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSAuthenticateHandlerAuthOTTInvalidLength63Error(http_client, base_url, mocker):
    baseURL = "/rps"
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a0"
    body = {
        "mpinResponse":{
            "authOTT":authOTT,
            "version":"version",
            "pass":"pass"
         }
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/authenticate".format(base_url,baseURL),
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
            assert e.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/authenticate 127.0.0.1  {1} {2} {3} Invalid data received. authOTT argument invalid length unknown".format(baseURL, "", "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSAuthenticateHandlerAuthOTTInvalidLength65Error(http_client, base_url, mocker):
    baseURL = "/rps"
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08f"
    body = {
        "mpinResponse":{
            "authOTT":authOTT,
            "version":"version",
            "pass":"pass"
         }
    }
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/authenticate".format(base_url,baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

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

            mockLog.assert_called_with("{0}/authenticate 127.0.0.1 {1} {2} {3} {4} Invalid data received. authOTT argument invalid length {5}".format(baseURL, xForwardedFor, "", "", "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSAuthenticateHandlerAuthOTTInvalidCharacterFullError(http_client, base_url, mocker):
    baseURL = "/rps"
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a0Ａ"
    body = {
        "mpinResponse":{
            "authOTT":authOTT,
            "version":"version",
            "pass":"pass"
         }
    }
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/authenticate".format(base_url,baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

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

            mockLog.assert_called_with("{0}/authenticate 127.0.0.1 {1} {2} {3} {4} Invalid data received. authOTT argument contains invalid characters {5}".format(baseURL, xForwardedFor, "", "", "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSAuthenticateHandlerAuthOTTInvalidCharacterNotHexError(http_client, base_url, mocker):
    baseURL = "/rps"
    authOTT = "9F86d081884c7d659A2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a0g"
    body = {
        "mpinResponse":{
            "authOTT":authOTT,
            "version":"version",
            "pass":"pass"
         }
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/authenticate".format(base_url,baseURL),
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
            assert e.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/authenticate 127.0.0.1  {1} {2} {3} Invalid data received. authOTT argument contains invalid characters unknown".format(baseURL, "", "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSAuthenticateHandlerAuthOTTInvalidCharacterNotHexCapitalError(http_client, base_url, mocker):
    baseURL = "/rps"
    authOTT = "9F86d081884c7d659A2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a0G"
    body = {
        "mpinResponse":{
            "authOTT":authOTT,
            "version":"version",
            "pass":"pass"
         }
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/authenticate".format(base_url,baseURL),
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
            assert e.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/authenticate 127.0.0.1  {1} {2} {3} Invalid data received. authOTT argument contains invalid characters unknown".format(baseURL, "", "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSAuthenticateHandlerAuthOTTInvalidCharacterSymbolsError(http_client, base_url, mocker):
    baseURL = "/rps"
    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a0/"
    body = {
        "mpinResponse":{
            "authOTT":authOTT,
            "version":"version",
            "pass":"pass"
         }
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/authenticate".format(base_url,baseURL),
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
            assert e.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/authenticate 127.0.0.1  {1} {2} {3} Invalid data received. authOTT argument contains invalid characters unknown".format(baseURL, "", "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSAuthenticateHandlerJSONError(http_client, base_url, mocker):
    baseURL = "/rps"

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/authenticate".format(base_url,baseURL),
        "POST",
        None,
        "jsonError"
    )

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

            mockLog.assert_called_with("{0}/authenticate 127.0.0.1  {1} {2} {3} Cannot decode body as JSON. unknown".format(baseURL, "", "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSAuthenticateHandlerOAuthOTTExpired(http_client, base_url, mocker):
    baseURL = "/rps"

    authOTT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    authToken = {
        "mpin_id" : mpinId.decode("hex"),
        "successCode": 0,
        "pinError": 0,
        "expires": "2100-04-01T12:00:00Z"
    }
    userId = "root@localhost"
    body = {
        "mpinResponse": {
            "authOTT": authOTT
        }
    }
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/authenticate".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )
    mockLog = mocker.Mock()
    http_server.storage.add(stage="auth", expire_time="2000-04-01T12:00:00", authOTT=authOTT, authToken=authToken, browserReady=True)
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 412

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            responseJson = json.loads(e.response.body)
            assert responseJson["message"] == "Invalid or expired access number"

            mockLog.assert_called_with("{0}/authenticate 127.0.0.1 {1} {2} {3} {4} Invalid or expired authOTT {5}".format(baseURL, xForwardedFor, "", "", "", userAgent).decode("utf-8"))
