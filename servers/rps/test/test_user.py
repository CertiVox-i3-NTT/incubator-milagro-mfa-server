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
def test_UserHandler(http_client, base_url, mocker):
    activateKey = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    body = {
        "activateKey": activateKey
    }
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    xForwardedFor = "127.0.0.1"

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/user/{1}".format(base_url,mpinId),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    http_server.storage.add(stage="register", mpinId=mpinId)

    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)
        assert response.code == 200

        I = http_server.storage.find(stage="register", mpinId=mpinId)
        assert I.mpinId == mpinId

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

        mockLog.assert_called_with("200 POST /user/{0} 127.0.0.1 {1} {2} {3} {4}".format(mpinId, xForwardedFor, mpinId, "root@localhost", "").decode("utf-8"))

@pytest.mark.gen_test
def test_UserHandlerCapital(http_client, base_url, mocker):
    activateKey = "9F86d081884c7d659A2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    body = {
        "activateKey": activateKey
    }
    mpinId = "7b226d6F62696c65223A20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/user/{1}".format(base_url,mpinId),
        "POST",
        None,
        json.dumps(body)
    )

    http_server.storage.add(stage="register", mpinId=mpinId)

    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)
        assert response.code == 200

        I = http_server.storage.find(stage="register", mpinId=mpinId)
        assert I.mpinId == mpinId

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

        mockLog.assert_called_with("200 POST /user/{0} 127.0.0.1  {1} {2} {3}".format(mpinId, mpinId, "root@localhost", "").decode("utf-8"))

@pytest.mark.gen_test
def test_UserHandlerUnnecessaryKeyError(http_client, base_url, mocker):
    activateKey = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    body = {
        "unnecessaryKey":"test",
        "activateKey": activateKey
    }
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/user/{1}".format(base_url,mpinId),
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

            mockLog.assert_called_with("/user/{0} 127.0.0.1 {1} {2} {3} {4} Invalid data received. unnecessaryKey argument unnecessary {5}".format(mpinId, xForwardedFor, mpinId, "root@localhost", "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_UserHandlerActivateKeyError(http_client, base_url, mocker):
    activateKey = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08f"
    body = {
    }
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/user/{1}".format(base_url,mpinId),
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

            mockLog.assert_called_with("/user/{0} 127.0.0.1 {1} {2} {3} {4} Invalid data received. activateKey argument missing {5}".format(mpinId, xForwardedFor, mpinId, "root@localhost", "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_UserHandlerActivateKeyInvalidLength65Error(http_client, base_url, mocker):
    activateKey = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08f"
    body = {
        "activateKey": activateKey
    }
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/user/{1}".format(base_url,mpinId),
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

            mockLog.assert_called_with("/user/{0} 127.0.0.1  {1} {2} {3} Invalid data received. activateKey argument invalid length unknown".format(mpinId, mpinId, "root@localhost", "").decode("utf-8"))

@pytest.mark.gen_test
def test_UserHandlerActivateKeyInvalidLength63Error(http_client, base_url, mocker):
    activateKey = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a0"
    body = {
        "activateKey": activateKey
    }
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/user/{1}".format(base_url,mpinId),
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

            mockLog.assert_called_with("/user/{0} 127.0.0.1  {1} {2} {3} Invalid data received. activateKey argument invalid length unknown".format(mpinId, mpinId, "root@localhost", "").decode("utf-8"))

@pytest.mark.gen_test
def test_UserHandlerActivateKeyInvalidCharacterFullError(http_client, base_url, mocker):
    activateKey = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a0Ａ"
    body = {
        "activateKey": activateKey
    }
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/user/{1}".format(base_url,mpinId),
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

            mockLog.assert_called_with("/user/{0} 127.0.0.1  {1} {2} {3} Invalid data received. activateKey argument contains invalid characters unknown".format(mpinId, mpinId, "root@localhost", "").decode("utf-8"))

@pytest.mark.gen_test
def test_UserHandlerActivateKeyInvalidCharacterNotHexError(http_client, base_url, mocker):
    activateKey = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a0g"
    body = {
        "activateKey": activateKey
    }
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/user/{1}".format(base_url,mpinId),
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

            mockLog.assert_called_with("/user/{0} 127.0.0.1  {1} {2} {3} Invalid data received. activateKey argument contains invalid characters unknown".format(mpinId, mpinId, "root@localhost", "").decode("utf-8"))

@pytest.mark.gen_test
def test_UserHandlerActivateKeyInvalidCharacterNotHexCapitalError(http_client, base_url, mocker):
    activateKey = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a0G"
    body = {
        "activateKey": activateKey
    }
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/user/{1}".format(base_url,mpinId),
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

            mockLog.assert_called_with("/user/{0} 127.0.0.1  {1} {2} {3} Invalid data received. activateKey argument contains invalid characters unknown".format(mpinId, mpinId, "root@localhost", "").decode("utf-8"))

@pytest.mark.gen_test
def test_UserHandlerActivateKeyInvalidCharacterSymbolsError(http_client, base_url, mocker):
    activateKey = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a0/"
    body = {
        "activateKey": activateKey
    }
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/user/{1}".format(base_url,mpinId),
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

            mockLog.assert_called_with("/user/{0} 127.0.0.1  {1} {2} {3} Invalid data received. activateKey argument contains invalid characters unknown".format(mpinId, mpinId, "root@localhost", "").decode("utf-8"))

@pytest.mark.gen_test
def test_UserHandlerMpinIdEmptyError(http_client, base_url, mocker):
    activateKey = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    body = {
        "activateKey": activateKey
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/user{1}".format(base_url,""),
        "POST",
        None,
        json.dumps(body)
    )


    try:
        response = yield http_client.fetch(request)
        assert False
    except rps.tornado.httpclient.HTTPError as e:
        assert e.code == 404

        assert e.message == "HTTP 404: URI NOT FOUND"
        assert e.response.headers.get("Access-Control-Allow-Origin") == None
        assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

@pytest.mark.gen_test
def test_UserHandlerMpinIdInvalidLengthError(http_client, base_url, mocker):
    activateKey = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    body = {
        "activateKey": activateKey
    }
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227da"

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/user/{1}".format(base_url,mpinId),
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

            mockLog.assert_called_with("/user/{0} 127.0.0.1  {1} {2} {3} Invalid data received. mpinId argument invalid length unknown".format(mpinId, mpinId, "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_UserHandlerMpinIdInvalidCharacterFullError(http_client, base_url, mocker):
    activateKey = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    body = {
        "activateKey": activateKey
    }
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227Ａ"

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/user/{1}".format(base_url,mpinId),
        "POST",
        None,
        json.dumps(body)
    )

    try:
        response = yield http_client.fetch(request)
        assert False
    except rps.tornado.httpclient.HTTPError as e:
        assert e.code == 404

        assert e.message == "HTTP 404: URI NOT FOUND"
        assert e.response.headers.get("Access-Control-Allow-Origin") == None
        assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

@pytest.mark.gen_test
def test_UserHandlerMpinIdInvalidCharacterNotHexError(http_client, base_url, mocker):
    activateKey = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    body = {
        "activateKey": activateKey
    }
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227g"

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/user/{1}".format(base_url,mpinId),
        "POST",
        None,
        json.dumps(body)
    )

    try:
        response = yield http_client.fetch(request)
        assert False
    except rps.tornado.httpclient.HTTPError as e:
        assert e.code == 404

        assert e.message == "HTTP 404: URI NOT FOUND"
        assert e.response.headers.get("Access-Control-Allow-Origin") == None
        assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

@pytest.mark.gen_test
def test_UserHandlerMpinIdInvalidCharacterNotHexCapitalError(http_client, base_url, mocker):
    activateKey = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    body = {
        "activateKey": activateKey
    }
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227G"

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/user/{1}".format(base_url,mpinId),
        "POST",
        None,
        json.dumps(body)
    )

    try:
        response = yield http_client.fetch(request)
        assert False
    except rps.tornado.httpclient.HTTPError as e:
        assert e.code == 404

        assert e.message == "HTTP 404: URI NOT FOUND"
        assert e.response.headers.get("Access-Control-Allow-Origin") == None
        assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

@pytest.mark.gen_test
def test_UserHandlerMpinIdInvalidCharacterSymbolsError(http_client, base_url, mocker):
    activateKey = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a0/"
    body = {
        "activateKey": activateKey
    }
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227/"

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/user/{1}".format(base_url,mpinId),
        "POST",
        None,
        json.dumps(body)
    )

    try:
        response = yield http_client.fetch(request)
        assert False
    except rps.tornado.httpclient.HTTPError as e:
        assert e.code == 404

        assert e.message == "HTTP 404: URI NOT FOUND"
        assert e.response.headers.get("Access-Control-Allow-Origin") == None
        assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

@pytest.mark.gen_test
def test_UserHandlerRequestBodyJsonError(http_client, base_url, mocker):
    activateKey = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/user/{1}".format(base_url,mpinId),
        "POST",
        None,
        "jsonError"
    )

    http_server.storage.add(stage="register", mpinId=mpinId)

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

            mockLog.assert_called_with("/user/{0} 127.0.0.1  {1} {2} {3} Invalid JSON request: jsonError unknown".format(mpinId, mpinId, "root@localhost", "").decode("utf-8"))

@pytest.mark.gen_test
def test_UserHandlerUserGetError(http_client, base_url, mocker):
    activateKey = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    body = {
        "activateKey": activateKey
    }
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}/user/{1}".format(base_url,mpinId),
        "POST",
        None,
        json.dumps(body)
    )

    http_server.storage.add(stage="register", mpinId=mpinId)

    mockLog = mocker.Mock()
    mockWarnLog = mocker.Mock()
    with mock.patch.object(rps.log, "info", mockLog), mock.patch.object(rps.log, "warn", mockWarnLog):
        response = yield http_client.fetch(request)
        assert response.code == 200

        I = http_server.storage.find(stage="register", mpinId=mpinId)
        assert I.mpinId == mpinId

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        mockLog.assert_called_with("200 POST /user/{0} 127.0.0.1  {1} {2} {3}".format(mpinId, mpinId, "", "").decode("utf-8"))
        mockWarnLog.assert_called_with("/user/{0} 127.0.0.1  {1} {2} {3} fail to get userID unknown".format(mpinId, mpinId, "", "").decode("utf-8"))
