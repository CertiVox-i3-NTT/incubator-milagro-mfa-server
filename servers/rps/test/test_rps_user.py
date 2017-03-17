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

#define("OTTLength", default=16, type=int)

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
def test_RPSUserHandler(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    userId = "root@localhosttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
    body = {
        "userId":userId,
        "regOTT":regOTT,
    }
    xForwardedFor = "127.0.0.1"

    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    forceActivate = False
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    active = 0
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
        rps.tornado.httputil.HTTPHeaders({"X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT)

    mockResponse = {
        "forceActivate": forceActivate
    }
    httpserver.serve_content(json.dumps(mockResponse), 200)

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        responseJson = json.loads(response.body)
        assert response.code == 200

        assert responseJson["mpinId"] == mpinId
        assert responseJson["regOTT"] == regOTT
        assert responseJson["expireTime"] == "2016-04-01T13:00:00.000001"
        assert responseJson["nowTime"] == "2016-04-01T12:00:00.000001"
        assert responseJson["active"] == False

        register = http_server.storage.find(stage="register", mpinId=mpinId)
        assert register.regOTT == regOTT
        assert register._expires == "2016-04-01T13:00:00.000001"
        assert register.active == active

        mockLog.assert_called_with("200 PUT {0}/user/{1} 127.0.0.1 {2} {3} {4} {5}".format(baseURL, mpinId, xForwardedFor, mpinId, userId, "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSUserHandlerContainOptionalKey(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    userId = "root@localhosttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
    body = {
        "userId":userId,
        "regOTT":regOTT,
        "mobile":0,
        "deviceName":"test",
        "userData":"test"
    }

    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    forceActivate = False
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    active = 0
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
        None,
        json.dumps(body)
    )
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT)

    mockResponse = {
        "forceActivate": forceActivate
    }
    httpserver.serve_content(json.dumps(mockResponse), 200)

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        responseJson = json.loads(response.body)
        assert response.code == 200

        assert responseJson["mpinId"] == mpinId
        assert responseJson["regOTT"] == regOTT
        assert responseJson["expireTime"] == "2016-04-01T13:00:00.000001"
        assert responseJson["nowTime"] == "2016-04-01T12:00:00.000001"
        assert responseJson["active"] == False

        register = http_server.storage.find(stage="register", mpinId=mpinId)
        assert register.regOTT == regOTT
        assert register._expires == "2016-04-01T13:00:00.000001"
        assert register.active == active

        mockLog.assert_called_with("200 PUT {0}/user/{1} 127.0.0.1  {2} {3} {4}".format(baseURL, mpinId, mpinId, userId, "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSUserHandlerForceActivateMissing(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    userId = "root@localhosttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
    body = {
        "userId":userId,
        "regOTT":regOTT,
        "mobile":0,
        "deviceName":"test",
        "userData":"test"
    }

    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    forceActivate = False
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    active = 0
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
        None,
        json.dumps(body)
    )
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT)

    mockResponse = {
    }
    httpserver.serve_content(json.dumps(mockResponse), 200)

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        responseJson = json.loads(response.body)
        assert response.code == 200

        assert responseJson["mpinId"] == mpinId
        assert responseJson["regOTT"] == regOTT
        assert responseJson["expireTime"] == "2016-04-01T13:00:00.000001"
        assert responseJson["nowTime"] == "2016-04-01T12:00:00.000001"
        assert responseJson["active"] == False

        register = http_server.storage.find(stage="register", mpinId=mpinId)
        assert register.regOTT == regOTT
        assert register._expires == "2016-04-01T13:00:00.000001"
        assert register.active == active

        mockLog.assert_called_with("200 PUT {0}/user/{1} 127.0.0.1  {2} {3} {4}".format(baseURL, mpinId, mpinId, userId, "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSUserHandlerMobileOne(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    userId = "root@localhosttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
    body = {
        "userId":userId,
        "regOTT":regOTT,
        "mobile":1,
        "deviceName":"test",
        "userData":"test"
    }

    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    forceActivate = False
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    active = 0
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
        None,
        json.dumps(body)
    )
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT)

    mockResponse = {
        "forceActivate": forceActivate
    }
    httpserver.serve_content(json.dumps(mockResponse), 200)

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        responseJson = json.loads(response.body)
        assert response.code == 200

        assert responseJson["mpinId"] == mpinId
        assert responseJson["regOTT"] == regOTT
        assert responseJson["expireTime"] == "2016-04-01T13:00:00.000001"
        assert responseJson["nowTime"] == "2016-04-01T12:00:00.000001"
        assert responseJson["active"] == False

        register = http_server.storage.find(stage="register", mpinId=mpinId)
        assert register.regOTT == regOTT
        assert register._expires == "2016-04-01T13:00:00.000001"
        assert register.active == active

        mockLog.assert_called_with("200 PUT {0}/user/{1} 127.0.0.1  {2} {3} {4}".format(baseURL, mpinId, mpinId, userId, "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSUserHandlerCapital(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    regOTT = "9F86d081884c7d659A2feaa0c55ad015"
    userId = "root@localhostttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
    body = {
        "userId":userId,
        "regOTT":regOTT,
        "mobile":0,
        "deviceName":"test",
        "userData":"test"
    }

    mpinId = "7b226d6F62696c65223A20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    forceActivate = False
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    active = 0
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
        None,
        json.dumps(body)
    )
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT)

    mockResponse = {
        "forceActivate": forceActivate
    }
    httpserver.serve_content(json.dumps(mockResponse), 200)

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        responseJson = json.loads(response.body)
        assert response.code == 200

        assert responseJson["mpinId"] == mpinId
        assert responseJson["regOTT"] == regOTT
        assert responseJson["expireTime"] == "2016-04-01T13:00:00.000001"
        assert responseJson["nowTime"] == "2016-04-01T12:00:00.000001"
        assert responseJson["active"] == False

        register = http_server.storage.find(stage="register", mpinId=mpinId)
        assert register.regOTT == regOTT
        assert register._expires == "2016-04-01T13:00:00.000001"
        assert register.active == active

        mockLog.assert_called_with("200 PUT {0}/user/{1} 127.0.0.1  {2} {3} {4}".format(baseURL, mpinId, mpinId, userId, "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSUserHandlerMpinIdEmptySlashExist(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    userId = "root@localhosttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
    body = {
        "userId":userId,
        "regOTT":regOTT,
    }

    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    forceActivate = False
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    active = 0
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,""),
        "PUT",
        None,
        json.dumps(body)
    )
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT)

    mockResponse = {
        "forceActivate": forceActivate
    }
    httpserver.serve_content(json.dumps(mockResponse), 200)

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.makeMPinID", return_value=mpinId), mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        responseJson = json.loads(response.body)
        assert response.code == 200

        assert responseJson["mpinId"] == mpinId
        assert responseJson["regOTT"] == regOTT
        assert responseJson["expireTime"] == "2016-04-01T13:00:00.000001"
        assert responseJson["nowTime"] == "2016-04-01T12:00:00.000001"
        assert responseJson["active"] == False

        register = http_server.storage.find(stage="register", mpinId=mpinId)
        assert register.regOTT == regOTT
        assert register._expires == "2016-04-01T13:00:00.000001"
        assert register.active == active

        mockLog.assert_called_with("200 PUT {0}/user/{1} 127.0.0.1  {2} {3} {4}".format(baseURL, "", mpinId, userId, "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSUserHandlerMpinIdEmpty(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    userId = "root@localhosttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
    body = {
        "userId":userId,
        "regOTT":regOTT,
    }

    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    forceActivate = False
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    active = 0
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user{2}".format(base_url,baseURL,""),
        "PUT",
        None,
        json.dumps(body)
    )
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT)

    mockResponse = {
        "forceActivate": forceActivate
    }
    httpserver.serve_content(json.dumps(mockResponse), 200)

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.makeMPinID", return_value=mpinId), mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        responseJson = json.loads(response.body)
        assert response.code == 200

        assert responseJson["mpinId"] == mpinId
        assert responseJson["regOTT"] == regOTT
        assert responseJson["expireTime"] == "2016-04-01T13:00:00.000001"
        assert responseJson["nowTime"] == "2016-04-01T12:00:00.000001"
        assert responseJson["active"] == False

        register = http_server.storage.find(stage="register", mpinId=mpinId)
        assert register.regOTT == regOTT
        assert register._expires == "2016-04-01T13:00:00.000001"
        assert register.active == active

        mockLog.assert_called_with("200 PUT {0}/user{1} 127.0.0.1  {2} {3} {4}".format(baseURL, "", mpinId, userId, "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSUserHandlerNotMatchUserId(http_client, base_url, mocker):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    userId = "root@localhosttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
    body = {
        "userId":userId,
        "regOTT":regOTT,
    }
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    forceActivate = False
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    active = 0
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT)

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")

    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "verifyIdentityRegex", "^.*@localhost$".decode("utf-8")), mock.patch.object(rps.options.mockable(), "verifyIdentityShow", False), mock.patch.object(rps.log, "error", mockLog):
        response = yield http_client.fetch(request)

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"
        responseJson = json.loads(response.body)
        assert response.code == 200

        assert responseJson["mpinId"] == mpinId
        assert responseJson["regOTT"] == regOTT
        assert responseJson["expireTime"] == "2016-04-01T13:00:00.000001"
        assert responseJson["nowTime"] == "2016-04-01T12:00:00.000001"
        assert responseJson["active"] == False

        register = http_server.storage.find(stage="register", mpinId=mpinId)
        assert register.regOTT == regOTT

        mockLog.assert_called_with("{0}/user/{1} 127.0.0.1 {2} {3} {4} {5} Unmatch verifyIdentityRegex {6}".format(baseURL, mpinId, xForwardedFor, mpinId, userId, "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSUserHandlerUnnecessaryKeyError(http_client, base_url, mocker):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    body = {
        "unnecessaryKey":"test",
        "userId":"root@localhost",
        "regOTT":regOTT,
        "mobile":0,
        "deviceName":"test",
        "userData":"test"
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
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

            mockLog.assert_called_with("{0}/user/{1} 127.0.0.1  {2} {3} {4} Invalid data received. unnecessaryKey argument unnecessary unknown".format(baseURL, mpinId, mpinId, "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSUserHandlerMpinIdInvalidLengthError(http_client, base_url, mocker):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227df"

    body = {
        "userId":"root@localhost",
        "regOTT":regOTT,
        "mobile":"0",
        "deviceName":"test",
        "userData":"test"
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
        None,
        json.dumps(body)
    )
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT)
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

            mockLog.assert_called_with("{0}/user/{1} 127.0.0.1  {2} {3} {4} Invalid data received. mpinId argument invalid length unknown".format(baseURL, mpinId, mpinId, "root@localhost", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSUserHandlerMpinIdInvalidCharacterError(http_client, base_url, mocker):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227Ａ"

    body = {
        "userId":"root@localhost",
        "regOTT":regOTT,
        "mobile":"0",
        "deviceName":"test",
        "userData":"test"
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
        None,
        json.dumps(body)
    )
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT)

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
def test_RPSUserHandlerMpinIdInvalidCharacterNotHexError(http_client, base_url, mocker):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227g"

    body = {
        "userId":"root@localhost",
        "regOTT":regOTT,
        "mobile":"0",
        "deviceName":"test",
        "userData":"test"
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
        None,
        json.dumps(body)
    )
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT)

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
def test_RPSUserHandlerMpinIdInvalidCharacterNotHexCapitalError(http_client, base_url, mocker):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227G"

    body = {
        "userId":"root@localhost",
        "regOTT":regOTT,
        "mobile":"0",
        "deviceName":"test",
        "userData":"test"
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
        None,
        json.dumps(body)
    )
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT)

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
def test_RPSUserHandlerMpinIdInvalidCharacterSymbolsError(http_client, base_url, mocker):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227/"

    body = {
        "userId":"root@localhost",
        "regOTT":regOTT,
        "mobile":"0",
        "deviceName":"test",
        "userData":"test"
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
        None,
        json.dumps(body)
    )
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT)

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
def test_RPSUserHandlerUserIdInvalidLength257Error(http_client, base_url, mocker):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    userId = "root@localhostttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    body = {
        "userId":userId,
        "regOTT":regOTT,
        "mobile":0,
        "deviceName":"test",
        "userData":"test"
    }
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
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

            mockLog.assert_called_with("{0}/user/{1} 127.0.0.1 {2} {3} {4} {5} Invalid data received. userId argument invalid length {6}".format(baseURL, mpinId, xForwardedFor, mpinId, userId, "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSUserHandlerUserIdInvalidCharacterFullError(http_client, base_url, mocker):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    userId = "localhostttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttＡ"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    body = {
        "userId":userId,
        "regOTT":regOTT,
        "mobile":0,
        "deviceName":"test",
        "userData":"test"
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
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

            mockLog.assert_called_with("{0}/user/{1} 127.0.0.1  {2} {3} {4} Invalid data received. userId argument contains invalid characters unknown".format(baseURL, mpinId, mpinId, userId, "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSUserHandlerRegOTTInvalidLengthPlusError(http_client, base_url, mocker):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015f"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    body = {
        "userId":"root@localhost",
        "regOTT":regOTT,
        "mobile":0,
        "deviceName":"test",
        "userData":"test"
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
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

            mockLog.assert_called_with("{0}/user/{1} 127.0.0.1  {2} {3} {4} Invalid data received. regOTT argument invalid length unknown".format(baseURL, mpinId, mpinId, "root@localhost", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSUserHandlerRegOTTInvalidLengthMinusError(http_client, base_url, mocker):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad01"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    body = {
        "userId":"root@localhost",
        "regOTT":regOTT,
        "mobile":0,
        "deviceName":"test",
        "userData":"test"
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
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

            mockLog.assert_called_with("{0}/user/{1} 127.0.0.1  {2} {3} {4} Invalid data received. regOTT argument invalid length unknown".format(baseURL, mpinId, mpinId, "root@localhost", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSUserHandlerRegOTTInvalidCharacterFullError(http_client, base_url, mocker):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad01Ａ"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    body = {
        "userId":"root@localhost",
        "regOTT":regOTT,
        "mobile":"0",
        "deviceName":"test",
        "userData":"test"
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
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

            mockLog.assert_called_with("{0}/user/{1} 127.0.0.1  {2} {3} {4} Invalid data received. regOTT argument contains invalid characters unknown".format(baseURL, mpinId, mpinId, "root@localhost", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSUserHandlerRegOTTInvalidCharacterNotHexError(http_client, base_url, mocker):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad01g"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    body = {
        "userId":"root@localhost",
        "regOTT":regOTT,
        "mobile":"0",
        "deviceName":"test",
        "userData":"test"
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
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

            mockLog.assert_called_with("{0}/user/{1} 127.0.0.1  {2} {3} {4} Invalid data received. regOTT argument contains invalid characters unknown".format(baseURL, mpinId, mpinId, "root@localhost", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSUserHandlerRegOTTInvalidCharacterNotHexCapitalError(http_client, base_url, mocker):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad01G"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    body = {
        "userId":"root@localhost",
        "regOTT":regOTT,
        "mobile":"0",
        "deviceName":"test",
        "userData":"test"
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
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

            mockLog.assert_called_with("{0}/user/{1} 127.0.0.1  {2} {3} {4} Invalid data received. regOTT argument contains invalid characters unknown".format(baseURL, mpinId, mpinId, "root@localhost", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSUserHandlerRegOTTInvalidCharacterSymbolsError(http_client, base_url, mocker):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad01/"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    body = {
        "userId":"root@localhost",
        "regOTT":regOTT,
        "mobile":"0",
        "deviceName":"test",
        "userData":"test"
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
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

            mockLog.assert_called_with("{0}/user/{1} 127.0.0.1  {2} {3} {4} Invalid data received. regOTT argument contains invalid characters unknown".format(baseURL, mpinId, mpinId, "root@localhost", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSUserHandlerMobileInvalidValueError(http_client, base_url, mocker):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    mobile = {}
    body = {
        "userId":"root@localhost",
        "regOTT":regOTT,
        "mobile":mobile,
        "deviceName":"test",
        "userData":"test"
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
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

            mockLog.assert_called_with("{0}/user/{1} 127.0.0.1  {2} {3} {4} Cannot decode body as JSON. unknown".format(baseURL, mpinId, mpinId, "root@localhost", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSUserHandlerMobileInvalidNumber2Error(http_client, base_url, mocker):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    body = {
        "userId":"root@localhost",
        "regOTT":regOTT,
        "mobile":"2",
        "deviceName":"test",
        "userData":"test"
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
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

            mockLog.assert_called_with("{0}/user/{1} 127.0.0.1  {2} {3} {4} Invalid data received. mobile argument invalid number unknown".format(baseURL, mpinId, mpinId, "root@localhost", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSUserHandlerMobileInvalidNumberFullError(http_client, base_url, mocker):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    body = {
        "userId":"root@localhost",
        "regOTT":regOTT,
        "mobile":"Ａ",
        "deviceName":"test",
        "userData":"test"
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
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

            mockLog.assert_called_with("{0}/user/{1} 127.0.0.1  {2} {3} {4} Cannot decode body as JSON. unknown".format(baseURL, mpinId, mpinId, "root@localhost", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSUserHandlerMobileInvalidNumberAlphaError(http_client, base_url, mocker):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    body = {
        "userId":"root@localhost",
        "regOTT":regOTT,
        "mobile":"a",
        "deviceName":"test",
        "userData":"test"
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
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

            mockLog.assert_called_with("{0}/user/{1} 127.0.0.1  {2} {3} {4} Cannot decode body as JSON. unknown".format(baseURL, mpinId, mpinId, "root@localhost", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSUserHandlerForceActivateInvalidTypeError(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    body = {
        "userId":"root@localhost",
        "regOTT":regOTT,
        "mobile":0,
        "deviceName":"test",
        "userData":"test"
    }

    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    forceActivate = "test"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    active = 0
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
        None,
        json.dumps(body)
    )
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT)

    mockResponse = {
        "forceActivate": forceActivate
    }
    httpserver.serve_content(json.dumps(mockResponse), 200)

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")

    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey),mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/user/{1} 127.0.0.1  {2} {3} {4} Invalid data received. forceActivate invalid type unknown".format(baseURL, mpinId, mpinId, "root@localhost", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSUserHandlerNotMatchUserIdError(http_client, base_url, mocker):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    userId = "root@localhosttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
    body = {
        "userId":userId,
        "regOTT":regOTT,
    }

    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    forceActivate = False
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    active = 0
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
        None,
        json.dumps(body)
    )
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT)

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")

    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "verifyIdentityRegex", "^.*@localhost$".decode("utf-8")), mock.patch.object(rps.options.mockable(), "verifyIdentityShow", True), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400

        assert e.response.headers.get("Access-Control-Allow-Origin") == None
        assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

        mockLog.assert_called_with("{0}/user/{1} 127.0.0.1  {2} {3} {4} Unmatch verifyIdentityRegex unknown".format(baseURL, mpinId, mpinId, userId, "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSUserHandlerUserIdEmpty(http_client, base_url, mocker):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    body = {
        "userId":"",
        "regOTT":regOTT,
        "mobile":0,
        "deviceName":"test",
        "userData":"test"
    }
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
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

            mockLog.assert_called_with("{0}/user/{1} 127.0.0.1 {2} {3} {4} {5} Missing userId {6}".format(baseURL, mpinId, xForwardedFor, mpinId, "", "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSUserHandlerMpinIdNotFound(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    userId = "root@localhosttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
    body = {
        "userId":userId,
        "regOTT":regOTT,
    }

    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    forceActivate = False
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    active = 0
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
        None,
        json.dumps(body)
    )

    mockResponse = {
        "forceActivate": forceActivate
    }
    #http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT)
    httpserver.serve_content(json.dumps(mockResponse), 200)

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockInfoLog = mocker.Mock()
    mockErrLog = mocker.Mock()
    with mocker.patch("mpin_utils.secrets.generate_ott", return_value=regOTT), mocker.patch("rps.makeMPinID", return_value=mpinId), mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.log, "info", mockInfoLog), mock.patch.object(rps.log, "error", mockErrLog):
        response = yield http_client.fetch(request)

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        responseJson = json.loads(response.body)
        assert response.code == 200

        assert responseJson["mpinId"] == mpinId
        assert responseJson["regOTT"] == regOTT
        assert responseJson["expireTime"] == "2016-04-01T13:00:00.000001"
        assert responseJson["nowTime"] == "2016-04-01T12:00:00.000001"
        assert responseJson["active"] == False

        register = http_server.storage.find(stage="register", mpinId=mpinId)
    	assert register.regOTT == regOTT
        assert register._expires == "2016-04-01T13:00:00.000001"
        assert register.active == active

        mockInfoLog.assert_called_with("200 PUT {0}/user/{1} 127.0.0.1  {2} {3} {4}".format(baseURL, mpinId, mpinId, userId, "").decode("utf-8"))
        mockErrLog.assert_called_with("{0}/user/{1} 127.0.0.1  {2} {3} {4} Missing or invalid mpinID. Will generate a new mpinID unknown".format(baseURL, mpinId, None, userId, "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSUserHandlerRegOTTInvalid(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    regOTTDb = "9f86d081884c7d659a2feaa0c55ad016"
    userId = "root@localhosttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
    body = {
        "userId":userId,
        "regOTT":regOTT,
    }

    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    active = 0
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
        None,
        json.dumps(body)
    )
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTTDb)

    mockLog = mocker.Mock()
    with  mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/user/{1} 127.0.0.1  {2} {3} {4} Missing or invalid regOTT unknown".format(baseURL, mpinId, mpinId, userId, "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSUserHandlerRPAVerifyUserURLNotSet(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    userId = "root@localhosttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
    body = {
        "userId":userId,
        "regOTT":regOTT,
    }

    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    forceActivate = False
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
        None,
        json.dumps(body)
    )
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT)

    mockResponse = {
        "forceActivate": forceActivate
    }
    httpserver.serve_content(json.dumps(mockResponse), 200)

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", None), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/user/{1} 127.0.0.1  {2} {3} {4} RPAVerifyUserURL option not set! Unable to make Verify request unknown".format(baseURL, mpinId, mpinId, userId, "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSUserHandlerResponseErr(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    userId = "root@localhosttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
    body = {
        "userId":userId,
        "regOTT":regOTT,
    }

    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    forceActivate = False
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
        None,
        json.dumps(body)
    )
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT)
    httpserver.serve_content("", 500)

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/user/{1} 127.0.0.1  {2} {3} {4} RPA verify request error: HTTP 500: INTERNAL SERVER ERROR. Code: 500, Reason: INTERNAL SERVER ERROR unknown".format(baseURL, mpinId, mpinId, userId, "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSUserHandlerResponseBodyInvalid(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    userId = "root@localhosttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
    body = {
        "userId":userId,
        "regOTT":regOTT,
    }

    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    forceActivate = False
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/user/{2}".format(base_url,baseURL,mpinId),
        "PUT",
        None,
        json.dumps(body)
    )
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT)
    httpserver.serve_content("test", 200)

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/user/{1} 127.0.0.1  {2} {3} {4} RPA verify request: Invalid JSON response: test unknown".format(baseURL, mpinId, mpinId, userId, "").decode("utf-8"))
