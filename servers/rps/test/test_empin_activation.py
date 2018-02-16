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
def test_EMpinActivationHandler(http_client, base_url, httpserver, httpsserver, mocker):
    baseURL = "/rps"
    userId = "1root@localhost"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    forceActivate = False

    body = {
        "userId": userId
    }
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        rps.tornado.httputil.HTTPHeaders({"X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a202231726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "61ec586f1e57219606f4bcb2dc0742602926c3889082a3f76f57b0fc7c54f353"
    signature = "5a7e95c3812b4699ec9b7b39de95e22c7a5a937e0f4257070ee99b2793fbb9fb"
    clientSecret = "040f03f596dcca370a4cc07d9485bc88648f532a6aa81d2c5339f560d37a66b1d123231fd1d59faafceac8ca3ecbb1d88ec4b1fb4d6496b1a38e33c2699428762a"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }
    mockResponse2 = {
        "forceActivate": forceActivate
    }
    httpserver.serve_content(json.dumps(mockResponse), 200)
    httpsserver.serve_content(json.dumps(mockResponse2), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpsserver.url.decode("utf-8")), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        responseJson = json.loads(response.body)
        mpinIdJson = json.loads(responseJson["mpinId"].decode("hex"))
        assert mpinIdJson["mobile"] == mobile
        assert mpinIdJson["userID"] == userId
        expireTime = datetime.datetime.strptime(responseJson["expireTime"], "%Y-%m-%dT%H:%M:%S.%f")
        nowTime = datetime.datetime.strptime(responseJson["nowTime"], "%Y-%m-%dT%H:%M:%S.%f")
        assert (expireTime - nowTime).total_seconds() == 3600
        assert responseJson["active"] == forceActivate
        assert responseJson["activationCode"] == 0
        assert responseJson["params"] == "mobile={0}&expires={1}Z&app_id={2}&hash_mpin_id={3}&signature={4}&hash_user_id=".format(mobile, urllib.quote_plus(mockTime.isoformat().split(".")[0]), appId, hashMpinId, signature)
        assert responseJson["clientSecretShare"] == clientSecret

        mockLog.assert_called_with("200 PUT {0}/eMpinActivation 127.0.0.1 {1} {2} {3} {4}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerContainOptionalKey(http_client, base_url, httpserver, httpsserver, mocker):
    baseURL = "/rps"
    userId = "1root@localhost"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    forceActivate = False

    body = {
        "mobile": mobile,
        "userId": userId,
        "deviceName": "testDevice1/Ａ",
        "userData": "testUserData1/Ａ",
        "resend": True
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        None,
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a202231726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "61ec586f1e57219606f4bcb2dc0742602926c3889082a3f76f57b0fc7c54f353"
    signature = "5a7e95c3812b4699ec9b7b39de95e22c7a5a937e0f4257070ee99b2793fbb9fb"
    clientSecret = "040f03f596dcca370a4cc07d9485bc88648f532a6aa81d2c5339f560d37a66b1d123231fd1d59faafceac8ca3ecbb1d88ec4b1fb4d6496b1a38e33c2699428762a"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568"
    }
    mockResponse2 = {
        "forceActivate": forceActivate
    }
    httpserver.serve_content(json.dumps(mockResponse), 200)
    httpsserver.serve_content(json.dumps(mockResponse2), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpsserver.url.decode("utf-8")), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        responseJson = json.loads(response.body)
        mpinIdJson = json.loads(responseJson["mpinId"].decode("hex"))
        assert mpinIdJson["mobile"] == mobile
        assert mpinIdJson["userID"] == userId
        expireTime = datetime.datetime.strptime(responseJson["expireTime"], "%Y-%m-%dT%H:%M:%S.%f")
        nowTime = datetime.datetime.strptime(responseJson["nowTime"], "%Y-%m-%dT%H:%M:%S.%f")
        assert (expireTime - nowTime).total_seconds() == 3600
        assert responseJson["active"] == forceActivate
        assert responseJson["activationCode"] == 0
        assert responseJson["params"] == "mobile={0}&expires={1}Z&app_id={2}&hash_mpin_id={3}&signature={4}&hash_user_id=".format(mobile, urllib.quote_plus(mockTime.isoformat().split(".")[0]), appId, hashMpinId, signature)
        assert responseJson["clientSecretShare"] == clientSecret

        mockLog.assert_called_with("200 PUT {0}/eMpinActivation 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, userId, hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerActivationCodeHexOddLength(http_client, base_url, httpserver, httpsserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    forceActivate = False

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        None,
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"
    clientSecret = "04075e68d01964d4cc186f981bf16e475e2c0c14d1f3b9f06310f790d2fca92b0706f98f28e5dc8152fb80bc85340036253c412dd9dee6136d9cbba3f6d95ec453"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 14065070394
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }
    mockResponse2 = {
        "forceActivate": forceActivate
    }
    httpserver.serve_content(json.dumps(mockResponse), 200)
    httpsserver.serve_content(json.dumps(mockResponse2), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpsserver.url.decode("utf-8")), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        responseJson = json.loads(response.body)
        mpinIdJson = json.loads(responseJson["mpinId"].decode("hex"))
        assert mpinIdJson["mobile"] == mobile
        assert mpinIdJson["userID"] == userId
        expireTime = datetime.datetime.strptime(responseJson["expireTime"], "%Y-%m-%dT%H:%M:%S.%f")
        nowTime = datetime.datetime.strptime(responseJson["nowTime"], "%Y-%m-%dT%H:%M:%S.%f")
        assert (expireTime - nowTime).total_seconds() == 3600
        assert responseJson["active"] == forceActivate
        assert responseJson["activationCode"] == 0
        assert responseJson["params"] == "mobile={0}&expires={1}Z&app_id={2}&hash_mpin_id={3}&signature={4}&hash_user_id=".format(mobile, urllib.quote_plus(mockTime.isoformat().split(".")[0]), appId, hashMpinId, signature)
        assert responseJson["clientSecretShare"] == clientSecret

        mockLog.assert_called_with("200 PUT {0}/eMpinActivation 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, userId, hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerNotMatchUserId(http_client, base_url, httpserver, mocker):
    baseURL = "/rps"
    userId = "1root@localhost"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    forceActivate = False

    body = {
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        None,
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a202231726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "61ec586f1e57219606f4bcb2dc0742602926c3889082a3f76f57b0fc7c54f353"
    signature = "5a7e95c3812b4699ec9b7b39de95e22c7a5a937e0f4257070ee99b2793fbb9fb"
    clientSecret = "040f03f596dcca370a4cc07d9485bc88648f532a6aa81d2c5339f560d37a66b1d123231fd1d59faafceac8ca3ecbb1d88ec4b1fb4d6496b1a38e33c2699428762a"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }
    httpserver.serve_content(json.dumps(mockResponse), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.options.mockable(), "verifyIdentityRegex", "^.`@localhost.localdomain$".decode("utf-8")), mock.patch.object(rps.options.mockable(), "verifyIdentityShow", False), mock.patch.object(rps.log, "error", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        responseJson = json.loads(response.body)
        mpinIdJson = json.loads(responseJson["mpinId"].decode("hex"))
        assert mpinIdJson["mobile"] == mobile
        assert mpinIdJson["userID"] == userId
        expireTime = datetime.datetime.strptime(responseJson["expireTime"], "%Y-%m-%dT%H:%M:%S.%f")
        nowTime = datetime.datetime.strptime(responseJson["nowTime"], "%Y-%m-%dT%H:%M:%S.%f")
        assert (expireTime - nowTime).total_seconds() == 3600
        assert responseJson["active"] == forceActivate
        assert responseJson["activationCode"] == 0
        assert responseJson["params"] == "mobile={0}&expires={1}Z&app_id={2}&hash_mpin_id={3}&signature={4}&hash_user_id=".format(mobile, urllib.quote_plus(mockTime.isoformat().split(".")[0]), appId, hashMpinId, signature)
        assert responseJson["clientSecretShare"] == clientSecret

        mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1  {1} {2} {3} Unmatch verifyIdentityRegex {4}".format(baseURL, mpinId, userId, hashMpinId, "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerForwardAllHeader(http_client, base_url, httpserver, httpsserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    forceActivate = False

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        rps.tornado.httputil.HTTPHeaders({"ForwardHeaderName1": "ForwardHeaderValue1", "ForwardHeaderName2": "ForwardHeaderValue2"}),
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"
    clientSecret = "040025066321f8b5b070b51ca2a809db13a1afe33a3c672c9272f287b64f0722680d54658b07e5850df4e7a363ad52944f4e3cb908118541cddeddf3a8ad9c791c"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }
    mockResponse2 = {
        "forceActivate": forceActivate
    }
    httpserver.serve_content(json.dumps(mockResponse), 200)
    httpsserver.serve_content(json.dumps(mockResponse2), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.options.mockable(), "RegisterForwardUserHeaders", "*".decode("utf-8")), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpsserver.url.decode("utf-8")), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        responseJson = json.loads(response.body)
        mpinIdJson = json.loads(responseJson["mpinId"].decode("hex"))
        assert mpinIdJson["mobile"] == mobile
        assert mpinIdJson["userID"] == userId
        expireTime = datetime.datetime.strptime(responseJson["expireTime"], "%Y-%m-%dT%H:%M:%S.%f")
        nowTime = datetime.datetime.strptime(responseJson["nowTime"], "%Y-%m-%dT%H:%M:%S.%f")
        assert (expireTime - nowTime).total_seconds() == 3600
        assert responseJson["active"] == forceActivate
        assert responseJson["activationCode"] == 0
        assert responseJson["params"] == "mobile={0}&expires={1}Z&app_id={2}&hash_mpin_id={3}&signature={4}&hash_user_id=".format(mobile, urllib.quote_plus(mockTime.isoformat().split(".")[0]), appId, hashMpinId, signature)
        assert responseJson["clientSecretShare"] == clientSecret

        mockLog.assert_called_with("200 PUT {0}/eMpinActivation 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, userId, hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerForward1Header(http_client, base_url, httpserver, httpsserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    forceActivate = False

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        rps.tornado.httputil.HTTPHeaders({"ForwardHeaderName1": "ForwardHeaderValue1", "ForwardHeaderName2": "ForwardHeaderValue2"}),
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"
    clientSecret = "040025066321f8b5b070b51ca2a809db13a1afe33a3c672c9272f287b64f0722680d54658b07e5850df4e7a363ad52944f4e3cb908118541cddeddf3a8ad9c791c"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }
    mockResponse2 = {
        "forceActivate": forceActivate
    }
    httpserver.serve_content(json.dumps(mockResponse), 200)
    httpsserver.serve_content(json.dumps(mockResponse2), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.options.mockable(), "RegisterForwardUserHeaders", "ForwardHeaderName1".decode("utf-8")), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpsserver.url.decode("utf-8")), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        responseJson = json.loads(response.body)
        mpinIdJson = json.loads(responseJson["mpinId"].decode("hex"))
        assert mpinIdJson["mobile"] == mobile
        assert mpinIdJson["userID"] == userId
        expireTime = datetime.datetime.strptime(responseJson["expireTime"], "%Y-%m-%dT%H:%M:%S.%f")
        nowTime = datetime.datetime.strptime(responseJson["nowTime"], "%Y-%m-%dT%H:%M:%S.%f")
        assert (expireTime - nowTime).total_seconds() == 3600
        assert responseJson["active"] == forceActivate
        assert responseJson["activationCode"] == 0
        assert responseJson["params"] == "mobile={0}&expires={1}Z&app_id={2}&hash_mpin_id={3}&signature={4}&hash_user_id=".format(mobile, urllib.quote_plus(mockTime.isoformat().split(".")[0]), appId, hashMpinId, signature)
        assert responseJson["clientSecretShare"] == clientSecret

        mockLog.assert_called_with("200 PUT {0}/eMpinActivation 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, userId, hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerForward2Header(http_client, base_url, httpserver, httpsserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    forceActivate = False

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        rps.tornado.httputil.HTTPHeaders({"ForwardHeaderName1": "ForwardHeaderValue1", "ForwardHeaderName2": "ForwardHeaderValue2"}),
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"
    clientSecret = "040025066321f8b5b070b51ca2a809db13a1afe33a3c672c9272f287b64f0722680d54658b07e5850df4e7a363ad52944f4e3cb908118541cddeddf3a8ad9c791c"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }
    mockResponse2 = {
        "forceActivate": forceActivate
    }
    httpserver.serve_content(json.dumps(mockResponse), 200)
    httpsserver.serve_content(json.dumps(mockResponse2), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.options.mockable(), "RegisterForwardUserHeaders", "ForwardHeaderName1,ForwardHeaderName2".decode("utf-8")), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpsserver.url.decode("utf-8")), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        responseJson = json.loads(response.body)
        mpinIdJson = json.loads(responseJson["mpinId"].decode("hex"))
        assert mpinIdJson["mobile"] == mobile
        assert mpinIdJson["userID"] == userId
        expireTime = datetime.datetime.strptime(responseJson["expireTime"], "%Y-%m-%dT%H:%M:%S.%f")
        nowTime = datetime.datetime.strptime(responseJson["nowTime"], "%Y-%m-%dT%H:%M:%S.%f")
        assert (expireTime - nowTime).total_seconds() == 3600
        assert responseJson["active"] == forceActivate
        assert responseJson["activationCode"] == 0
        assert responseJson["params"] == "mobile={0}&expires={1}Z&app_id={2}&hash_mpin_id={3}&signature={4}&hash_user_id=".format(mobile, urllib.quote_plus(mockTime.isoformat().split(".")[0]), appId, hashMpinId, signature)
        assert responseJson["clientSecretShare"] == clientSecret

        mockLog.assert_called_with("200 PUT {0}/eMpinActivation 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, userId, hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerActivateTrue(http_client, base_url, httpserver, httpsserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    forceActivate = True

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": ""}),
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"
    clientSecret = "040025066321f8b5b070b51ca2a809db13a1afe33a3c672c9272f287b64f0722680d54658b07e5850df4e7a363ad52944f4e3cb908118541cddeddf3a8ad9c791c"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }
    mockResponse2 = {
        "forceActivate": forceActivate
    }
    httpserver.serve_content(json.dumps(mockResponse), 200)
    httpsserver.serve_content(json.dumps(mockResponse2), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpsserver.url.decode("utf-8")), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        responseJson = json.loads(response.body)
        mpinIdJson = json.loads(responseJson["mpinId"].decode("hex"))
        assert mpinIdJson["mobile"] == mobile
        assert mpinIdJson["userID"] == userId
        expireTime = datetime.datetime.strptime(responseJson["expireTime"], "%Y-%m-%dT%H:%M:%S.%f")
        nowTime = datetime.datetime.strptime(responseJson["nowTime"], "%Y-%m-%dT%H:%M:%S.%f")
        assert (expireTime - nowTime).total_seconds() == 3600
        assert responseJson["active"] == forceActivate
        assert responseJson["activationCode"] == mockRandomInt
        assert responseJson["params"] == "mobile={0}&expires={1}Z&app_id={2}&hash_mpin_id={3}&signature={4}&hash_user_id=".format(mobile, urllib.quote_plus(mockTime.isoformat().split(".")[0]), appId, hashMpinId, signature)
        assert responseJson["clientSecretShare"] == clientSecret

        mockLog.assert_called_with("200 PUT {0}/eMpinActivation 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, userId, hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerReqUserIdEmptyError(http_client, base_url, mocker):
    baseURL = "/rps"
    mobile = 0
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "mobile": mobile,
        "userId": ""
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
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

            mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1 {1} {2} {3} {4} Missing userId {5}".format(baseURL, xForwardedFor, "", "", "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerDecodeClientSecretError(http_client, base_url, httpserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(

        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "decodeError",
        "message": "OK",
    }

    httpserver.serve_content(json.dumps(mockResponse), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1 {1} {2} {3} {4} Invalid data received. clientSecret invalid length {5}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerEncodeError(http_client, base_url, httpserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13560",
        "message": "OK",
    }

    httpserver.serve_content(json.dumps(mockResponse), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400
            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1 {1} {2} {3} {4} Encoding client secret with activation code Failed {5}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerEncodeInvalidHidError(http_client, base_url, httpserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"

    mockHid = "040a3e3fd3df38fcd1a22ebb3291ed6f748c7e745d927519f9596813f5aa96087f1ed1f619233a6067aa51848d175fc62c3d4ac4491f8785ab0bbee53804bc9e30"
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }

    httpserver.serve_content(json.dumps(mockResponse), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.secrets.mpin.server_1", return_value=(mockHid.decode("hex"),"")), mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400
            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1 {1} {2} {3} {4} Encoding client secret with activation code Failed {5}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerReqJsonError(http_client, base_url, mocker):
    baseURL = "/rps"
    mobile = 0
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
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
            assert e.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1 {1} {2} {3} {4} Cannot decode body as JSON. {5}".format(baseURL, xForwardedFor, "", "", "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerDTALocalError(http_client, base_url, httpserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockLog = mocker.Mock()
    mockCode = 500
    httpserver.serve_content("", mockCode)
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            errMsg = "DTA clientSecret Failed. URL: {0}/clientSecret?mobile={1}&expires={2}Z&app_id={3}&hash_mpin_id={4}&signature={5}&hash_user_id=, Code: {6}, Message: HTTP 500: INTERNAL SERVER ERROR".format(httpserver.url, mobile, urllib.quote_plus(mockTime.isoformat().split(".")[0]), appId, hashMpinId, signature, mockCode)
            mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, errMsg, userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerDTAlocalEmptyError(http_client, base_url, httpserver, httpsserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    forceActivate = False
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"
    clientSecret = "040025066321f8b5b070b51ca2a809db13a1afe33a3c672c9272f287b64f0722680d54658b07e5850df4e7a363ad52944f4e3cb908118541cddeddf3a8ad9c791c"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockLog = mocker.Mock()
    mockResponse2 = {
        "forceActivate": forceActivate
    }
    httpserver.serve_content("", 200)
    httpsserver.serve_content(json.dumps(mockResponse2), 200)
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpsserver.url.decode("utf-8")), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1 {1} {2} {3} {4} DTA /clientSecret Failed. Invalid JSON response:  {5}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerDTALocalJsonError(http_client, base_url, httpserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "mobile": mobile,
        "userId": userId
    }

    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockLog = mocker.Mock()
    httpserver.serve_content("jsonError", 200)
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1 {1} {2} {3} {4} DTA /clientSecret Failed. Invalid JSON response: jsonError {5}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerVerifyURLError(http_client, base_url, httpserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockLog = mocker.Mock()
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }
    httpserver.serve_content(json.dumps(mockResponse), 200)
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", "".decode("utf-8")), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1 {1} {2} {3} {4} RPAVerifyUserURL option not set! Unable to make Verify request {5}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerVerifyError(http_client, base_url, httpserver, httpsserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockLog = mocker.Mock()
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }
    mockCode = 500
    httpserver.serve_content(json.dumps(mockResponse), 200)
    httpsserver.serve_content("", mockCode)
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpsserver.url.decode("utf-8")), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1 {1} {2} {3} {4} RPA verify request error. Code: 500, Message: HTTP 500: INTERNAL SERVER ERROR {5}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerVerifyEmptyError(http_client, base_url, httpserver, httpsserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"
    clientSecret = "040025066321f8b5b070b51ca2a809db13a1afe33a3c672c9272f287b64f0722680d54658b07e5850df4e7a363ad52944f4e3cb908118541cddeddf3a8ad9c791c"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockLog = mocker.Mock()
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }
    httpserver.serve_content(json.dumps(mockResponse), 200)
    httpsserver.serve_content("", 200)
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpsserver.url.decode("utf-8")), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1 {1} {2} {3} {4} RPA verify request: Invalid JSON response:  {5}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerVerifyJsonError(http_client, base_url, httpserver, httpsserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394

    mockLog = mocker.Mock()
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }
    mockBody = "jsonError"
    httpserver.serve_content(json.dumps(mockResponse), 200)
    httpsserver.serve_content(mockBody, 200)
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpsserver.url.decode("utf-8")), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1 {1} {2} {3} {4} RPA verify request: Invalid JSON response: {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, mockBody, userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerVerifyJsonErrorUserAgentEmpty(http_client, base_url, httpserver, httpsserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        None,
        json.dumps(body)
    )

    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394

    mockLog = mocker.Mock()
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }
    mockBody = "jsonError"
    httpserver.serve_content(json.dumps(mockResponse), 200)
    httpsserver.serve_content(mockBody, 200)
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpsserver.url.decode("utf-8")), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1  {1} {2} {3} RPA verify request: Invalid JSON response: jsonError {4}".format(baseURL, mpinId, userId, hashMpinId, "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerMpinIdMax(http_client, base_url, httpserver, httpsserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    forceActivate = False

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        None,
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227d"
    hashMpinId = "c7e58b63caf88264ed786596fe6679a0645c95788ca36e53b2a6f8e37b7f231d"
    signature = "13b2bef92de58b037110fc1e593d587a040d28dc0279bbea23b658c54b2ba6a8"
    clientSecret = "041d195d3fd10b02b20004a092a58c3765e66013c5bc313a9fc85502b4f36333c401a084df936bc17f7e52cf19446b8152846d45354de01a6f631f7053667d8eb3"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "ffffffffffffffffffffffffffffffff"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }
    mockResponse2 = {
        "forceActivate": forceActivate
    }
    httpserver.serve_content(json.dumps(mockResponse), 200)
    httpsserver.serve_content(json.dumps(mockResponse2), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpsserver.url.decode("utf-8")), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        responseJson = json.loads(response.body)
        mpinIdJson = json.loads(responseJson["mpinId"].decode("hex"))
        assert mpinIdJson["mobile"] == mobile
        assert mpinIdJson["userID"] == userId
        expireTime = datetime.datetime.strptime(responseJson["expireTime"], "%Y-%m-%dT%H:%M:%S.%f")
        nowTime = datetime.datetime.strptime(responseJson["nowTime"], "%Y-%m-%dT%H:%M:%S.%f")
        assert (expireTime - nowTime).total_seconds() == 3600
        assert responseJson["active"] == forceActivate
        assert responseJson["activationCode"] == 0
        assert responseJson["params"] == "mobile={0}&expires={1}Z&app_id={2}&hash_mpin_id={3}&signature={4}&hash_user_id=".format(mobile, urllib.quote_plus(mockTime.isoformat().split(".")[0]), appId, hashMpinId, signature)
        assert responseJson["clientSecretShare"] == clientSecret

        mockLog.assert_called_with("200 PUT {0}/eMpinActivation 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, userId, hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerMpinIdMin(http_client, base_url, httpserver, httpsserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    forceActivate = False

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        None,
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20223030303030303030303030303030303030303030303030303030303030303030227d"
    hashMpinId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    signature = "acb1e4a7f9c5e12b30413e8154d36eba8df114f558d5d39c16c9759bcb98ab84"
    clientSecret = "040c8916fd3e73d9c3ace205b709a0f542a0d95f1fa1a0ba92ba00f77ac2cf84200f9fc6f9edde432c6d40db5e860afc4001da879af815e53bade07113d057f379"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "00000000000000000000000000000000"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "042382b249b15bc339f45f9402abc8885c55cfcd432611860c10320bf9dac3e9cc0bdb5a61dc1c9ab64d66b372eddc3d3422e311b2802ef63a21a81aae6d77e8d2",
        "message": "OK",
    }
    mockResponse2 = {
        "forceActivate": forceActivate
    }
    httpserver.serve_content(json.dumps(mockResponse), 200)
    httpsserver.serve_content(json.dumps(mockResponse2), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpsserver.url.decode("utf-8")), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        responseJson = json.loads(response.body)
        mpinIdJson = json.loads(responseJson["mpinId"].decode("hex"))
        print "test" + str(responseJson["mpinId"])
        assert mpinIdJson["mobile"] == mobile
        assert mpinIdJson["userID"] == userId
        expireTime = datetime.datetime.strptime(responseJson["expireTime"], "%Y-%m-%dT%H:%M:%S.%f")
        nowTime = datetime.datetime.strptime(responseJson["nowTime"], "%Y-%m-%dT%H:%M:%S.%f")
        assert (expireTime - nowTime).total_seconds() == 3600
        assert responseJson["active"] == forceActivate
        assert responseJson["activationCode"] == 0
        assert responseJson["params"] == "mobile={0}&expires={1}Z&app_id={2}&hash_mpin_id={3}&signature={4}&hash_user_id=".format(mobile, urllib.quote_plus(mockTime.isoformat().split(".")[0]), appId, hashMpinId, signature)
        assert responseJson["clientSecretShare"] == clientSecret

        mockLog.assert_called_with("200 PUT {0}/eMpinActivation 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, userId, hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerActivationCodeMax(http_client, base_url, httpserver, httpsserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    forceActivate = False

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        None,
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"
    clientSecret = "041bc396fb670c97f4143443ca4e7a9c1ae96e55d5fcdb77e8b29c173dd1a88c9b237b74641793e5b19de891b92d510f3184e1e395a822d3811b76da3461f9caa7"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 999999999999
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }
    mockResponse2 = {
        "forceActivate": forceActivate
    }
    httpserver.serve_content(json.dumps(mockResponse), 200)
    httpsserver.serve_content(json.dumps(mockResponse2), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpsserver.url.decode("utf-8")), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        responseJson = json.loads(response.body)
        mpinIdJson = json.loads(responseJson["mpinId"].decode("hex"))
        assert mpinIdJson["mobile"] == mobile
        assert mpinIdJson["userID"] == userId
        expireTime = datetime.datetime.strptime(responseJson["expireTime"], "%Y-%m-%dT%H:%M:%S.%f")
        nowTime = datetime.datetime.strptime(responseJson["nowTime"], "%Y-%m-%dT%H:%M:%S.%f")
        assert (expireTime - nowTime).total_seconds() == 3600
        assert responseJson["active"] == forceActivate
        assert responseJson["activationCode"] == 0
        assert responseJson["params"] == "mobile={0}&expires={1}Z&app_id={2}&hash_mpin_id={3}&signature={4}&hash_user_id=".format(mobile, urllib.quote_plus(mockTime.isoformat().split(".")[0]), appId, hashMpinId, signature)
        assert responseJson["clientSecretShare"] == clientSecret

        mockLog.assert_called_with("200 PUT {0}/eMpinActivation 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, userId, hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerActivationCodeMin(http_client, base_url, httpserver, httpsserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    forceActivate = False

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        None,
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"
    clientSecret = "040b14c0445da278495448c7b21d44f04b6ba8178033a1098ea04bb84b6f7e86401042fe84a74d999564a1e2c0be2efd5178378f84a8cd753378b281691e257d61"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 1
    mockResponse = {
        "clientSecret": "0401ce4276d6da42785b66f96a04044a58a663378147c94f905eb84aa6790cc5131159ab00a44fad18c4b016b5bbb9fe4521fbf6f376968b0d009acadbcc38c7ea",
        "message": "OK",
    }
    mockResponse2 = {
        "forceActivate": forceActivate
    }
    httpserver.serve_content(json.dumps(mockResponse), 200)
    httpsserver.serve_content(json.dumps(mockResponse2), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpsserver.url.decode("utf-8")), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        responseJson = json.loads(response.body)
        mpinIdJson = json.loads(responseJson["mpinId"].decode("hex"))
        assert mpinIdJson["mobile"] == mobile
        assert mpinIdJson["userID"] == userId
        expireTime = datetime.datetime.strptime(responseJson["expireTime"], "%Y-%m-%dT%H:%M:%S.%f")
        nowTime = datetime.datetime.strptime(responseJson["nowTime"], "%Y-%m-%dT%H:%M:%S.%f")
        assert (expireTime - nowTime).total_seconds() == 3600
        assert responseJson["active"] == forceActivate
        assert responseJson["activationCode"] == 0
        assert responseJson["params"] == "mobile={0}&expires={1}Z&app_id={2}&hash_mpin_id={3}&signature={4}&hash_user_id=".format(mobile, urllib.quote_plus(mockTime.isoformat().split(".")[0]), appId, hashMpinId, signature)
        assert responseJson["clientSecretShare"] == clientSecret

        mockLog.assert_called_with("200 PUT {0}/eMpinActivation 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, userId, hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerActivationCodeGenerateCountSecond(http_client, base_url, httpserver, httpsserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    forceActivate = False

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        None,
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"
    clientSecret = "040025066321f8b5b070b51ca2a809db13a1afe33a3c672c9272f287b64f0722680d54658b07e5850df4e7a363ad52944f4e3cb908118541cddeddf3a8ad9c791c"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }
    mockResponse2 = {
        "forceActivate": forceActivate
    }
    httpserver.serve_content(json.dumps(mockResponse), 200)
    httpsserver.serve_content(json.dumps(mockResponse2), 200)
    mockFunc = mocker.MagicMock(side_effect=[0,mockRandomInt, mockRandomInt])
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", mockFunc), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpsserver.url.decode("utf-8")), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        responseJson = json.loads(response.body)
        mpinIdJson = json.loads(responseJson["mpinId"].decode("hex"))
        assert mpinIdJson["mobile"] == mobile
        assert mpinIdJson["userID"] == userId
        expireTime = datetime.datetime.strptime(responseJson["expireTime"], "%Y-%m-%dT%H:%M:%S.%f")
        nowTime = datetime.datetime.strptime(responseJson["nowTime"], "%Y-%m-%dT%H:%M:%S.%f")
        assert (expireTime - nowTime).total_seconds() == 3600
        assert responseJson["active"] == forceActivate
        assert responseJson["activationCode"] == 0
        assert responseJson["params"] == "mobile={0}&expires={1}Z&app_id={2}&hash_mpin_id={3}&signature={4}&hash_user_id=".format(mobile, urllib.quote_plus(mockTime.isoformat().split(".")[0]), appId, hashMpinId, signature)
        assert responseJson["clientSecretShare"] == clientSecret

        mockLog.assert_called_with("200 PUT {0}/eMpinActivation 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, userId, hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerActivationCodeGenerateCountThird(http_client, base_url, httpserver, httpsserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    forceActivate = False

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        None,
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"
    clientSecret = "040025066321f8b5b070b51ca2a809db13a1afe33a3c672c9272f287b64f0722680d54658b07e5850df4e7a363ad52944f4e3cb908118541cddeddf3a8ad9c791c"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }
    mockResponse2 = {
        "forceActivate": forceActivate
    }
    httpserver.serve_content(json.dumps(mockResponse), 200)
    httpsserver.serve_content(json.dumps(mockResponse2), 200)
    mockFunc = mocker.MagicMock(side_effect=[0,0,mockRandomInt])
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", mockFunc), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpsserver.url.decode("utf-8")), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        responseJson = json.loads(response.body)
        mpinIdJson = json.loads(responseJson["mpinId"].decode("hex"))
        assert mpinIdJson["mobile"] == mobile
        assert mpinIdJson["userID"] == userId
        expireTime = datetime.datetime.strptime(responseJson["expireTime"], "%Y-%m-%dT%H:%M:%S.%f")
        nowTime = datetime.datetime.strptime(responseJson["nowTime"], "%Y-%m-%dT%H:%M:%S.%f")
        assert (expireTime - nowTime).total_seconds() == 3600
        assert responseJson["active"] == forceActivate
        assert responseJson["activationCode"] == 0
        assert responseJson["params"] == "mobile={0}&expires={1}Z&app_id={2}&hash_mpin_id={3}&signature={4}&hash_user_id=".format(mobile, urllib.quote_plus(mockTime.isoformat().split(".")[0]), appId, hashMpinId, signature)
        assert responseJson["clientSecretShare"] == clientSecret

        mockLog.assert_called_with("200 PUT {0}/eMpinActivation 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, userId, hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerActivationCodeGenerateCountError(http_client, base_url, httpserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    forceActivate = False

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        None,
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"
    clientSecret = "040025066321f8b5b070b51ca2a809db13a1afe33a3c672c9272f287b64f0722680d54658b07e5850df4e7a363ad52944f4e3cb908118541cddeddf3a8ad9c791c"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }
    mockResponse2 = {
        "forceActivate": forceActivate
    }
    mockLog = mocker.Mock()
    httpserver.serve_content(json.dumps(mockResponse), 200)
    mockFunc = mocker.MagicMock(side_effect=[0,0,0])
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", mockFunc), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1  {1} {2} {3} Failed to generate non-zero activation code. {4}".format(baseURL, mpinId, userId, hashMpinId, "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerCapital(http_client, base_url, httpserver, httpsserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    forceActivate = False

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        None,
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"
    clientSecret = "040025066321f8b5b070b51ca2a809db13a1afe33a3c672c9272f287b64f0722680d54658b07e5850df4e7a363ad52944f4e3cb908118541cddeddf3a8ad9c791c"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179F07484d8db2d806095bAef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }
    mockResponse2 = {
        "forceActivate": forceActivate
    }
    httpserver.serve_content(json.dumps(mockResponse), 200)
    httpsserver.serve_content(json.dumps(mockResponse2), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpsserver.url.decode("utf-8")), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        responseJson = json.loads(response.body)
        mpinIdJson = json.loads(responseJson["mpinId"].decode("hex"))
        assert mpinIdJson["mobile"] == mobile
        assert mpinIdJson["userID"] == userId
        expireTime = datetime.datetime.strptime(responseJson["expireTime"], "%Y-%m-%dT%H:%M:%S.%f")
        nowTime = datetime.datetime.strptime(responseJson["nowTime"], "%Y-%m-%dT%H:%M:%S.%f")
        assert (expireTime - nowTime).total_seconds() == 3600
        assert responseJson["active"] == forceActivate
        assert responseJson["activationCode"] == 0
        assert responseJson["params"] == "mobile={0}&expires={1}Z&app_id={2}&hash_mpin_id={3}&signature={4}&hash_user_id=".format(mobile, urllib.quote_plus(mockTime.isoformat().split(".")[0]), appId, hashMpinId, signature)
        assert responseJson["clientSecretShare"] == clientSecret

        mockLog.assert_called_with("200 PUT {0}/eMpinActivation 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, userId, hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerUserIdValidLength256(http_client, base_url, httpserver, httpsserver, mocker):
    baseURL = "/rps"
    userId = "root@localhosttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    forceActivate = False

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        None,
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f73747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "50b4031b0bd55ddca5d8499c83132e98c3a5e690e0c033866dfc808d22f21f16"
    signature = "78609fb2e3d4bb391327221dce4392d1872b54e386d763205e069837263e4744"
    clientSecret = "0402cc7c857d8925816583e162bb9a202b3491002706d0172c3a4d4c688cc571f80fcd65746bdcd6c1d1f8fa19eb72855d69c8032f802550d2ab5ddc882daed881"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }
    mockResponse2 = {
        "forceActivate": forceActivate
    }
    httpserver.serve_content(json.dumps(mockResponse), 200)
    httpsserver.serve_content(json.dumps(mockResponse2), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpsserver.url.decode("utf-8")), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        responseJson = json.loads(response.body)
        mpinIdJson = json.loads(responseJson["mpinId"].decode("hex"))
        assert mpinIdJson["mobile"] == mobile
        assert mpinIdJson["userID"] == userId
        expireTime = datetime.datetime.strptime(responseJson["expireTime"], "%Y-%m-%dT%H:%M:%S.%f")
        nowTime = datetime.datetime.strptime(responseJson["nowTime"], "%Y-%m-%dT%H:%M:%S.%f")
        assert (expireTime - nowTime).total_seconds() == 3600
        assert responseJson["active"] == forceActivate
        assert responseJson["activationCode"] == 0
        assert responseJson["params"] == "mobile={0}&expires={1}Z&app_id={2}&hash_mpin_id={3}&signature={4}&hash_user_id=".format(mobile, urllib.quote_plus(mockTime.isoformat().split(".")[0]), appId, hashMpinId, signature)
        assert responseJson["clientSecretShare"] == clientSecret

        mockLog.assert_called_with("200 PUT {0}/eMpinActivation 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, userId, hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerUnnessesaryKeyError(http_client, base_url, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    userAgent = "unknown"
    body = {
            "mobile": mobile,
            "userId": userId,
            "unnecessaryKey":"test"
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        None,
        json.dumps(body)
    )

    mockLog = mocker.Mock()
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
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

            mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1  {1} {2} {3} Invalid data received. unnecessaryKey argument unnecessary {4}".format(baseURL, "", "", "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerUserIdInvalidLength257Error(http_client, base_url, httpserver, mocker):
    baseURL = "/rps"
    userId = "localhosttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    userAgent = "unknown"

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        None,
        json.dumps(body)
    )
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }

    httpserver.serve_content(json.dumps(mockResponse), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403
            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1  {1} {2} {3} Invalid data received. userId argument invalid length {4}".format(baseURL, "", userId, "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerMobileOne(http_client, base_url, httpserver, httpsserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 1
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    forceActivate = False

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        None,
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "71e9c8a13d95550c49e65b61864751fed4fd8876bf53d38f408b3056965c7956"
    signature = "324edd2dcbf74c65ffbfadd66345c0f28e48c3a530a158800053aba624ec421b"
    clientSecret = "04078ae5340163e21d55bda5d57d2ff4771ec936f5e420886d6a09e581461f249e040113e9c3ec0f0a0c54cbdde0e49d8f84e2ad8d3aac510dda55ba803fa1ba21"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179F07484d8db2d806095bAef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }
    mockResponse2 = {
        "forceActivate": forceActivate
    }
    httpserver.serve_content(json.dumps(mockResponse), 200)
    httpsserver.serve_content(json.dumps(mockResponse2), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpsserver.url.decode("utf-8")), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        responseJson = json.loads(response.body)
        mpinIdJson = json.loads(responseJson["mpinId"].decode("hex"))
        assert mpinIdJson["mobile"] == mobile
        assert mpinIdJson["userID"] == userId
        expireTime = datetime.datetime.strptime(responseJson["expireTime"], "%Y-%m-%dT%H:%M:%S.%f")
        nowTime = datetime.datetime.strptime(responseJson["nowTime"], "%Y-%m-%dT%H:%M:%S.%f")
        assert (expireTime - nowTime).total_seconds() == 3600
        assert responseJson["active"] == forceActivate
        assert responseJson["activationCode"] == 0
        assert responseJson["params"] == "mobile={0}&expires={1}Z&app_id={2}&hash_mpin_id={3}&signature={4}&hash_user_id=".format(mobile, urllib.quote_plus(mockTime.isoformat().split(".")[0]), appId, hashMpinId, signature)
        assert responseJson["clientSecretShare"] == clientSecret

        mockLog.assert_called_with("200 PUT {0}/eMpinActivation 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, userId, hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerUserIdInvalidCharacterFullError(http_client, base_url, httpserver, mocker):
    baseURL = "/rps"
    userId = "root@localhostＡ"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    userAgent = "unknown"
    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        None,
        json.dumps(body)
    )
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }

    httpserver.serve_content(json.dumps(mockResponse), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403
            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1  {1} {2} {3} Invalid data received. userId argument contains invalid characters {4}".format(baseURL, "", userId, "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerMobileInvalidNumber2Error(http_client, base_url, httpserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 2
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    userAgent = "unknown"
    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        None,
        json.dumps(body)
    )
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }

    httpserver.serve_content(json.dumps(mockResponse), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400
            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1  {1} {2} {3} Invalid data received. mobile argument invalid number {4}".format(baseURL, "", userId, "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerMobileInvalidNumberFullError(http_client, base_url, httpserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = "Ａ"
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        None,
        json.dumps(body)
    )
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }

    httpserver.serve_content(json.dumps(mockResponse), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400
            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1  {1} {2} {3} Cannot decode body as JSON. {4}".format(baseURL, "", userId, "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerMobileInvalidNumberAlphaError(http_client, base_url, httpserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = "a"
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        None,
        json.dumps(body)
    )
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }

    httpserver.serve_content(json.dumps(mockResponse), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400
            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1  {1} {2} {3} Cannot decode body as JSON. {4}".format(baseURL, "", userId, "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerMobileInvalidNumberSymbolsError(http_client, base_url, httpserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = "/"
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        None,
        json.dumps(body)
    )
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }

    httpserver.serve_content(json.dumps(mockResponse), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400
            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1  {1} {2} {3} Cannot decode body as JSON. {4}".format(baseURL, "", userId, "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerMobileInvalidValueError(http_client, base_url, httpserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = {}
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        None,
        json.dumps(body)
    )
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }

    httpserver.serve_content(json.dumps(mockResponse), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400
            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1  {1} {2} {3} Cannot decode body as JSON. {4}".format(baseURL, "", userId, "", "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerClientSecretInvalidLength131Error(http_client, base_url, httpserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        None,
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13560f",
        "message": "OK",
    }

    httpserver.serve_content(json.dumps(mockResponse), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 500
            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1  {1} {2} {3} Invalid data received. clientSecret invalid length {4}".format(baseURL, mpinId, userId, hashMpinId, "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerClientSecretInvalidLength129Error(http_client, base_url, httpserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        None,
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b1356",
        "message": "OK",
    }

    httpserver.serve_content(json.dumps(mockResponse), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 500
            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1  {1} {2} {3} Invalid data received. clientSecret invalid length {4}".format(baseURL, mpinId, userId, hashMpinId, "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerClientSecretInvalidCharacterFullError(http_client, base_url, httpserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        None,
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b1356Ａ",
        "message": "OK",
    }

    httpserver.serve_content(json.dumps(mockResponse), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 500
            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1  {1} {2} {3} Invalid data received. clientSecret contains invalid characters {4}".format(baseURL, mpinId, userId, hashMpinId, "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerClientSecretInvalidCharacterNotHexError(http_client, base_url, httpserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        None,
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b1356g",
        "message": "OK",
    }

    httpserver.serve_content(json.dumps(mockResponse), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 500
            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1  {1} {2} {3} Invalid data received. clientSecret contains invalid characters {4}".format(baseURL, mpinId, userId, hashMpinId, "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerClientSecretInvalidCharacterNotHexCapitalError(http_client, base_url, httpserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        None,
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b1356G",
        "message": "OK",
    }

    httpserver.serve_content(json.dumps(mockResponse), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 500
            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1  {1} {2} {3} Invalid data received. clientSecret contains invalid characters {4}".format(baseURL, mpinId, userId, hashMpinId, "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerClientSecretInvalidCharacterSymbolsError(http_client, base_url, httpserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        None,
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b1356/",
        "message": "OK",
    }

    httpserver.serve_content(json.dumps(mockResponse), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 500
            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1  {1} {2} {3} Invalid data received. clientSecret contains invalid characters {4}".format(baseURL, mpinId, userId, hashMpinId, "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerForceActivateInvalidTypeError(http_client, base_url, httpserver, httpsserver, mocker):
    baseURL = "/rps"
    userId = "root@localhost"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    forceActivate = "test"

    body = {
        "mobile": mobile,
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        None,
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }
    mockResponse2 = {
        "forceActivate": forceActivate
    }

    httpserver.serve_content(json.dumps(mockResponse), 200)
    httpsserver.serve_content(json.dumps(mockResponse2), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.options.mockable(), "RPAVerifyUserURL", httpsserver.url.decode("utf-8")), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 500
            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1  {1} {2} {3} Invalid data received. forceActivate invalid type {4}".format(baseURL, mpinId, userId, hashMpinId, "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinActivationHandlerNotMatchUserIdError(http_client, base_url, httpserver, mocker):
    baseURL = "/rps"
    userId = "1root@localhost"
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    forceActivate = False

    body = {
        "userId": userId
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinActivation".format(base_url, baseURL),
        "PUT",
        None,
        json.dumps(body)
    )
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a202231726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    hashMpinId = "61ec586f1e57219606f4bcb2dc0742602926c3889082a3f76f57b0fc7c54f353"
    signature = "5a7e95c3812b4699ec9b7b39de95e22c7a5a937e0f4257070ee99b2793fbb9fb"
    clientSecret = "040f03f596dcca370a4cc07d9485bc88648f532a6aa81d2c5339f560d37a66b1d123231fd1d59faafceac8ca3ecbb1d88ec4b1fb4d6496b1a38e33c2699428762a"

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockUrandomHex = "c6e2c0421939430518e847bbca26041f"
    mockRandomInt = 284065070394
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }
    httpserver.serve_content(json.dumps(mockResponse), 200)
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("os.urandom", return_value=mockUrandomHex.decode('hex')), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mocker.patch("rps.secrets.get_random_integer", return_value=mockRandomInt), mock.patch.object(rps.options.mockable(), "verifyIdentityRegex", "^.`@localhost.localdomain$".decode("utf-8")), mock.patch.object(rps.options.mockable(), "verifyIdentityShow", True), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/eMpinActivation 127.0.0.1  {1} {2} {3} Unmatch verifyIdentityRegex {4}".format(baseURL, mpinId, userId, hashMpinId, "unknown").decode("utf-8"))
