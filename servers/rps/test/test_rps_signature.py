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
def test_RPSSignatureHandler(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    userId = "root@localhosttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
    mpin_id ={
        "userID":userId,
        "issued":"test",
        "salt":"test"
    }

    mpinId = json.dumps(mpin_id).encode("hex")

    mobile = 0

    hashMpinId = "9209a5400fb9e56617be0324ceed73a50bc555c79a8e832150d4f036dff1812f"

    signature = "5147033181c7d29a9a1153687cc3757341ab40327f40ff353c6e4467f3fcb79b"

    appId = "828aab3a428811e6b23b06df5546c0ed"

    regOTT = "9f86d081884c7d659a2feaa0c55ad015"

    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT,
    })

    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        rps.tornado.httputil.HTTPHeaders({"X-Forwarded-For": xForwardedFor}),
    )

    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    active = "859013fec7474cb6a76abf51e92fa6020bdad96995e81b615bc3060f4381361c"

    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }

    clientSecret = "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568"

    httpserver.serve_content(json.dumps(mockResponse), 200)
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT,active=active)
    mockLog = mocker.Mock()
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")

    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)
        responseJson = json.loads(response.body)
        assert response.code == 200

        assert responseJson["clientSecretShare"] == clientSecret
        assert responseJson["params"] == "mobile={0}&expires={1}Z&app_id={2}&hash_mpin_id={3}&signature={4}&hash_user_id=".format(mobile, urllib.quote_plus(mockTime.isoformat().split(".")[0]), appId, hashMpinId, signature)
        I = http_server.storage.find(stage="register", mpinId=mpinId)
        assert I == None

        mockLog.assert_called_with("200 GET {0}/signature/{1} 127.0.0.1 {2} {3} {4} {5}".format(baseURL, mpinId, xForwardedFor, mpinId, userId, hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerOptionalKey(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    mobile = 0

    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"

    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"

    appId = "828aab3a428811e6b23b06df5546c0ed"

    regOTT = "9f86d081884c7d659a2feaa0c55ad015"

    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT,
    })

    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        None
    )

    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    active = "4d59e989c86356dd38418934c980696be4291ad79a16c76abc8b34a09ed08a21"

    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568"
    }

    clientSecret = "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568"

    httpserver.serve_content(json.dumps(mockResponse), 200)
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT,active=active)
    mockLog = mocker.Mock()
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")

    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)
        responseJson = json.loads(response.body)
        assert response.code == 200

        assert responseJson["clientSecretShare"] == clientSecret
        assert responseJson["params"] == "mobile={0}&expires={1}Z&app_id={2}&hash_mpin_id={3}&signature={4}&hash_user_id=".format(mobile, urllib.quote_plus(mockTime.isoformat().split(".")[0]), appId, hashMpinId, signature)
        I = http_server.storage.find(stage="register", mpinId=mpinId)
        assert I == None

        mockLog.assert_called_with("200 GET {0}/signature/{1} 127.0.0.1  {2} {3} {4}".format(baseURL, mpinId, mpinId, "root@localhost", hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerMobileOne(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a202231222c2022697373756564223a202274657374222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a202274657374227d"

    mobile = 1

    hashMpinId = "549a5240df64fc2f7065a497ceb63575c783ec675691456409c90cb5fa161434"

    signature = "b02dfe11e9ae646420b931bba47930f3ee538356ca7c2eb77541f9594cdc6558"

    appId = "828aab3a428811e6b23b06df5546c0ed"

    regOTT = "9f86d081884c7d659a2feaa0c55ad015"

    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT,
    })

    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        None
    )

    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    active = "450cccc22669aa63b33f32850e8ee32652db3690e6486d955b38682b6d820b94"

    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }

    clientSecret = "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568"

    httpserver.serve_content(json.dumps(mockResponse), 200)
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT,active=active)
    mockLog = mocker.Mock()
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")

    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)
        responseJson = json.loads(response.body)
        assert response.code == 200

        assert responseJson["clientSecretShare"] == clientSecret
        assert responseJson["params"] == "mobile={0}&expires={1}Z&app_id={2}&hash_mpin_id={3}&signature={4}&hash_user_id=".format(mobile, urllib.quote_plus(mockTime.isoformat().split(".")[0]), appId, hashMpinId, signature)
        I = http_server.storage.find(stage="register", mpinId=mpinId)
        assert I == None

        mockLog.assert_called_with("200 GET {0}/signature/{1} 127.0.0.1  {2} {3} {4}".format(baseURL, mpinId, mpinId, "root@localhost", hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerCapital(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    mpinId = "7b226d6F62696c65223A20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    mobile = 0

    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"

    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"

    appId = "828aab3a428811e6b23b06df5546c0ed"

    regOTT = "9F86d081884c7d659a2feaa0c55ad015"

    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT,
    })

    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        None
    )

    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    active = "2726e9eae0325c96e1eb8e2f2d08e3b84d1aa050e9c7935eaf1a2273fe453a97"

    mockResponse = {
        "clientSecret": "04010Ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }

    clientSecret = "04010Ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568"

    httpserver.serve_content(json.dumps(mockResponse), 200)
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT,active=active)
    mockLog = mocker.Mock()
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")

    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)
        responseJson = json.loads(response.body)
        assert response.code == 200

        assert responseJson["clientSecretShare"] == clientSecret
        assert responseJson["params"] == "mobile={0}&expires={1}Z&app_id={2}&hash_mpin_id={3}&signature={4}&hash_user_id=".format(mobile, urllib.quote_plus(mockTime.isoformat().split(".")[0]), appId, hashMpinId, signature)
        I = http_server.storage.find(stage="register", mpinId=mpinId)
        assert I == None

        mockLog.assert_called_with("200 GET {0}/signature/{1} 127.0.0.1  {2} {3} {4}".format(baseURL, mpinId, mpinId, "root@localhost", hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerUnnessesaryKeyError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "unnecessaryKey":"test",
        "regOTT":regOTT,
    })
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
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

            mockLog.assert_called_with("{0}/signature/{1} 127.0.0.1 {2} {3} {4} {5} Invalid data received. unnecessaryKey argument unnecessary {6}".format(baseURL, mpinId, xForwardedFor, mpinId, "", "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerRegOTTKeyError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
    })
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
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

            mockLog.assert_called_with("{0}/signature/{1} 127.0.0.1 {2} {3} {4} {5} Missing argument regOTT {6}".format(baseURL, mpinId, xForwardedFor, mpinId, "", "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerRegOTTInvaliLengthPlusError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015f"
    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT
    })

    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        None
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

            mockLog.assert_called_with("{0}/signature/{1} 127.0.0.1  {2} {3} {4} Invalid data received. regOTT argument invalid length unknown".format(baseURL, mpinId, mpinId, "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerRegOTTInvaliLengthMinusError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    regOTT = "9f86d081884c7d659a2feaa0c55ad01"
    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT
    })
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
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

            mockLog.assert_called_with("{0}/signature/{1} 127.0.0.1 {2} {3} {4} {5} Invalid data received. regOTT argument invalid length {6}".format(baseURL, mpinId, xForwardedFor, mpinId, "", "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerRegOTTInvaliLengthCharacterFullError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    regOTT = "9f86d081884c7d659a2feaa0c55ad01Ａ"
    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT
    })
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
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

            mockLog.assert_called_with("{0}/signature/{1} 127.0.0.1 {2} {3} {4} {5} Invalid data received. regOTT argument contains invalid characters {6}".format(baseURL, mpinId, xForwardedFor, mpinId, "", "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerRegOTTInvaliLengthCharacterNotHexError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    regOTT = "9f86d081884c7d659a2feaa0c55ad01g"
    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT
    })

    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        None
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

            mockLog.assert_called_with("{0}/signature/{1} 127.0.0.1  {2} {3} {4} Invalid data received. regOTT argument contains invalid characters unknown".format(baseURL, mpinId, mpinId, "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerRegOTTInvaliLengthCharacterNotHexCapitalError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    regOTT = "9f86d081884c7d659a2feaa0c55ad01G"
    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT
    })

    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        None
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

            mockLog.assert_called_with("{0}/signature/{1} 127.0.0.1  {2} {3} {4} Invalid data received. regOTT argument contains invalid characters unknown".format(baseURL, mpinId, mpinId, "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerRegOTTInvaliLengthCharacterSymbolsError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"
    regOTT = "9f86d081884c7d659a2feaa0c55ad01/"
    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT
    })

    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        None
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

            mockLog.assert_called_with("{0}/signature/{1} 127.0.0.1  {2} {3} {4} Invalid data received. regOTT argument contains invalid characters unknown".format(baseURL, mpinId, mpinId, "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerMpinIdEmptyError(http_client, base_url, mocker):
    baseURL = "/rps"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    url = rps.url_concat(
    "{0}{1}/signature{2}".format(base_url, baseURL, ""), {
        "regOTT":regOTT
    })

    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        None
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
def test_RPSSignatureHandlerMpinIdInvalidLengthError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT
    })

    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        None
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

            mockLog.assert_called_with("{0}/signature/{1} 127.0.0.1  {2} {3} {4} Invalid data received. Odd-length string unknown".format(baseURL, mpinId, mpinId, "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerMpinIdInvalidCharacterFullError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227Ａ"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT
    })

    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        None
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
def test_RPSSignatureHandlerMpinIdInvalidCharacterNotHexError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227g"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT
    })

    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        None
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
def test_RPSSignatureHandlerMpinIdInvalidCharacterNotHexCapitalError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227G"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT
    })

    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        None
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
def test_RPSSignatureHandlerMpinIdInvalidCharacterSymbolsError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227/"
    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT
    })

    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        None
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
def test_RPSSignatureHandlerUserIdKeyError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpin_id ={
        "issued":"test",
        "mobile":"0",
        "salt":"test"
    }

    mpinId = json.dumps(mpin_id).encode("hex")

    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT
    })

    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        None
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

            mockLog.assert_called_with("{0}/signature/{1} 127.0.0.1  {2} {3} {4} Invalid data received. userID argument missing unknown".format(baseURL, mpinId, mpinId, "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerUserIdInValidLength257Error(http_client, base_url, mocker):
    baseURL = "/rps"
    userId = "root@localhostttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
    mpin_id ={
        "userID":userId,
        "issued":"test",
        "mobile":"0",
        "salt":"test"
    }
    mpinId = json.dumps(mpin_id).encode("hex")

    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT,
    })

    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        None
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

            mockLog.assert_called_with("{0}/signature/{1} 127.0.0.1  {2} {3} {4} Invalid data received. userID argument invalid length unknown".format(baseURL, mpinId, mpinId, userId, "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerMobileInvalidNumber2Error(http_client, base_url, mocker):
    baseURL = "/rps"
    userId = "root@localhostttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
    mpin_id ={
        "userID":userId,
        "issued":"test",
        "mobile":"2",
        "salt":"test"
    }
    mpinId = json.dumps(mpin_id).encode("hex")

    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT,
    })

    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        None
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

            mockLog.assert_called_with("{0}/signature/{1} 127.0.0.1  {2} {3} {4} Invalid data received. mobile argument invalid number unknown".format(baseURL, mpinId, mpinId, "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerMobileInvalidFullError(http_client, base_url, mocker):
    baseURL = "/rps"
    userId = "root@localhostttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
    mpin_id ={
        "userID":userId,
        "issued":"test",
        "mobile":"Ａ",
        "salt":"test"
    }
    mpinId = json.dumps(mpin_id).encode("hex")

    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT,
    })

    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        None
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

            mockLog.assert_called_with("{0}/signature/{1} 127.0.0.1  {2} {3} {4} Invalid data received.  unknown".format(baseURL, mpinId, mpinId, "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerMobileInvalidNumberAlpha2Error(http_client, base_url, mocker):
    baseURL = "/rps"
    userId = "root@localhostttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
    mpin_id ={
        "userID":userId,
        "issued":"test",
        "mobile":"test",
        "salt":"test"
    }
    mpinId = json.dumps(mpin_id).encode("hex")

    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT,
    })
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
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

            mockLog.assert_called_with("{0}/signature/{1} 127.0.0.1 {2} {3} {4} {5} Invalid data received. invalid literal for int() with base 10: 'test' {6}".format(baseURL, mpinId, xForwardedFor, mpinId, "", "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerMobileInvalidNumberSymbolsError(http_client, base_url, mocker):
    baseURL = "/rps"
    userId = "root@localhostttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
    mpin_id ={
        "userID":userId,
        "issued":"test",
        "mobile":"/",
        "salt":"test"
    }
    mpinId = json.dumps(mpin_id).encode("hex")

    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT,
    })
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
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

            mockLog.assert_called_with("{0}/signature/{1} 127.0.0.1 {2} {3} {4} {5} Invalid data received. invalid literal for int() with base 10: '/' {6}".format(baseURL, mpinId, xForwardedFor, mpinId, "", "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerMobileInvalidValueError(http_client, base_url, mocker):
    baseURL = "/rps"
    userId = "root@localhostttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
    mpin_id ={
        "userID":userId,
        "issued":"test",
        "mobile":{},
        "salt":"test"
    }
    mpinId = json.dumps(mpin_id).encode("hex")

    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT,
    })

    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        None
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

            mockLog.assert_called_with("{0}/signature/{1} 127.0.0.1  {2} {3} {4} Invalid data received. int() argument must be a string or a number, not 'dict' unknown".format(baseURL, mpinId, mpinId, "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerUserIdValidLength256(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    userId = "root@localhosttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"
    mpin_id ={
        "userID":userId,
        "issued":"test",
        "mobile":"0",
        "salt":"test"
    }

    mpinId = json.dumps(mpin_id).encode("hex")

    mobile = 0

    hashMpinId = "7dbc96e98b51897ba0a4d5603f81377040ea89d6bdb286a1db539e4a178ba313"

    signature = "326545d7318e495d67d093cb2f29bc2b3f27bd181acd2a8e64d63fe34f15ce41"

    appId = "828aab3a428811e6b23b06df5546c0ed"

    regOTT = "9f86d081884c7d659a2feaa0c55ad015"

    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT,
    })

    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        None
    )

    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    active = "859a057ac1dbc1b9a6cea666a5b2f1e8a60c5dc16df57b0a6f73d93ff982ee84"

    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }

    clientSecret = "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568"

    httpserver.serve_content(json.dumps(mockResponse), 200)
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT,active=active)
    mockLog = mocker.Mock()
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")

    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)
        responseJson = json.loads(response.body)
        assert response.code == 200

        assert responseJson["clientSecretShare"] == clientSecret
        assert responseJson["params"] == "mobile={0}&expires={1}Z&app_id={2}&hash_mpin_id={3}&signature={4}&hash_user_id=".format(mobile, urllib.quote_plus(mockTime.isoformat().split(".")[0]), appId, hashMpinId, signature)
        I = http_server.storage.find(stage="register", mpinId=mpinId)
        assert I == None

        mockLog.assert_called_with("200 GET {0}/signature/{1} 127.0.0.1  {2} {3} {4}".format(baseURL, mpinId, mpinId, userId, hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerUserIdInvalidCharacterFull(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    userId = "root@localhostＡ"
    mpin_id ={
        "userID":userId,
        "issued":"test",
        "mobile":"0",
        "salt":"test"
    }

    mpinId = json.dumps(mpin_id).encode("hex")

    mobile = 0

    hashMpinId = "7dbc96e98b51897ba0a4d5603f81377040ea89d6bdb286a1db539e4a178ba313"

    signature = "326545d7318e495d67d093cb2f29bc2b3f27bd181acd2a8e64d63fe34f15ce41"

    appId = "828aab3a428811e6b23b06df5546c0ed"

    regOTT = "9f86d081884c7d659a2feaa0c55ad015"

    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT,
    })

    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        None
    )

    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    active = "859a057ac1dbc1b9a6cea666a5b2f1e8a60c5dc16df57b0a6f73d93ff982ee84"

    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568",
        "message": "OK",
    }

    clientSecret = "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568"

    httpserver.serve_content(json.dumps(mockResponse), 200)
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT,active=active)
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

            mockLog.assert_called_with("{0}/signature/{1} 127.0.0.1  {2} {3} {4} Invalid data received. userID argument contains invalid characters unknown".format(baseURL, mpinId, mpinId, userId, "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerClientSecretKeyError(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"


    regOTT = "9f86d081884c7d659a2feaa0c55ad015"

    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT,
    })

    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        None
    )

    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    active = "4d59e989c86356dd38418934c980696be4291ad79a16c76abc8b34a09ed08a21"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    mockResponse = {
        "message": "OK",
    }


    httpserver.serve_content(json.dumps(mockResponse), 200)
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT,active=active)
    mockLog = mocker.Mock()
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")

    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/signature/{1} 127.0.0.1  {2} {3} {4} DTA /clientSecret Failed. Invalid JSON response unknown".format(baseURL, mpinId, mpinId, "root@localhost", hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerClientSecretInvalidLength131Error(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    regOTT = "9f86d081884c7d659a2feaa0c55ad015"

    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT,
    })

    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        None
    )

    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    active = "4d59e989c86356dd38418934c980696be4291ad79a16c76abc8b34a09ed08a21"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b13568f",
        "message": "OK",
    }


    httpserver.serve_content(json.dumps(mockResponse), 200)
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT,active=active)
    mockLog = mocker.Mock()
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")

    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/signature/{1} 127.0.0.1  {2} {3} {4} Invalid data received. clientSecret invalid length unknown".format(baseURL, mpinId, mpinId, "root@localhost", hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerClientSecretInvalidLength129Error(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    regOTT = "9f86d081884c7d659a2feaa0c55ad015"

    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT,
    })

    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        None
    )

    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    active = "4d59e989c86356dd38418934c980696be4291ad79a16c76abc8b34a09ed08a21"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b1356",
        "message": "OK",
    }

    httpserver.serve_content(json.dumps(mockResponse), 200)
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT,active=active)
    mockLog = mocker.Mock()
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")

    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/signature/{1} 127.0.0.1  {2} {3} {4} Invalid data received. clientSecret invalid length unknown".format(baseURL, mpinId, mpinId, "root@localhost", hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerClientSecretInvalidCharacterFullError(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    regOTT = "9f86d081884c7d659a2feaa0c55ad015"

    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT,
    })

    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        None
    )

    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    active = "4d59e989c86356dd38418934c980696be4291ad79a16c76abc8b34a09ed08a21"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b1356Ａ",
        "message": "OK",
    }


    httpserver.serve_content(json.dumps(mockResponse), 200)
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT,active=active)
    mockLog = mocker.Mock()
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")

    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/signature/{1} 127.0.0.1  {2} {3} {4} Invalid data received. clientSecret contains invalid characters unknown".format(baseURL, mpinId, mpinId, "root@localhost", hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerClientSecretInvalidCharacterNotHexError(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    regOTT = "9f86d081884c7d659a2feaa0c55ad015"

    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT,
    })

    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        None
    )

    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    active = "4d59e989c86356dd38418934c980696be4291ad79a16c76abc8b34a09ed08a21"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b1356g",
        "message": "OK",
    }


    httpserver.serve_content(json.dumps(mockResponse), 200)
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT,active=active)
    mockLog = mocker.Mock()
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")

    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/signature/{1} 127.0.0.1  {2} {3} {4} Invalid data received. clientSecret contains invalid characters unknown".format(baseURL, mpinId, mpinId, "root@localhost", hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerClientSecretInvalidCharacterNotHexCapitalError(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    regOTT = "9f86d081884c7d659a2feaa0c55ad015"

    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT,
    })

    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        None
    )

    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    active = "4d59e989c86356dd38418934c980696be4291ad79a16c76abc8b34a09ed08a21"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b1356G",
        "message": "OK",
    }


    httpserver.serve_content(json.dumps(mockResponse), 200)
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT,active=active)
    mockLog = mocker.Mock()
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")

    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/signature/{1} 127.0.0.1  {2} {3} {4} Invalid data received. clientSecret contains invalid characters unknown".format(baseURL, mpinId, mpinId, "root@localhost", hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerClientSecretInvalidCharacterSymbolsError(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    regOTT = "9f86d081884c7d659a2feaa0c55ad015"

    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT,
    })

    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        None
    )

    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    active = "4d59e989c86356dd38418934c980696be4291ad79a16c76abc8b34a09ed08a21"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b1356/",
        "message": "OK",
    }


    httpserver.serve_content(json.dumps(mockResponse), 200)
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT,active=active)
    mockLog = mocker.Mock()
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")

    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/signature/{1} 127.0.0.1  {2} {3} {4} Invalid data received. clientSecret contains invalid characters unknown".format(baseURL, mpinId, mpinId, "root@localhost", hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerClientSecretInvalidCharacterNotHexCapitalError(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    regOTT = "9f86d081884c7d659a2feaa0c55ad015"

    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT,
    })

    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        None
    )

    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    active = "4d59e989c86356dd38418934c980696be4291ad79a16c76abc8b34a09ed08a21"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b1356G",
        "message": "OK",
    }


    httpserver.serve_content(json.dumps(mockResponse), 200)
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT,active=active)
    mockLog = mocker.Mock()
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")

    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/signature/{1} 127.0.0.1  {2} {3} {4} Invalid data received. clientSecret contains invalid characters unknown".format(baseURL, mpinId, mpinId, "root@localhost", hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerResponseError(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    regOTT = "9f86d081884c7d659a2feaa0c55ad015"

    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT,
    })

    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        None
    )
    mobile = 0
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    active = "4d59e989c86356dd38418934c980696be4291ad79a16c76abc8b34a09ed08a21"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "1f86a9493998dec2aad5f3afb95226ebbd553778e798379085c505a8bf5d6cbc"
    httpserver.serve_content("", 500)
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTT,active=active)
    mockLog = mocker.Mock()
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")

    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_id", appId), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
            url = "{0}/clientSecret?mobile={1}&expires={2}Z&app_id={3}&hash_mpin_id={4}&signature={5}&hash_user_id=".format(httpserver.url, mobile, urllib.quote_plus(mockTime.isoformat().split(".")[0]), appId, hashMpinId, signature)

            mockLog.assert_called_with("{0}/signature/{1} 127.0.0.1  {2} {3} {4} DTA clientSecret failed, URL: {5}. Code: 500, Reason: INTERNAL SERVER ERROR unknown".format(baseURL, mpinId, mpinId, "root@localhost", hashMpinId, url).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSSignatureHandlerNotMatchRegOTT(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227d"

    regOTT = "9f86d081884c7d659a2feaa0c55ad015"
    regOTTDB = "9f86d081884c7d659a2feaa0c55ad016"

    url = rps.url_concat(
    "{0}{1}/signature/{2}".format(base_url, baseURL, mpinId), {
        "regOTT":regOTT,
    })

    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        None
    )

    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    active = "4d59e989c86356dd38418934c980696be4291ad79a16c76abc8b34a09ed08a21"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    mockResponse = {
        "clientSecret": "04010ec01050179f07484d8db2d806095baef147b0466527efd86ba4a9aa40974b2075a354962403fd97d2d0b4fa100cad38c1309b712d7923b73367d611b1356G",
        "message": "OK",
    }


    httpserver.serve_content(json.dumps(mockResponse), 200)
    http_server.storage.add(stage="register", mpinId=mpinId, regOTT=regOTTDB,active=active)
    mockLog = mocker.Mock()
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")

    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/signature/{1} 127.0.0.1  {2} {3} {4} MpinID {5} regOTT does not match! unknown".format(baseURL, mpinId, mpinId, "root@localhost", "", mpinId).decode("utf-8"))
