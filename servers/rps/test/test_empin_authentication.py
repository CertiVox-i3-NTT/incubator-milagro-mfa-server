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
def test_EMpinAuthenticationHandler(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"
    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )
    mockLog = mocker.Mock()
    with mocker.patch("rps.secrets.get_today",return_value=17115), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        print response.body
        responseJson = json.loads(response.body)
        pattern = re.compile("^[0-9a-z]+$", re.IGNORECASE)
        assert responseJson["version"] == "0.3"
        assert pattern.match(responseJson["authOTT"])
        assert responseJson["message"] == "eMpin Authentication is valid."

        nonceListCheck = http_server.storage.find(stage="empin-auth-nonce-list-check", mpinId=mpinId)
        assert nonceListCheck.nonce_list == [nonce]

        nonceCheck = http_server.storage.find(stage="empin-auth-nonce-check", mpinId=mpinId, nonce=nonce)
        isoFormat = re.compile("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}$")
        assert isoFormat.match(nonceCheck._expires)

        auth = http_server.storage.find(stage="auth", mpinId=mpinId.decode("hex"))
        assert isoFormat.match(auth._expires)
        assert auth.authOTT == responseJson["authOTT"]
        assert auth.wid == ""
        assert auth.webOTT == 0
        assert auth.authToken["mpin_id"] == mpinId.decode("hex")
        assert auth.authToken["mpin_id_hex"] == mpinId
        assert auth.authToken["successCode"] == 0
        assert auth.authToken["pinError"] == 0
        assert auth.authToken["pinErrorCost"] == 0
        assert auth.authToken["expires"] == "{0}Z".format(auth._expires)

        mockLog.assert_called_with("200 POST {0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4}".format(baseURL, xForwardedFor, mpinId, "ansible@localhost", hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerDelAttemptsCount(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"
    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockLog = mocker.Mock()
    http_server.storage.add(stage="empin-auth-attempts", mpinId=mpinId.decode("hex"), attemptsCount=rps.options.maxInvalidLoginAttempts - 1)
    with mocker.patch("rps.secrets.get_today",return_value=17115), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        responseJson = json.loads(response.body)
        pattern = re.compile("^[0-9a-z]+$", re.IGNORECASE)
        assert responseJson["version"] == "0.3"
        assert pattern.match(responseJson["authOTT"])
        assert responseJson["message"] == "eMpin Authentication is valid."

        nonceListCheck = http_server.storage.find(stage="empin-auth-nonce-list-check", mpinId=mpinId)
        assert nonceListCheck.nonce_list == [nonce]

        nonceCheck = http_server.storage.find(stage="empin-auth-nonce-check", mpinId=mpinId, nonce=nonce)
        isoFormat = re.compile("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}$")
        assert isoFormat.match(nonceCheck._expires)

        attempts = http_server.storage.find(stage="empin-auth-attempts", mpinId=mpinId.decode("hex"))
        assert attempts == None

        auth = http_server.storage.find(stage="auth", mpinId=mpinId.decode("hex"))
        assert isoFormat.match(auth._expires)
        assert auth.authOTT == responseJson["authOTT"]
        assert auth.wid == ""
        assert auth.webOTT == 0
        assert auth.authToken["mpin_id"] == mpinId.decode("hex")
        assert auth.authToken["mpin_id_hex"] == mpinId
        assert auth.authToken["successCode"] == 0
        assert auth.authToken["pinError"] == 0
        assert auth.authToken["pinErrorCost"] == 0
        assert auth.authToken["expires"] == "{0}Z".format(auth._expires)

        mockLog.assert_called_with("200 POST {0}/eMpinAuthentication 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, "ansible@localhost", hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerJsonError(http_client, base_url, mocker):
    baseURL = "/rps"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        "jsonError"
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, "", "", "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerErrorUserAgentEmpty(http_client, base_url, mocker):
    baseURL = "/rps"

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        None,
        "jsonError"
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1  {1} {2} {3} {4} {5}".format(baseURL, "", "", "", responseJson["message"], "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerKeyError(http_client, base_url, mocker):
    baseURL = "/rps"
    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, "", "", "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerKeyErrorUserAgentEmpty(http_client, base_url, mocker):
    baseURL = "/rps"
    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    body = {
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1  {1} {2} {3} {4} {5}".format(baseURL, "", "", "", responseJson["message"], "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerDecodeYError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mocker.patch("rps.secrets.hash_id", return_value="decodeError"), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerDecodeErrorUserAgentEmpty(http_client, base_url, mocker):
    baseURL = "/rps"
    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    body = {
        "MpinId": "decodeError",
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1  {1} {2} {3} {4} {5}".format(baseURL, "decodeError", "", "", responseJson["message"], "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerCheckNonceError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    http_server.storage.add(stage="empin-auth-nonce-list-check", mpinId=mpinId, nonce_list=[nonce])
    http_server.storage.add(stage="empin-auth-nonce-check", expire_time="2100-04-01T12:00:00", mpinId=mpinId, nonce=nonce)
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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
            assert responseJson["message"] == "Invalid nonce received."

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerCheckNonceErrorUserAgentEmpty(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    http_server.storage.add(stage="empin-auth-nonce-list-check", mpinId=mpinId, nonce_list=[nonce])
    http_server.storage.add(stage="empin-auth-nonce-check", expire_time="2100-04-01T12:00:00", mpinId=mpinId, nonce=nonce)
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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
            assert responseJson["message"] == "Invalid nonce received."

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1  {1} {2} {3} {4} {5}".format(baseURL, mpinId, userId, hashMpinId, responseJson["message"], "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerClientTimeError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-08-05T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("rps.secrets.get_today",return_value=17115), mock.patch.object(rps.log, "error", mockLog):
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
            assert responseJson["message"] == "Invalid client time received."

            args, kwargs = mockLog.call_args
            assert "{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} (timegap ".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"]) in args[0]
            assert ("sec) %s" % (userAgent)) in args[0]

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerClientTimeErrorUserAgentEmpty(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"

    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-08-05T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("rps.secrets.get_today",return_value=17115), mock.patch.object(rps.log, "error", mockLog):
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
            assert responseJson["message"] == "Invalid client time received."

            args, kwargs = mockLog.call_args
            assert "{0}/eMpinAuthentication 127.0.0.1  {1} {2} {3} {4} (timegap ".format(baseURL, mpinId, userId, hashMpinId, responseJson["message"]) in args[0]
            assert ("sec) unknown") in args[0]

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerMaxAttemptsCountError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()

    http_server.storage.add(stage="empin-auth-attempts", mpinId=mpinId.decode("hex"), attemptsCount=rps.options.maxInvalidLoginAttempts)
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("rps.secrets.get_today",return_value=17115), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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
            assert responseJson["message"] == "PIN attempts count is the limit."

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerMaxAttemptsCountErrorUserAgentEmpty(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"

    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()

    http_server.storage.add(stage="empin-auth-attempts", mpinId=mpinId.decode("hex"), attemptsCount=rps.options.maxInvalidLoginAttempts)
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("rps.secrets.get_today",return_value=17115), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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
            assert responseJson["message"] == "PIN attempts count is the limit."

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1  {1} {2} {3} {4} {5}".format(baseURL, mpinId, userId, hashMpinId, responseJson["message"], "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerVerifError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0401e7482112d56b21fad4450cfedbe110d2ecf324f5c856cd14249edc30248880208b9e8e04734102a54b6251505c4c9c21d8ea1104ec9d60b6ec95ea237d450f"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()

    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("rps.secrets.get_today",return_value=17115), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            attempts = http_server.storage.find(stage="empin-auth-attempts", mpinId=mpinId.decode("hex"))
            assert attempts.attemptsCount == 1

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerVerifErrorUserAgentEmpty(http_client, base_url, httpserver, httpsserver, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0401e7482112d56b21fad4450cfedbe110d2ecf324f5c856cd14249edc30248880208b9e8e04734102a54b6251505c4c9c21d8ea1104ec9d60b6ec95ea237d450f"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"

    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()

    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("rps.secrets.get_today",return_value=17115), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            attempts = http_server.storage.find(stage="empin-auth-attempts", mpinId=mpinId.decode("hex"))
            assert attempts.attemptsCount == 1

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1  {1} {2} {3} {4} {5}".format(baseURL, mpinId, userId, hashMpinId, responseJson["message"], "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerVerifMaxAttemptsCountError(http_client, base_url, httpserver, httpsserver, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0401e7482112d56b21fad4450cfedbe110d2ecf324f5c856cd14249edc30248880208b9e8e04734102a54b6251505c4c9c21d8ea1104ec9d60b6ec95ea237d450f"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )


    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()

    http_server.storage.add(stage="empin-auth-attempts", mpinId=mpinId.decode("hex"), attemptsCount=rps.options.maxInvalidLoginAttempts - 1)
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("rps.secrets.get_today",return_value=17115), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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
            assert responseJson["message"] == "PIN attempts count is the limit."

            attempts = http_server.storage.find(stage="empin-auth-attempts", mpinId=mpinId.decode("hex"))
            assert attempts.attemptsCount == rps.options.maxInvalidLoginAttempts

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerVerifMaxAttemptsCountErrorUserAgentEmpty(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0401e7482112d56b21fad4450cfedbe110d2ecf324f5c856cd14249edc30248880208b9e8e04734102a54b6251505c4c9c21d8ea1104ec9d60b6ec95ea237d450f"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"

    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()

    http_server.storage.add(stage="empin-auth-attempts", mpinId=mpinId.decode("hex"), attemptsCount=rps.options.maxInvalidLoginAttempts - 1)
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mocker.patch("rps.secrets.get_today",return_value=17115), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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
            assert responseJson["message"] == "PIN attempts count is the limit."

            attempts = http_server.storage.find(stage="empin-auth-attempts", mpinId=mpinId.decode("hex"))
            assert attempts.attemptsCount == rps.options.maxInvalidLoginAttempts

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1  {1} {2} {3} {4} {5}".format(baseURL, mpinId, userId, hashMpinId, responseJson["message"], "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerMpinIdMax(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d32392030363a35373a31312e383633373333222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226666666666666666666666666666666666666666666666666666666666666666227d"
    hashMpinId = "8ef00ae0b7eb0a5ab9437da1e6ed8ab69eb23ad0283dc6236c1419adca7be5b2"
    u = "0401e7482112d56b21fad4450cfedbe110d2ecf324f5c856cd14249edc30248880208b9e8e04734102a54b6251505c4c9c21d8ea1104ec9d60b6ec95ea237d450f"
    v = "040a117486494bee9f7afa7bb6377c9d435c208453af9d9f3262701a4e9d46d5ff1d72a6ca9a61cd5644c696c526d6ec6f44326b8ee8fbbf9e87c8408f70b33e8d"
    w = "041dfdcf02a90ea53f178188683b871d0b3361333912a5c7ff008253301cbd7b961fce4abbb8f1ba835a4318fcd6e05e4f50c59cff719dd7a3ae9bb9e5dfee974a"
    nonce = "60e7074185b38dcdabcf0ae4a7c036e541defb73562dd7dacfcffb8eeb0f0b8c"
    cct = "158aedf9181"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockLog = mocker.Mock()
    with mocker.patch("rps.secrets.get_today",return_value=17134), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        print response.body
        responseJson = json.loads(response.body)
        pattern = re.compile("^[0-9a-z]+$", re.IGNORECASE)
        assert responseJson["version"] == "0.3"
        assert pattern.match(responseJson["authOTT"])
        assert responseJson["message"] == "eMpin Authentication is valid."

        nonceListCheck = http_server.storage.find(stage="empin-auth-nonce-list-check", mpinId=mpinId)
        assert nonceListCheck.nonce_list == [nonce]

        nonceCheck = http_server.storage.find(stage="empin-auth-nonce-check", mpinId=mpinId, nonce=nonce)
        isoFormat = re.compile("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}$")
        assert isoFormat.match(nonceCheck._expires)

        auth = http_server.storage.find(stage="auth", mpinId=mpinId.decode("hex"))
        assert isoFormat.match(auth._expires)
        assert auth.authOTT == responseJson["authOTT"]
        assert auth.wid == ""
        assert auth.webOTT == 0
        assert auth.authToken["mpin_id"] == mpinId.decode("hex")
        assert auth.authToken["mpin_id_hex"] == mpinId
        assert auth.authToken["successCode"] == 0
        assert auth.authToken["pinError"] == 0
        assert auth.authToken["pinErrorCost"] == 0
        assert auth.authToken["expires"] == "{0}Z".format(auth._expires)

    	mockLog.assert_called_with("200 POST {0}/eMpinAuthentication 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, "root@localhost", hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerMpinIdMin(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d32392030373a30353a34352e303236303330222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20223030303030303030303030303030303030303030303030303030303030303030227d"
    hashMpinId = "9093734431da5282aec1ba52c02ad7fc9c8e5db359181acd9353e778e08bc37b"
    u = "0407a2fe2cf4fa2aa1dd939aaaecaed98738519417c8987669ccb00d2da33ab3f91d8ed63522f44fd6fa12d936864397db3a85a7d9133e4ffe67f7cc9b001dbe2f"
    v = "0412c595c8a9d6841af78cd78f29f75dc5dab334871c5fc153cffc3a2de73185890372cc671668c8a854a3473b3721fc5ef3764740ed394103d232fa19248780d5"
    w = "040d8431f1d92a2019c40c38794214226eb5725d727791709ab94de7025f136333083eaf50b38276fbe7b82c55f50e457d8d4e9e79cfd83a38126b2bd82b44205e"
    nonce = "647932a52a25133e954020f860b023275cae16b36e2af803a132aac7aa990fc1"
    cct = "158aee77a48"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockLog = mocker.Mock()
    with mocker.patch("rps.secrets.get_today",return_value=17134), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        print response.body
        responseJson = json.loads(response.body)
        pattern = re.compile("^[0-9a-z]+$", re.IGNORECASE)
        assert responseJson["version"] == "0.3"
        assert pattern.match(responseJson["authOTT"])
        assert responseJson["message"] == "eMpin Authentication is valid."

        nonceListCheck = http_server.storage.find(stage="empin-auth-nonce-list-check", mpinId=mpinId)
        assert nonceListCheck.nonce_list == [nonce]

        nonceCheck = http_server.storage.find(stage="empin-auth-nonce-check", mpinId=mpinId, nonce=nonce)
        isoFormat = re.compile("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}$")
        assert isoFormat.match(nonceCheck._expires)

        auth = http_server.storage.find(stage="auth", mpinId=mpinId.decode("hex"))
        assert isoFormat.match(auth._expires)
        assert auth.authOTT == responseJson["authOTT"]
        assert auth.wid == ""
        assert auth.webOTT == 0
        assert auth.authToken["mpin_id"] == mpinId.decode("hex")
        assert auth.authToken["mpin_id_hex"] == mpinId
        assert auth.authToken["successCode"] == 0
        assert auth.authToken["pinError"] == 0
        assert auth.authToken["pinErrorCost"] == 0
        assert auth.authToken["expires"] == "{0}Z".format(auth._expires)

      	mockLog.assert_called_with("200 POST {0}/eMpinAuthentication 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, "root@localhost", hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerNonceMax(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30352030323a35393a31352e373530313438222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20223662333330633462313734366163313462626133323739346462353363313533227d"
    hashMpinId = "6d368a9c355b0a3f3d240840afb3833c8abfc8b20c6712f047ba83c312fdda09"
    userId = "root@localhost"
    u = "040a7cbd7c028d2be0088d90717a6da6fd47992f73b852da1a5db2e159b6a4d5440bb75bf5ca9d9b5ac8297086eb34e914cea0ac59001deccd1427f64398bdb378"
    v = "041de666afc5a8f86d4732e6fc49eafd9dee941eb305104179bfb43b986055d9d720d49b9ad1d22a4ab1602d7e2e6cb401e83ca5d4d74870f65e0989e96fabfde6"
    w = "041e3b926a1550645bceef58c1b031968b9ca68995793f1f8a880a6a6fc169685a0cdef8661a81fc94e2093df4291162702f7a4c4b7dd4ebcf0403b236cc853ee8"
    nonce = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    cct = "158ccebfc38"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockLog = mocker.Mock()
    with mocker.patch("rps.secrets.get_today",return_value=17140), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        print response.body
        responseJson = json.loads(response.body)
        pattern = re.compile("^[0-9a-z]+$", re.IGNORECASE)
        assert responseJson["version"] == "0.3"
        assert pattern.match(responseJson["authOTT"])
        assert responseJson["message"] == "eMpin Authentication is valid."

        nonceListCheck = http_server.storage.find(stage="empin-auth-nonce-list-check", mpinId=mpinId)
        assert nonceListCheck.nonce_list == [nonce]

        nonceCheck = http_server.storage.find(stage="empin-auth-nonce-check", mpinId=mpinId, nonce=nonce)
        isoFormat = re.compile("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}$")
        assert isoFormat.match(nonceCheck._expires)

        auth = http_server.storage.find(stage="auth", mpinId=mpinId.decode("hex"))
        assert isoFormat.match(auth._expires)
        assert auth.authOTT == responseJson["authOTT"]
        assert auth.wid == ""
        assert auth.webOTT == 0
        assert auth.authToken["mpin_id"] == mpinId.decode("hex")
        assert auth.authToken["mpin_id_hex"] == mpinId
        assert auth.authToken["successCode"] == 0
        assert auth.authToken["pinError"] == 0
        assert auth.authToken["pinErrorCost"] == 0
        assert auth.authToken["expires"] == "{0}Z".format(auth._expires)

        mockLog.assert_called_with("200 POST {0}/eMpinAuthentication 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, userId, hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerNonceMin(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30312030353a35313a34382e313530303238222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20223161336430346662343031363130653162323532353639353430393563613462227d"
    hashMpinId = "03765f4dfef4f7124db96aeb7703f77a6ffa3e20e10187881f3e807d6a335264"
    userId = "root@localhost"
    u = "040f26a26da8415f22fee4db2e61e48d33e615fe73a2c0dc31d39e1a85f109b29512402124b167f44f871bd24488774c731fb85b31bb29369db6961637c903f012"
    v = "040430c93df540bcd920409b0437bbe4f97ee76982881b27fafcbafa9c65676df60b658300f563d40e056a94f7cf9d6d36042607c9b00994428433164a989f17fc"
    w = "0418683e79654a5c9f7fab9f70a7c7d84a9f821c50a874bb0fec0be97c41cde874229b16f74c44f9908b254255906e95cb01dc6fa66b65065a71ee38f02a6dc4c7"
    nonce = "0000000000000000000000000000000000000000000000000000000000000000"
    cct = "158b8b91cbb"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockLog = mocker.Mock()
    with mocker.patch("rps.secrets.get_today",return_value=17136), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        print response.body
        responseJson = json.loads(response.body)
        pattern = re.compile("^[0-9a-z]+$", re.IGNORECASE)
        assert responseJson["version"] == "0.3"
        assert pattern.match(responseJson["authOTT"])
        assert responseJson["message"] == "eMpin Authentication is valid."

        nonceListCheck = http_server.storage.find(stage="empin-auth-nonce-list-check", mpinId=mpinId)
        assert nonceListCheck.nonce_list == [nonce]

        nonceCheck = http_server.storage.find(stage="empin-auth-nonce-check", mpinId=mpinId, nonce=nonce)
        isoFormat = re.compile("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}$")
        assert isoFormat.match(nonceCheck._expires)

        auth = http_server.storage.find(stage="auth", mpinId=mpinId.decode("hex"))
        assert isoFormat.match(auth._expires)
        assert auth.authOTT == responseJson["authOTT"]
        assert auth.wid == ""
        assert auth.webOTT == 0
        assert auth.authToken["mpin_id"] == mpinId.decode("hex")
        assert auth.authToken["mpin_id_hex"] == mpinId
        assert auth.authToken["successCode"] == 0
        assert auth.authToken["pinError"] == 0
        assert auth.authToken["pinErrorCost"] == 0
        assert auth.authToken["expires"] == "{0}Z".format(auth._expires)

        mockLog.assert_called_with("200 POST {0}/eMpinAuthentication 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, userId, hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerXValueMax(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30312030353a35313a34382e313530303238222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20223161336430346662343031363130653162323532353639353430393563613462227d"
    hashMpinId = "03765f4dfef4f7124db96aeb7703f77a6ffa3e20e10187881f3e807d6a335264"
    userId = "root@localhost"
    u = "0402ae827f02b305687430dba11ee9abd4dc6449c7c4ef07d5697864132abef400119de6f6f20d34165e29f3fefb91af08991d7c690466fb6e796995e7a1a5a324"
    v = "040a195990860b76f143daf8b79900b4f4e3d1cd5f5c695d813830068bc4eb6f7815842be2c61206634a48d7801e648fe28a4f995b4c9d6b6d5f5a031055f23b87"
    w = "041b290f00fe8cfd2544bc509e24987be0da38e4ea5971340a688e8836b008d3c3106dec51586790c05bc7d474e474c1628b3cdeca681ab6d1bf36daf4124cca18"
    nonce = "c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8"
    cct = "158b8b91cbb"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockLog = mocker.Mock()
    with mocker.patch("rps.secrets.get_today",return_value=17136), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        print response.body
        responseJson = json.loads(response.body)
        pattern = re.compile("^[0-9a-z]+$", re.IGNORECASE)
        assert responseJson["version"] == "0.3"
        assert pattern.match(responseJson["authOTT"])
        assert responseJson["message"] == "eMpin Authentication is valid."

        nonceListCheck = http_server.storage.find(stage="empin-auth-nonce-list-check", mpinId=mpinId)
        assert nonceListCheck.nonce_list == [nonce]

        nonceCheck = http_server.storage.find(stage="empin-auth-nonce-check", mpinId=mpinId, nonce=nonce)
        isoFormat = re.compile("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}$")
        assert isoFormat.match(nonceCheck._expires)

        auth = http_server.storage.find(stage="auth", mpinId=mpinId.decode("hex"))
        assert isoFormat.match(auth._expires)
        assert auth.authOTT == responseJson["authOTT"]
        assert auth.wid == ""
        assert auth.webOTT == 0
        assert auth.authToken["mpin_id"] == mpinId.decode("hex")
        assert auth.authToken["mpin_id_hex"] == mpinId
        assert auth.authToken["successCode"] == 0
        assert auth.authToken["pinError"] == 0
        assert auth.authToken["pinErrorCost"] == 0
        assert auth.authToken["expires"] == "{0}Z".format(auth._expires)

        mockLog.assert_called_with("200 POST {0}/eMpinAuthentication 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, userId, hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerXValueMin(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31322d30322030353a35333a35342e323735323633222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20223030303030303030303030303030303030303030303030303030303030303030227d"
    hashMpinId = "59245f1edda4bc0830e7db620f9de0e8cc774c606274eab1d8ce66846bf3af04"
    userId = "root@localhost"
    u = "040e83b73a5edb52cd0e1df703005b3d423ff7855755e794231b033b79ec2d9dac02f8548bbcb195d309a71fdeb3565b2e7452496bea0b073fc509c0938d700fa4"
    v = "040c1771eb1c37933416553ee49930f91c521a8ed8e58a2d160a0fefc8fe1b68a0054bdeaaa7a457bc990376d12e85a34df0e9bd18b19ae06b891511bf70559183"
    w = "0411245f1eccc467eccf6c1c991ad7134283f79e8432626cee5c021ea5b3bd03a00c535b5b983c55f08ca742bad20a6284feedf2563b649f12ee622fe8b18990d8"
    nonce = "0000000000000000000000000000000000000000000000000000000000000000"
    cct = "158be189d16"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockLog = mocker.Mock()
    with mocker.patch("rps.secrets.get_today",return_value=17137), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        print response.body
        responseJson = json.loads(response.body)
        pattern = re.compile("^[0-9a-z]+$", re.IGNORECASE)
        assert responseJson["version"] == "0.3"
        assert pattern.match(responseJson["authOTT"])
        assert responseJson["message"] == "eMpin Authentication is valid."

        nonceListCheck = http_server.storage.find(stage="empin-auth-nonce-list-check", mpinId=mpinId)
        assert nonceListCheck.nonce_list == [nonce]

        nonceCheck = http_server.storage.find(stage="empin-auth-nonce-check", mpinId=mpinId, nonce=nonce)
        isoFormat = re.compile("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}$")
        assert isoFormat.match(nonceCheck._expires)

        auth = http_server.storage.find(stage="auth", mpinId=mpinId.decode("hex"))
        assert isoFormat.match(auth._expires)
        assert auth.authOTT == responseJson["authOTT"]
        assert auth.wid == ""
        assert auth.webOTT == 0
        assert auth.authToken["mpin_id"] == mpinId.decode("hex")
        assert auth.authToken["mpin_id_hex"] == mpinId
        assert auth.authToken["successCode"] == 0
        assert auth.authToken["pinError"] == 0
        assert auth.authToken["pinErrorCost"] == 0
        assert auth.authToken["expires"] == "{0}Z".format(auth._expires)

        mockLog.assert_called_with("200 POST {0}/eMpinAuthentication 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, userId, hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerCapital(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7B226D6F62696C65223A20302C2022697373756564223A2022323031372D30322D30312030333A34333A35322E333939303437222C2022757365724944223A2022726F6F74406C6F63616C686F7374222C202273616C74223A20223036656536633932333033646135366233636231623430666666376534613766227D"
    userId = "root@localhost"
    hashMpinId = "2e673ca59bd2c9a7dfcaf24bea69f38e8c4d767384a48226c3ab4e9500d72881"
    u = "04211cd7ad2cb56b59097a39ff52fe939615ca7c915ab388b574770872befb637e063076cab4268c9835c56a8cc2de5cda1e6f733627a622e363e36063b007eb21"
    v = "040d5F06d295d661A10eeabca17af93735172a5925dfea90381187ed82dce058e417a55d504552ae4904cc5213024f050ac5c3041fd692a7a245bba44e4b643c09"
    w = "04133ae8cff37d5264e5b98ed868d10f48852b1ca50bce982fde91c83fe76e7e8f18754c08a1ca9ea4278db79a1f0001b6648c97bf5afc47581a8b9269ac80f8bf"
    nonce = "d80ba8a8e6ccdd8deed22868a1d3bd0871b9a84403392abce876840d79101d88"
    cct = "159f7c64e37"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockLog = mocker.Mock()
    with mocker.patch("rps.secrets.get_today",return_value=17198), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        print response.body
        responseJson = json.loads(response.body)
        pattern = re.compile("^[0-9a-z]+$", re.IGNORECASE)
        assert responseJson["version"] == "0.3"
        assert pattern.match(responseJson["authOTT"])
        assert responseJson["message"] == "eMpin Authentication is valid."

        nonceListCheck = http_server.storage.find(stage="empin-auth-nonce-list-check", mpinId=mpinId)
        assert nonceListCheck.nonce_list == [nonce]

        nonceCheck = http_server.storage.find(stage="empin-auth-nonce-check", mpinId=mpinId, nonce=nonce)
        isoFormat = re.compile("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}$")
        assert isoFormat.match(nonceCheck._expires)

        auth = http_server.storage.find(stage="auth", mpinId=mpinId.decode("hex"))
        assert isoFormat.match(auth._expires)
        assert auth.authOTT == responseJson["authOTT"]
        assert auth.wid == ""
        assert auth.webOTT == 0
        assert auth.authToken["mpin_id"] == mpinId.decode("hex")
        assert auth.authToken["mpin_id_hex"] == mpinId
        assert auth.authToken["successCode"] == 0
        assert auth.authToken["pinError"] == 0
        assert auth.authToken["pinErrorCost"] == 0
        assert auth.authToken["expires"] == "{0}Z".format(auth._expires)

        mockLog.assert_called_with("200 POST {0}/eMpinAuthentication 127.0.0.1  {1} {2} {3}".format(baseURL, mpinId, userId, hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerCapitalError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7B226D6F62696C65223A20302C2022697373756564223A2022323031372D30322D30312030333A34333A35322E333939303437222C2022757365724944223A2022726F6F74406C6F63616C686F7374222C202273616C74223A20223036656536633932333033646135366233636231623430666666376534613766227D"
    userId = "root@localhost"
    hashMpinId = "2e673ca59bd2c9a7dfcaf24bea69f38e8c4d767384a48226c3ab4e9500d72881"

    u = "04211cd7Ad2cb56b59097a39Ff52fe939615ca7c915ab388b574770872befb637e063076cab4268c9835c56a8cc2de5cda1e6f733627a622e363e36063b007eb21"
    v = "04133Ae8cFf37d5264e5b98ed868d10f48852b1ca50bce982fde91c83fe76e7e8f18754c08a1ca9ea4278db79a1f0001b6648c97bf5afc47581a8b9269ac80f8bf"
    w = "040d5F06D295d661A10eeabca17af93735172a5925dfea90381187ed82dce058e417a55d504552ae4904cc5213024f050ac5c3041fd692a7a245bba44e4b643c09"
    nonce = "d80bAFa8e6ccdd8deed22868a1d3bd0871b9a84403392abce876840d79101d88"
    cct = "15AF7c64e37"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.secrets.get_today",return_value=17198), mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerUnnessesaryKeyError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct,
        "unnecessaryKey":"test"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, "", "", "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerUKeyError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerVKeyError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerWKeyError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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
            assert responseJson["message"] == "Invalid data received. W argument missing"

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerNonceKeyError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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
            assert responseJson["message"] == "Invalid data received. Nonce argument missing"

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerCCTKeyError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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
            assert responseJson["message"] == "Invalid data received. CCT argument missing"

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerMpinIdInvalidLengthError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, "", "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerMpinIdInvalidCharacterFullError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227dＡ"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, "", "", "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerMpinIdInvalidCharacterNotHexError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227g"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, "", "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerMpinIdInvalidCharacterNotHexCapitalError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227G"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, "", "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerMpinIdInvalidCharacterSymbolsError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227/"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, "", "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerUInvalidLength131Error(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"
    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692f"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerUInvalidLength129Error(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"
    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f0169"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerUInvalidCharacterFullError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f0169Ａ"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerUInvalidCharacterNotHexError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f0169g"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerUInvalidCharacterNotHexCapitalError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f0169G"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerUInvalidCharacterSymbolsError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f0169/"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerVInvalidLength131Error(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"
    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47af"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerVInvalidLength129Error(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"
    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerVInvalidCharacterFullError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47Ａ"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerVInvalidCharacterNotHexError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47g"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerVInvalidCharacterNotHexCapitalError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47G"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerVInvalidCharacterSymbolsError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47/"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerWInvalidLength131Error(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"
    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7f"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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
            assert responseJson["message"] == "Invalid data received. W argument invalid length"

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerWInvalidLength129Error(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"
    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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
            assert responseJson["message"] == "Invalid data received. W argument invalid length"

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerWInvalidCharacterFullError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ceＡ"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerWInvalidCharacterNotHexError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ceg"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerWInvalidCharacterNotHexCapitalError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ceG"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerWInvalidCharacterSymbolsError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce/"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerNonceInvalidLength65Error(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721cf"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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
            assert responseJson["message"] == "Invalid data received. Nonce argument invalid length"

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerNonceInvalidLength63Error(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"
    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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
            assert responseJson["message"] == "Invalid data received. Nonce argument invalid length"

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerNonceInvalidCharacterFullError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"
    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721Ａ"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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
            assert responseJson["message"] == "Invalid data received. Nonce argument contains invalid characters"

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerNonceInvalidCharacterNotHexError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"
    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721g"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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
            assert responseJson["message"] == "Invalid data received. Nonce argument contains invalid characters"

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerNonceInvalidCharacterNotHexCapitalError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"
    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721G"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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
            assert responseJson["message"] == "Invalid data received. Nonce argument contains invalid characters"

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerNonceInvalidCharacterSymbolsError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"
    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721/"
    cct = "1584cba487c"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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
            assert responseJson["message"] == "Invalid data received. Nonce argument contains invalid characters"

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerCCTInvalidValueError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721d"
    cct = {}
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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
            assert responseJson["message"] == "Invalid data received. int() can't convert non-string with explicit base"

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerCCTInvalidCharacterFullError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721d"
    cct = "1584cba487Ｃ"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerCCTInvalidCharacterNotHexError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721d"
    cct = "1584cba487g"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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
            assert responseJson["message"] == "Invalid data received. invalid literal for int() with base 16: '1584cba487g'"

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerCCTInvalidCharacterNotHexCapitalError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721d"
    cct = "1584cba487G"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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
            assert responseJson["message"] == "Invalid data received. invalid literal for int() with base 16: '1584cba487G'"

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerCCTInvalidCharacterSymbolsError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d31312d31302030353a33333a32382e363633343134222c2022757365724944223a2022616e7369626c65406c6f63616c686f7374222c202273616c74223a20226565383936386430643161636637633733643662366336623466363563626435227d"
    userId = "ansible@localhost"
    hashMpinId = "56f4c761982fa4b9a71cfb862852a37c036a5af7a42f1d8f4694b102bab0efbf"

    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721d"
    cct = "1584cba487/"
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog):
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
            assert responseJson["message"] == "Invalid data received. invalid literal for int() with base 16: '1584cba487/'"

            mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1 {1} {2} {3} {4} {5} {6}".format(baseURL, xForwardedFor, mpinId, userId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_EMpinAuthenticationHandlerUserIDGetFailed(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20312c2022697373756564223a2022323031372d30322d30322030393a31373a32392e313838353635222c202273616c74223a20226461303863393634663734326636653830613633373863613136366264646664227d"
    u = "0407a052906204495ae514b8f7e994ca6fb77c858fa7aa6f0324cd37462d7c7e1106aff90c4b1b578e6f350745b033666693a1b76a943a6d2481e5a6a721f01692"
    v = "04020edf9c5d7cb0ab8d606caf27e0df76329f409b5974d4c195fd461e09ca92760c51b59e8fc0c412f68bb96871ad74004997dd3fe36f9813d1f46c6808dbf47a"
    w = "0405b095f17730d377157cc65259db81fb14a8183eab1c24126613a842b611254402597ee0f181447f584d9fc0d00ab51f41dbcc4ed1bfe9a15bd3ce3702070ce7"
    nonce = "ee5cf55c3d5185355cf3a7e6107a297e65fd85c9784fc5a5c7d75afb689a721c"
    cct = "1584cba487c"
    body = {
        "MpinId": mpinId,
        "U": u,
        "V": v,
        "W": w,
        "Nonce": nonce,
        "CCT": cct
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/eMpinAuthentication".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockLog = mocker.Mock()
    mockWarnLog = mocker.Mock()
    with mocker.patch("rps.secrets.get_today",return_value=17115), mock.patch.object(rps.options.mockable(), "maxTimeGap", sys.maxint), mock.patch.object(rps.log, "error", mockLog), mock.patch.object(rps.log, "warn", mockWarnLog):
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

    	    mockLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1  {1} {2} {3} Invalid signature received. {4}".format(baseURL, mpinId, "", "", "unknown").decode("utf-8"))
            mockWarnLog.assert_called_with("{0}/eMpinAuthentication 127.0.0.1  {1} {2} {3} fail to get userID or hash mpinID {4}".format(baseURL, mpinId, "", "", "unknown").decode("utf-8"))
