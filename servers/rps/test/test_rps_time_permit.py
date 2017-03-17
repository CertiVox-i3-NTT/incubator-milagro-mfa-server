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
def test_RPSTimePermitHandler(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    timePermit = "04202140d7034aa274b841decbb0d06e9938c53d278c63f073815df52a28bf2aa91e6755e0cc0e528cc3ccac056f11111f849bf8fa7a2f1b7b5416721eb22a069f"
    xForwardedFor = "127.0.0.1"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30372d32392030383a34323a31362e373834383636222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20223235353036643933303334636363626236346437613136623630366435616533227d"

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/timePermit/{2}".format(base_url, baseURL, mpinId),
        "GET",
        rps.tornado.httputil.HTTPHeaders({"X-Forwarded-For": xForwardedFor})
    )

    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    storageId = "cd4846168f526075b4068da74078c4d8a9e5eeb179148540b3ec7fe1f91a5e95"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinIdHex = "cd4846168f526075b4068da74078c4d8a9e5eeb179148540b3ec7fe1f91a5e95"
    mockResponse = {
        "timePermits": {
            rps.secrets.today(): timePermit
        },
        "message": "OK"
    }
    mockLog = mocker.Mock()
    httpserver.serve_content(json.dumps(mockResponse), 200)
    with mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Cache-Control") == "no-cache"

        print response.body
        responseJson = json.loads(response.body)
        assert responseJson["date"] == rps.secrets.today()
        assert responseJson["signature"] == signature
        assert responseJson["storageId"] == storageId
        assert responseJson["message"] == "M-Pin Time Permit Generated"
        assert responseJson["timePermit"] == timePermit
        assert responseJson["version"] == "0.3"

        cacheTimePermit = http_server.storage.find(time_permit_id=storageId, time_permit_date=rps.secrets.today())
        assert cacheTimePermit._expires == (datetime.datetime.fromtimestamp(int(rps.secrets.today()) * 60 * 1440) + datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S")
        assert cacheTimePermit.time_permit == timePermit

        mockLog.assert_called_with("200 GET {0}/timePermit/{1} 127.0.0.1 {2} {3} {4} {5}".format(baseURL, mpinId, xForwardedFor, mpinId, "", hashMpinIdHex).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSTimePermitHandlerCapital(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    timePermit = "04202140d7034aa274b841decbb0d06e9938c53d278c63f073815df52a28bf2aa91e6755e0cc0e528cc3ccac056f11111f849bf8fa7a2f1b7b5416721eb22a069f"
    mpinId = "7b226d6F62696C65223A20302c2022697373756564223a2022323031362d30372d32392030383a34323a31362e373834383636222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20223235353036643933303334636363626236346437613136623630366435616533227d"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    storageId = "cd4846168f526075b4068da74078c4d8a9e5eeb179148540b3ec7fe1f91a5e95"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinIdHex = "cd4846168f526075b4068da74078c4d8a9e5eeb179148540b3ec7fe1f91a5e95"
    mockResponse = {
        "timePermits": {
            rps.secrets.today(): timePermit
        }
    }
    mockLog = mocker.Mock()
    httpserver.serve_content(json.dumps(mockResponse), 200)
    with mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch("{0}{1}/timePermit/{2}".format(base_url, baseURL, mpinId))

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Cache-Control") == "no-cache"

        print response.body
        responseJson = json.loads(response.body)
        assert responseJson["date"] == rps.secrets.today()
        assert responseJson["signature"] == signature
        assert responseJson["storageId"] == storageId
        assert responseJson["message"] == "M-Pin Time Permit Generated"
        assert responseJson["timePermit"] == timePermit
        assert responseJson["version"] == "0.3"

        cacheTimePermit = http_server.storage.find(time_permit_id=storageId, time_permit_date=rps.secrets.today())
        assert cacheTimePermit._expires == (datetime.datetime.fromtimestamp(int(rps.secrets.today()) * 60 * 1440) + datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S")
        assert cacheTimePermit.time_permit == timePermit

        mockLog.assert_called_with("200 GET {0}/timePermit/{1} 127.0.0.1  {2} {3} {4}".format(baseURL, mpinId, mpinId, "", hashMpinIdHex).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSTimePermitHandlerPermitUser(http_client, base_url, mocker, httpserver, httpsserver):
    baseURL = "/rps"
    timePermit = "04202140d7034aa274b841decbb0d06e9938c53d278c63f073815df52a28bf2aa91e6755e0cc0e528cc3ccac056f11111f849bf8fa7a2f1b7b5416721eb22a069f"
    timePermit2 = "041fad02b21937badb32b7bb71dc19364e6da43eb0b274b95ad0d4c25aaeb55e5b06c6e062812216aaa617ff29b157cefb5740f9dd19b30e869b53cfa92deae90a"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30372d32392030383a34323a31362e373834383636222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20223235353036643933303334636363626236346437613136623630366435616533227d"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    storageId = "cd4846168f526075b4068da74078c4d8a9e5eeb179148540b3ec7fe1f91a5e95"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinIdHex = "cd4846168f526075b4068da74078c4d8a9e5eeb179148540b3ec7fe1f91a5e95"
    mockResponse = {
        "timePermits": {
            rps.secrets.today(): timePermit,
            str(int(rps.secrets.today()) + 1): timePermit2
        },
        "message": "OK"
    }
    mockLog = mocker.Mock()
    httpserver.serve_content(json.dumps(mockResponse), 200)
    httpsserver.serve_content("", 200)
    with mock.patch.object(rps.options.mockable(), "RPAPermitUserURL", httpsserver.url.decode("utf-8")), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", new=appKey), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch("{0}{1}/timePermit/{2}".format(base_url, baseURL, mpinId))

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Cache-Control") == "no-cache"

        responseJson = json.loads(response.body)
        assert responseJson["date"] == rps.secrets.today()
        assert responseJson["signature"] == signature
        assert responseJson["storageId"] == storageId
        assert responseJson["message"] == "M-Pin Time Permit Generated"
        assert responseJson["timePermit"] == timePermit
        assert responseJson["version"] == "0.3"

        cacheTimePermit = http_server.storage.find(time_permit_id=storageId, time_permit_date=rps.secrets.today())
        assert cacheTimePermit._expires == (datetime.datetime.fromtimestamp(int(rps.secrets.today()) * 60 * 1440) + datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S")
        assert cacheTimePermit.time_permit == timePermit
        cacheTimePermit = http_server.storage.find(time_permit_id=storageId, time_permit_date=str(int(rps.secrets.today()) + 1))
        assert cacheTimePermit._expires == (datetime.datetime.fromtimestamp(int(rps.secrets.today() + 1) * 60 * 1440) + datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S")
        assert cacheTimePermit.time_permit == timePermit2

        mockLog.assert_called_with("200 GET {0}/timePermit/{1} 127.0.0.1  {2} {3} {4}".format(baseURL, mpinId, mpinId, "", hashMpinIdHex).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSTimePermitHandlerCacheExist(http_client, base_url, mocker):
    baseURL = "/rps"
    timePermit = "04202140d7034aa274b841decbb0d06e9938c53d278c63f073815df52a28bf2aa91e6755e0cc0e528cc3ccac056f11111f849bf8fa7a2f1b7b5416721eb22a069f"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30372d32392030383a34323a31362e373834383636222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20223235353036643933303334636363626236346437613136623630366435616533227d"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    storageId = "cd4846168f526075b4068da74078c4d8a9e5eeb179148540b3ec7fe1f91a5e95"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinIdHex = "cd4846168f526075b4068da74078c4d8a9e5eeb179148540b3ec7fe1f91a5e95"
    mockLog = mocker.Mock()
    http_server.storage.add(expire_time="2100-04-01T12:00:00", time_permit_id=storageId, time_permit_date=rps.secrets.today(), time_permit=timePermit)
    with mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch("{0}{1}/timePermit/{2}".format(base_url, baseURL, mpinId))

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Cache-Control") == "no-cache"

        print response.body
        responseJson = json.loads(response.body)
        assert responseJson["date"] == rps.secrets.today()
        assert responseJson["signature"] == signature
        assert responseJson["storageId"] == storageId
        assert responseJson["message"] == "M-Pin Time Permit Generated"
        assert responseJson["timePermit"] == timePermit
        assert responseJson["version"] == "0.3"

        mockLog.assert_called_with("200 GET {0}/timePermit/{1} 127.0.0.1  {2} {3} {4}".format(baseURL, mpinId, mpinId, "", hashMpinIdHex).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSTimePermitHandlerCacheFalse(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    timePermit = "04202140d7034aa274b841decbb0d06e9938c53d278c63f073815df52a28bf2aa91e6755e0cc0e528cc3ccac056f11111f849bf8fa7a2f1b7b5416721eb22a069f"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30372d32392030383a34323a31362e373834383636222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20223235353036643933303334636363626236346437613136623630366435616533227d"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    storageId = "cd4846168f526075b4068da74078c4d8a9e5eeb179148540b3ec7fe1f91a5e95"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinIdHex = "cd4846168f526075b4068da74078c4d8a9e5eeb179148540b3ec7fe1f91a5e95"
    mockResponse = {
        "timePermits": {
            rps.secrets.today(): timePermit
        },
        "message": "OK"
    }
    mockLog = mocker.Mock()
    httpserver.serve_content(json.dumps(mockResponse), 200)
    with mock.patch.object(rps.options.mockable(), "cacheTimePermits", False), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch("{0}{1}/timePermit/{2}".format(base_url, baseURL, mpinId))

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
        assert response.headers.get("Cache-Control") == "no-cache"

        print response.body
        responseJson = json.loads(response.body)
        assert responseJson["date"] == rps.secrets.today()
        assert responseJson["signature"] == signature
        assert responseJson["storageId"] == storageId
        assert responseJson["message"] == "M-Pin Time Permit Generated"
        assert responseJson["timePermit"] == timePermit
        assert responseJson["version"] == "0.3"

        cacheTimePermit = http_server.storage.find(time_permit_id=storageId, time_permit_date=rps.secrets.today())
        assert cacheTimePermit == None

        mockLog.assert_called_with("200 GET {0}/timePermit/{1} 127.0.0.1  {2} {3} {4}".format(baseURL, mpinId, mpinId, "", hashMpinIdHex).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSTimePermitHandlerUnneccesaryKeyError(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30372d32392030383a34323a31362e373834383636222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20223235353036643933303334636363626236346437613136623630366435616533227d"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    storageId = "cd4846168f526075b4068da74078c4d8a9e5eeb179148540b3ec7fe1f91a5e95"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"

    mockResponse = {
        "message": "OK"
    }

    url = rps.url_concat("{0}{1}/timePermit/{2}".format(base_url, baseURL, mpinId), {
        "unnecessaryKey":"test"
    })
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        url,
        "GET",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
    )
    httpserver.serve_content(json.dumps(mockResponse), 200)
    mockLog = mocker.Mock()
    with mock.patch.object(rps.options.mockable(), "cacheTimePermits", False), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/timePermit/{1} 127.0.0.1 {2} {3} {4} {5} Invalid data received. unnecessaryKey argument unnecessary {6}".format(baseURL, mpinId, xForwardedFor, mpinId, "", "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSTimePermitHandlerTimePermitKeyError(http_client, base_url, mocker, httpserver):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30372d32392030383a34323a31362e373834383636222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20223235353036643933303334636363626236346437613136623630366435616533227d"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    storageId = "cd4846168f526075b4068da74078c4d8a9e5eeb179148540b3ec7fe1f91a5e95"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinIdHex = "cd4846168f526075b4068da74078c4d8a9e5eeb179148540b3ec7fe1f91a5e95"
    mockResponse = {
        "message": "OK"
    }
    httpserver.serve_content(json.dumps(mockResponse), 200)
    mockLog = mocker.Mock()
    with mock.patch.object(rps.options.mockable(), "cacheTimePermits", False), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch("{0}{1}/timePermit/{2}".format(base_url, baseURL, mpinId))
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/timePermit/{1} 127.0.0.1  {2} {3} {4} DTA /timePermit Failed. Invalid JSON response: {5} unknown".format(baseURL, mpinId, "", "", hashMpinIdHex, '{"message": "OK"}').decode("utf-8"))

@pytest.mark.gen_test
def test_RPSTimePermitHandlerMpinIdEmptyError(http_client, base_url, mocker):
    baseURL = "/rps"

    try:
        response = yield http_client.fetch("{0}{1}/timePermit{2}".format(base_url, baseURL, ""))
        assert False
    except rps.tornado.httpclient.HTTPError as e:
        assert e.code == 404

        assert e.message == "HTTP 404: URI NOT FOUND"
        assert e.response.headers.get("Access-Control-Allow-Origin") == None
        assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

@pytest.mark.gen_test
def test_RPSTimePermitHandlerMpinIdInvalidLengthError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227"

    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch("{0}{1}/timePermit/{2}".format(base_url, baseURL, mpinId))
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/timePermit/{1} 127.0.0.1  {2} {3} {4} Invalid data received. MpinId argument invalid length unknown".format(baseURL, mpinId, mpinId, "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSTimePermitHandlerMpinIdInvalidCharacterFullError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227Ａ"

    try:
        response = yield http_client.fetch("{0}{1}/timePermit/{2}".format(base_url, baseURL, mpinId))
        assert False
    except rps.tornado.httpclient.HTTPError as e:
        assert e.code == 404

        assert e.message == "HTTP 404: URI NOT FOUND"
        assert e.response.headers.get("Access-Control-Allow-Origin") == None
        assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

@pytest.mark.gen_test
def test_RPSTimePermitHandlerMpinIdInvalidCharacterNotHexError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227g"

    try:
        response = yield http_client.fetch("{0}{1}/timePermit/{2}".format(base_url, baseURL, mpinId))
        assert False
    except rps.tornado.httpclient.HTTPError as e:
        assert e.code == 404

        assert e.message == "HTTP 404: URI NOT FOUND"
        assert e.response.headers.get("Access-Control-Allow-Origin") == None
        assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

@pytest.mark.gen_test
def test_RPSTimePermitHandlerMpinIdInvalidCharacterNotHexCapitalError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227G"

    try:
        response = yield http_client.fetch("{0}{1}/timePermit/{2}".format(base_url, baseURL, mpinId))
        assert False
    except rps.tornado.httpclient.HTTPError as e:
        assert e.code == 404

        assert e.message == "HTTP 404: URI NOT FOUND"
        assert e.response.headers.get("Access-Control-Allow-Origin") == None
        assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

@pytest.mark.gen_test
def test_RPSTimePermitHandlerMpinIdInvalidCharacterSymbolsError(http_client, base_url, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30342d30312031323a30303a30302e303030303031222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226336653263303432313933393433303531386538343762626361323630343166227/"

    try:
        response = yield http_client.fetch("{0}{1}/timePermit/{2}".format(base_url, baseURL, mpinId))
        assert False
    except rps.tornado.httpclient.HTTPError as e:
        assert e.code == 404

        assert e.message == "HTTP 404: URI NOT FOUND"
        assert e.response.headers.get("Access-Control-Allow-Origin") == None
        assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

@pytest.mark.gen_test
def test_RPSTimePermitHandlerDTAError(http_client, base_url, httpserver, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30372d32392030383a34323a31362e373834383636222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20223235353036643933303334636363626236346437613136623630366435616533227d"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    storageId = "cd4846168f526075b4068da74078c4d8a9e5eeb179148540b3ec7fe1f91a5e95"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinIdHex = "cd4846168f526075b4068da74078c4d8a9e5eeb179148540b3ec7fe1f91a5e95"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/timePermit/{2}".format(base_url, baseURL, mpinId),
        "GET",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
    )
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockCount = 7
    mockLog = mocker.Mock()
    mockCode = 500
    httpserver.serve_content("", mockCode)
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mocker.patch("rps.random.randint", return_value=mockCount), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/timePermit/{1} 127.0.0.1 {2} {3} {4} {5} DTA timePermit failed, URL: {6}/timePermits?count={7}&hash_mpin_id={8}&signature={9}. Code: {10}, Reason: INTERNAL SERVER ERROR {11}".format(baseURL, mpinId, xForwardedFor, "", "", hashMpinIdHex, httpserver.url, mockCount, hashMpinIdHex, signature, mockCode, userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSTimePermitHandlerDTAErrorUserAgentEmpty(http_client, base_url, httpserver, mocker):
    baseURL = "/rps"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30372d32392030383a34323a31362e373834383636222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20223235353036643933303334636363626236346437613136623630366435616533227d"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    storageId = "cd4846168f526075b4068da74078c4d8a9e5eeb179148540b3ec7fe1f91a5e95"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinIdHex = "cd4846168f526075b4068da74078c4d8a9e5eeb179148540b3ec7fe1f91a5e95"

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/timePermit/{2}".format(base_url, baseURL, mpinId),
        "GET",
        None
    )
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockCount = 7
    mockLog = mocker.Mock()
    mockCode = 500
    httpserver.serve_content("", mockCode)
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mocker.patch("rps.random.randint", return_value=mockCount), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/timePermit/{1} 127.0.0.1  {2} {3} {4} DTA timePermit failed, URL: {5}/timePermits?count={6}&hash_mpin_id={7}&signature={8}. Code: {9}, Reason: INTERNAL SERVER ERROR unknown".format(baseURL, mpinId, "", "", hashMpinIdHex, httpserver.url, mockCount, hashMpinIdHex, signature, mockCode).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSTimePermitHandlerDTAResponseJSONError(http_client, base_url, httpserver, mocker):
    baseURL = "/rps"
    timePermit = "04202140d7034aa274b841decbb0d06e9938c53d278c63f073815df52a28bf2aa91e6755e0cc0e528cc3ccac056f11111f849bf8fa7a2f1b7b5416721eb22a069f"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30372d32392030383a34323a31362e373834383636222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20223235353036643933303334636363626236346437613136623630366435616533227d"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    storageId = "cd4846168f526075b4068da74078c4d8a9e5eeb179148540b3ec7fe1f91a5e95"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinIdHex = "cd4846168f526075b4068da74078c4d8a9e5eeb179148540b3ec7fe1f91a5e95"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/timePermit/{2}".format(base_url, baseURL, mpinId),
        "GET",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
    )
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockCount = 7
    mockLog = mocker.Mock()
    mockCode = 200
    httpserver.serve_content("jsonError", mockCode)
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", appKey), mocker.patch("rps.random.randint", return_value=mockCount), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/timePermit/{1} 127.0.0.1 {2} {3} {4} {5} DTA /timePermit Failed. Invalid JSON response: jsonError {6}".format(baseURL, mpinId, xForwardedFor, "", "", hashMpinIdHex, userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSTimePermitHandlerDTAResponseDateInvalidInteger(http_client, base_url, httpserver, mocker):
    baseURL = "/rps"
    timePermit = "04202140d7034aa274b841decbb0d06e9938c53d278c63f073815df52a28bf2aa91e6755e0cc0e528cc3ccac056f11111f849bf8fa7a2f1b7b5416721eb22a069f"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30372d32392030383a34323a31362e373834383636222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20223235353036643933303334636363626236346437613136623630366435616533227d"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    storageId = "cd4846168f526075b4068da74078c4d8a9e5eeb179148540b3ec7fe1f91a5e95"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinIdHex = "cd4846168f526075b4068da74078c4d8a9e5eeb179148540b3ec7fe1f91a5e95"

    mockResponse = {
        "timePermits": {
            "aa": timePermit
        },
        "message": "OK"
    }
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/timePermit/{2}".format(base_url, baseURL, mpinId),
        "GET",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
    )
    mockLog = mocker.Mock()
    httpserver.serve_content(json.dumps(mockResponse), 200)
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", new=appKey), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/timePermit/{1} 127.0.0.1 {2} {3} {4} {5} DTA /timePermit Failed. Date invalid integer {6}".format(baseURL, mpinId, xForwardedFor, "", "", hashMpinIdHex, userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSTimePermitHandlerDTAResponseDateInvalidIntegerUserAgentEmpty(http_client, base_url, httpserver, mocker):
    baseURL = "/rps"
    timePermit = "04202140d7034aa274b841decbb0d06e9938c53d278c63f073815df52a28bf2aa91e6755e0cc0e528cc3ccac056f11111f849bf8fa7a2f1b7b5416721eb22a069f"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30372d32392030383a34323a31362e373834383636222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20223235353036643933303334636363626236346437613136623630366435616533227d"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    storageId = "cd4846168f526075b4068da74078c4d8a9e5eeb179148540b3ec7fe1f91a5e95"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinIdHex = "cd4846168f526075b4068da74078c4d8a9e5eeb179148540b3ec7fe1f91a5e95"

    mockResponse = {
        "timePermits": {
            "aa": timePermit
        },
        "message": "OK"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/timePermit/{2}".format(base_url, baseURL, mpinId),
        "GET",
        None
    )
    mockLog = mocker.Mock()
    httpserver.serve_content(json.dumps(mockResponse), 200)
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", new=appKey), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/timePermit/{1} 127.0.0.1  {2} {3} {4} DTA /timePermit Failed. Date invalid integer unknown".format(baseURL, mpinId, "", "", hashMpinIdHex).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSTimePermitHandlerDTAPermitTimeIsNotToday(http_client, base_url, httpserver, mocker):
    baseURL = "/rps"
    timePermit = "04202140d7034aa274b841decbb0d06e9938c53d278c63f073815df52a28bf2aa91e6755e0cc0e528cc3ccac056f11111f849bf8fa7a2f1b7b5416721eb22a069f"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30372d32392030383a34323a31362e373834383636222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20223235353036643933303334636363626236346437613136623630366435616533227d"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    storageId = "cd4846168f526075b4068da74078c4d8a9e5eeb179148540b3ec7fe1f91a5e95"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinIdHex = "cd4846168f526075b4068da74078c4d8a9e5eeb179148540b3ec7fe1f91a5e95"

    mockResponse = {
        "timePermits": {
            str(int(rps.secrets.today()) + 1): timePermit
        },
        "message": "OK"
    }
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/timePermit/{2}".format(base_url, baseURL, mpinId),
        "GET",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
    )
    mockLog = mocker.Mock()
    httpserver.serve_content(json.dumps(mockResponse), 200)
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", new=appKey), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/timePermit/{1} 127.0.0.1 {2} {3} {4} {5} DTA /timePermit Failed. No time permit for today {6}".format(baseURL, mpinId, xForwardedFor, "", "", hashMpinIdHex, userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSTimePermitHandlerDTAPermitTimeIsNotTodayUserAgentEmpty(http_client, base_url, httpserver, mocker):
    baseURL = "/rps"
    timePermit = "04202140d7034aa274b841decbb0d06e9938c53d278c63f073815df52a28bf2aa91e6755e0cc0e528cc3ccac056f11111f849bf8fa7a2f1b7b5416721eb22a069f"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30372d32392030383a34323a31362e373834383636222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20223235353036643933303334636363626236346437613136623630366435616533227d"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    storageId = "cd4846168f526075b4068da74078c4d8a9e5eeb179148540b3ec7fe1f91a5e95"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinIdHex = "cd4846168f526075b4068da74078c4d8a9e5eeb179148540b3ec7fe1f91a5e95"

    mockResponse = {
        "timePermits": {
            str(int(rps.secrets.today()) + 1): timePermit
        },
        "message": "OK"
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/timePermit/{2}".format(base_url, baseURL, mpinId),
        "GET",
        None
    )
    mockLog = mocker.Mock()
    httpserver.serve_content(json.dumps(mockResponse), 200)
    mockTime = datetime.datetime.strptime("2016-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    with mocker.patch("rps.Time.syncedNow", return_value=mockTime), mock.patch.object(rps.options.mockable(), "DTALocalURL", httpserver.url.decode("utf-8")), mock.patch.object(rps.Keys, "app_key", new=appKey), mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.response.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/timePermit/{1} 127.0.0.1  {2} {3} {4} DTA /timePermit Failed. No time permit for today unknown".format(baseURL, mpinId, "", "", hashMpinIdHex).decode("utf-8"))
