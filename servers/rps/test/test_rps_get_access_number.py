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
def test_RPSGetAccessNumberHandler(http_client, base_url):
    baseURL = "/rps"

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/getAccessNumber".format(base_url, baseURL),
        "POST",
        None,
        ""
    )
    response = yield http_client.fetch(request)

    assert response.code == 200

    assert response.headers.get("Access-Control-Allow-Origin") == None
    assert response.headers.get("Access-Control-Allow-Credentials") == "true"
    assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
    assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

    responseJson = json.loads(response.body)
    assert responseJson["ttlSeconds"] == 300
    assert responseJson["localTimeEnd"] - responseJson["localTimeStart"] == 300000

    auth = http_server.storage.find(stage="auth", webOTT=responseJson["webOTT"])
    isoFormat = re.compile("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}$")
    assert auth.wid == responseJson["accessNumber"]
    expires = datetime.datetime.strptime(auth._expires, "%Y-%m-%dT%H:%M:%S.%f")
    assert rps.Time.DateTimetoEpoch(expires) - responseJson["localTimeEnd"] == 5000

@pytest.mark.gen_test
def test_RPSGetAccessNumberHandlerWIdNone(http_client, base_url, mocker):
    baseURL = "/rps"
    wId = "5319366"

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/getAccessNumber".format(base_url, baseURL),
        "POST",
        None,
        ""
    )

    mockFunc = mocker.MagicMock(side_effect=[None, wId])
    with mocker.patch("rps.secrets.generate_random_webid", mockFunc):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

        responseJson = json.loads(response.body)
        assert responseJson["ttlSeconds"] == 300
        assert responseJson["accessNumber"] == wId
        assert responseJson["localTimeEnd"] - responseJson["localTimeStart"] == 300000

        auth = http_server.storage.find(stage="auth", webOTT=responseJson["webOTT"])
        assert auth.wid == responseJson["accessNumber"]
        expires = datetime.datetime.strptime(auth._expires, "%Y-%m-%dT%H:%M:%S.%f")
        assert rps.Time.DateTimetoEpoch(expires) - responseJson["localTimeEnd"] == 5000

        assert mockFunc.mock_calls == [mocker.call.__enter__(), mocker.call(mocker.ANY, True), mocker.call(mocker.ANY, True)]

@pytest.mark.gen_test
def test_RPSGetAccessNumberHandlerWIdExist(http_client, base_url, mocker):
    baseURL = "/rps"
    webOTT = "26fc14be05fa66ad440a4ca627075540"
    wId = "5319366"
    wId2 = "0622575"

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/getAccessNumber".format(base_url, baseURL),
        "POST",
        None,
        ""
    )

    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", webOTT=webOTT, wid=wId)
    mockFunc = mocker.MagicMock(side_effect=[wId, wId2])
    with mocker.patch("rps.secrets.generate_random_webid", mockFunc):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

        responseJson = json.loads(response.body)
        assert responseJson["ttlSeconds"] == 300
        assert responseJson["accessNumber"] == wId2
        assert responseJson["localTimeEnd"] - responseJson["localTimeStart"] == 300000

        auth = http_server.storage.find(stage="auth", webOTT=responseJson["webOTT"])
        assert auth.wid == responseJson["accessNumber"]
        expires = datetime.datetime.strptime(auth._expires, "%Y-%m-%dT%H:%M:%S.%f")
        assert rps.Time.DateTimetoEpoch(expires) - responseJson["localTimeEnd"] == 5000

        assert mockFunc.mock_calls == [mocker.call.__enter__(), mocker.call(mocker.ANY, True), mocker.call(mocker.ANY, True)]