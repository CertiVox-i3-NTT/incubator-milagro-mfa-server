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
def test_clientSettings(http_client, base_url):
    baseURL = "/rps"
    accessNumberUseCheckSum = True
    requestOTP = False
    accessNumberDigits = 7

    with mock.patch.object(rps.options.mockable(), "rpsBaseURL", "".decode("utf-8")):
        response = yield http_client.fetch("{0}{1}/clientSettings".format(base_url, baseURL))

    assert response.code == 200

    assert response.headers.get("Access-Control-Allow-Origin") == None
    assert response.headers.get("Access-Control-Allow-Credentials") == "true"
    assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
    assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
    assert response.headers.get("Cache-Control") == "no-cache, no-store, max-age=0, must-revalidate"
    assert response.headers.get("Pragma") == "no-cache"
    assert response.headers.get("Expires") == "Sat, 26 Jul 1997 05:00:00 GMT"

    print response.body
    responseJson = json.loads(response.body)
    pattern = re.compile("^[0-9a-z]+$", re.IGNORECASE)
    assert responseJson["certivoxURL"] == "https://community-api.certivox.net/v3/"
    assert responseJson["signatureURL"] == "{0}/signature".format(baseURL)
    assert responseJson["registerURL"] == "{0}/user".format(baseURL)
    assert responseJson["timePermitsURL"] == "{0}/timePermit".format(baseURL)
    assert responseJson["timePermitsStorageURL"] == "https://timepermits.certivox.net"
    assert responseJson["setupDoneURL"] == "{0}/setupDone".format(baseURL)
    assert responseJson["mpinAuthServerURL"] == baseURL
    assert responseJson["authenticateURL"] == "/mpinAuthenticate"
    assert responseJson["mobileAuthenticateURL"] == "{0}/authenticate".format(baseURL)
    assert responseJson["setDeviceName"] == False
    assert responseJson["accessNumberUseCheckSum"] == accessNumberUseCheckSum
    assert pattern.match(responseJson["appID"])
    assert responseJson["requestOTP"] == requestOTP
    assert pattern.match(responseJson["seedValue"])
    assert responseJson["useWebSocket"] == False
    assert responseJson["accessNumberDigits"] == accessNumberDigits
    assert responseJson["cSum"] == 1
    assert responseJson["eMpinAuthenticationURL"] == "{0}/eMpinAuthentication".format(baseURL)
    assert responseJson["eMpinActivationURL"] == "{0}/eMpinActivation".format(baseURL)
    assert responseJson["eMpinActivationVerifyURL"] == "{0}/eMpinActivationVerify".format(baseURL)
    assert responseJson["accessNumberURL"] == "{0}/access".format(baseURL)
    assert responseJson["getAccessNumberURL"] == "{0}/getAccessNumber".format(baseURL)

@pytest.mark.gen_test
def test_clientSettingsCheckSumFalse(http_client, base_url):
    baseURL = "/rps"
    accessNumberUseCheckSum = False
    requestOTP = False
    accessNumberDigits = 6

    with mock.patch.object(rps.options.mockable(), "rpsBaseURL", "".decode("utf-8")), mock.patch.object(rps.options.mockable(), "accessNumberUseCheckSum", accessNumberUseCheckSum):
        response = yield http_client.fetch("{0}{1}/clientSettings".format(base_url, baseURL))

    assert response.code == 200

    assert response.headers.get("Access-Control-Allow-Origin") == None
    assert response.headers.get("Access-Control-Allow-Credentials") == "true"
    assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
    assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
    assert response.headers.get("Cache-Control") == "no-cache, no-store, max-age=0, must-revalidate"
    assert response.headers.get("Pragma") == "no-cache"
    assert response.headers.get("Expires") == "Sat, 26 Jul 1997 05:00:00 GMT"

    responseJson = json.loads(response.body)
    pattern = re.compile("^[0-9a-z]+$", re.IGNORECASE)
    assert responseJson["certivoxURL"] == "https://community-api.certivox.net/v3/"
    assert responseJson["signatureURL"] == "{0}/signature".format(baseURL)
    assert responseJson["registerURL"] == "{0}/user".format(baseURL)
    assert responseJson["timePermitsURL"] == "{0}/timePermit".format(baseURL)
    assert responseJson["timePermitsStorageURL"] == "https://timepermits.certivox.net"
    assert responseJson["setupDoneURL"] == "{0}/setupDone".format(baseURL)
    assert responseJson["mpinAuthServerURL"] == baseURL
    assert responseJson["authenticateURL"] == "/mpinAuthenticate"
    assert responseJson["mobileAuthenticateURL"] == "{0}/authenticate".format(baseURL)
    assert responseJson["setDeviceName"] == False
    assert responseJson["accessNumberUseCheckSum"] == accessNumberUseCheckSum
    assert pattern.match(responseJson["appID"])
    assert responseJson["requestOTP"] == requestOTP
    assert pattern.match(responseJson["seedValue"])
    assert responseJson["useWebSocket"] == False
    assert responseJson["accessNumberDigits"] == accessNumberDigits
    assert responseJson["cSum"] == 1
    assert responseJson["eMpinAuthenticationURL"] == "{0}/eMpinAuthentication".format(baseURL)
    assert responseJson["eMpinActivationURL"] == "{0}/eMpinActivation".format(baseURL)
    assert responseJson["eMpinActivationVerifyURL"] == "{0}/eMpinActivationVerify".format(baseURL)
    assert responseJson["accessNumberURL"] == "{0}/access".format(baseURL)
    assert responseJson["getAccessNumberURL"] == "{0}/getAccessNumber".format(baseURL)

@pytest.mark.gen_test
def test_clientSettingsRequestOTPTrue(http_client, base_url):
    baseURL = "/rps"
    accessNumberUseCheckSum = True
    requestOTP = True
    accessNumberDigits = 7

    with mock.patch.object(rps.options.mockable(), "rpsBaseURL", "".decode("utf-8")), mock.patch.object(rps.options.mockable(), "requestOTP", requestOTP):
        response = yield http_client.fetch("{0}{1}/clientSettings".format(base_url, baseURL))

    assert response.code == 200

    assert response.headers.get("Access-Control-Allow-Origin") == None
    assert response.headers.get("Access-Control-Allow-Credentials") == "true"
    assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
    assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"
    assert response.headers.get("Cache-Control") == "no-cache, no-store, max-age=0, must-revalidate"
    assert response.headers.get("Pragma") == "no-cache"
    assert response.headers.get("Expires") == "Sat, 26 Jul 1997 05:00:00 GMT"

    responseJson = json.loads(response.body)
    pattern = re.compile("^[0-9a-z]+$", re.IGNORECASE)
    assert responseJson["certivoxURL"] == "https://community-api.certivox.net/v3/"
    assert responseJson["signatureURL"] == "{0}/signature".format(baseURL)
    assert responseJson["registerURL"] == "{0}/user".format(baseURL)
    assert responseJson["timePermitsURL"] == "{0}/timePermit".format(baseURL)
    assert responseJson["timePermitsStorageURL"] == "https://timepermits.certivox.net"
    assert responseJson["setupDoneURL"] == "{0}/setupDone".format(baseURL)
    assert responseJson["mpinAuthServerURL"] == baseURL
    assert responseJson["authenticateURL"] == "/mpinAuthenticate"
    assert responseJson["mobileAuthenticateURL"] == "{0}/authenticate".format(baseURL)
    assert responseJson["setDeviceName"] == False
    assert responseJson["accessNumberUseCheckSum"] == accessNumberUseCheckSum
    assert pattern.match(responseJson["appID"])
    assert responseJson["requestOTP"] == requestOTP
    assert pattern.match(responseJson["seedValue"])
    assert responseJson["useWebSocket"] == False
    assert responseJson["accessNumberDigits"] == accessNumberDigits
    assert responseJson["cSum"] == 1
    assert responseJson["eMpinAuthenticationURL"] == "{0}/eMpinAuthentication".format(baseURL)
    assert responseJson["eMpinActivationURL"] == "{0}/eMpinActivation".format(baseURL)
    assert responseJson["eMpinActivationVerifyURL"] == "{0}/eMpinActivationVerify".format(baseURL)
    assert "accessNumberURL" not in responseJson
    assert "getAccessNumberURL" not in responseJson
