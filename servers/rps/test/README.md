# RPS Test

## Server Setting

Install the RPS and configuration

## Install the following packages

```bash
$ cd <milagro-mfa-services>/servers/rps
$ sudo pip install -r test/requirement.txt
```

Place the server certificate `/usr/lib/python2.7/site-packages/pytest_localserver/server.pem`</br>
Add the ca certificate `/usr/lib/python2.7/site-packages/certifi/cacert.pem`

## Running Tests

```bash
$ export PYTHONPATH=<milagro-mfa-services>/lib:/usr/lib/python2.7/site-packages
$ export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
$ cd <milagro-mfa-services>/servers/rps
$ py.test test
```

