# Wattson
The WaTTS (INDIGO Token Translation Service) command line client

## Installing
Please install the [latest realease](https://github.com/indigo-dc/wattson/releases/latest) of
wattson at your system or import the Docker container (see below).

## Quickstart
Once installed using wattson is straight forward:

The next lines will set up the connection and check the supported issuer:
```
export WATTSON_URL=https://tts-dev.data.kit.edu
wattson lsprov
```
The output will be similar to:
```
connecting to https://tts-dev.data.kit.edu/api/v2/ using protocol version 2

*** WARNING: either access token or issuer has not been specified ***

retrieving provider list:
Provider [iam][ready] INDIGO Datacloud Identity and Access Management (IAM) (https://iam-test.indigo-datacloud.eu/)
Provider [hbp][ready] Human Brain Project (HBP) (https://services.humanbrainproject.eu/oidc/)
Provider [eudat][ready] EUDAT (b2access) (https://b2access.eudat.eu:8443/oauth2)
Provider [egi][ready] European Grid Infrastracture (Development) (https://aai-dev.egi.eu/oidc/)
Provider [google][ready] Google, the well known search giant (https://accounts.google.com)
```
The output shows the list of supported provider:
 - their id
 - wether they are ready or not
 - a descriptive name
 - the issuer url

Also a warning is shown that the access token and isuer need to be set.
In this example we will use 'iam'. Log in at the web interface of TTS using IAM. Then select 'show access token' and copy the content of the dialog.
The following line will set up the authorization for the command line client and request the list of
services:
```
export WATTSON_TOKEN=<paste the copied text from the dialog here>
export WATTSON_ISSUER=iam
wattson lsserv
```
The output should be similar to:
```
connecting to https://tts-dev.data.kit.edu/api/v2/ using protocol version 2
retrieving service list:

Service [x509][enabled/authorized] A simple, non trusted demo CA
 - credenitals: 0/3
 - parameter sets:
    Empty Parameter Set (allows basic request)


Service [aarc_ssh][enabled/NOT AUTHORIZED] Ssh Key Deployment on multiple VMs
   Your authorisation is insufficient for this service. This may be due to missing group membership or due to a too low Level of Assurance (LoA) (Yes, we already support that kind of stuff ;D)
 - credenitals: 0/1
 - parameter sets:
    Parameter Set:
      MANDATORY Parameter 'public key' [pub_key]: the public key to upload to the service (textarea)

    Empty Parameter Set (allows basic request)


Service [indigo_ssh][enabled/authorized] Example Ssh Key Deployment
 - credenitals: 0/1
 - parameter sets:
    Parameter Set:
      MANDATORY Parameter 'public key' [pub_key]: the public key to upload to the service (textarea)

    Empty Parameter Set (allows basic request)


Service [HBP_S3][enabled/NOT AUTHORIZED] Self Service for your HBP-S3 storage keys
   The S3 key creation is only active when you are a member of the HBP group 'hbp-kit-cloud'
 - credenitals: 0/1
 - parameter sets:
    Empty Parameter Set (allows basic request)


Service [info][enabled/authorized] Simple Info Service
 - credenitals: 0/1
 - parameter sets:
    Empty Parameter Set (allows basic request)
```
The warning of the missing token/issuer is gone.
The output shows the list of all services:
 - the id
 - wether the service is enabled
 - wether one is authorized to use that service
 - a description of the service
 - the number of credentials one has and max. allowed
 - the parameter sets (mainly used for development)



Requesting a credential simply works with the command 'request' and the service id:
```
wattson request info
```
the output should be similar to:
```
requesting credential for service [info]:
Credential [f9dbb0e0-9e3e-4065-9fee-8ac30387d2b4]:
[ TTS version (text)] => 1.0.0-rc4
[ TTS userid (text)] => eyJpc3N1ZXIiOiJpc3MiLCJzdWJqZWN0Ijoic3ViIn0
[ TTS userid (decoded) (text)] => {"issuer":"iss","subject":"sub"}
[ family_name (text)] => Wegh
[ Name (text)] => Bas Wegh
[ Issuer (text)] => iss
[ Gender (text)] => M
[ preferred_username (text)] => bwegh
[ updated_at (text)] => Wed Aug 31 09:06:43 UTC 2016
[ given_name (text)] => Bas
[ Groups (textarea)] => [<<"Users">>]
[ organisation_name (text)] => indigo-dc
[ Subject (text)] => sub
[ json object (textarea)] => {
    "action": "request",
    "conf_params": {},
    "cred_state": "undefined",
    "params": {},
    "tts_userid": "eyJpc3N1ZXIiOiJpc3MiLCJzdWJqZWN0Ijoic3ViIn0",
    "tts_version": "1.0.0-rc4",
    "user_info": {
        "family_name": "Wegh",
        "gender": "M",
        "given_name": "Bas",
        "groups": [
            "Users"
        ],
        "iss": "iss",
        "name": "Bas Wegh",
        "organisation_name": "indigo-dc",
        "preferred_username": "baswegh",
        "sub": "sub",
        "updated_at": "Wed Aug 31 09:06:43 UTC 2016"
    }
}

```
Now you can use that information/credential, once you do not need it anymore you need to revoke it
using the credential id, shown in the first line:
```
wattson revoke f9dbb0e0-9e3e-4065-9fee-8ac30387d2b4
```
the output should look like:
```
revoking credential [f9dbb0e0-9e3e-4065-9fee-8ac30387d2b4]:
credential sucessfully revoked
```

For more information and more examples please see [the documentation](https://indigo-dc.gitbooks.io/wattson/content/)

## Using Docker
If your system is not supported with packages you can still use wattson through a lightweight
Docker container.
Download the container in the release section and import it using the `docker load` command:
```
docker load --input wattson_container_1.0.1.tar
```

After loading the container you can use it to run orchent:
```
docker run wattson:1.0.1 --version
docker run orchent:1.0.1 --help
```

For information on how to pass environment settings to the docker see
```
docker run --help
```

## Building wattson
wattson can be build from source by running
```
./utils/compile.sh
```
After generating the binary you can eithe use it locally or install it in e.g. /usr/local/bin
