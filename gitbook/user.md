# User Guide
Using wattson is made as easy as possible. In case you are lost orchent provides a lot of
information with its 'help' command, just call `wattson --help`.

```
$ wattson --help
usage: wattson [<flags>] <command> [<args> ...]

The WaTTS client. Please store your access token in the 'WATTSON_TOKEN' and the issuer id (up to version 1 the issuer url) in the 'WATTSON_ISSUER' environment
variable: 'export WATTSON_TOKEN=<your access token>', 'export WATTSON_ISSUER=<the issuer id>'. The url of watts can be stored in the environment variable
'WATTSON_URL': export WATTSON_URL=<url of watts>

Flags:
      --help       Show context-sensitive help (also try --help-long and --help-man).
      --version    Show application version.
  -u, --url=URL    the base url of watts' rest interface
  -p, --protver=2  protocol version to use (can be 0, 1 or 2)
  -j, --json       enable json output
      --debug      enable debug output

Commands:
  help [<command>...]
    Show help.

  info
    get the information about watts, e.g. its version

  lsprov
    list all OpenID Connect provider

  lsserv
    list all service

  lscred
    list all credentials

  request <serviceId> [<parameter>]
    request a credential for a service

  revoke <credId>
    revoke a credential

```

If you have questions or found a bug please always include the version on your description:
```
wattson --version
```


## Client setup
The client is configured by environment variables:
 - WATTSON_URL: the base url of the Token Translation service, e.g. `https://tts-dev.data.kit.edu`
 - WATTSON_ISSUER: the issuer id of the OpenId Connect provider in use (see `lsprov`). For protocol version 1 this is the issuer url.
 - WATTSON_TOKEN: the access token received from the OpenId Connect provider, e.g. using the web interface of the Token Translation Service

All commands need at least the `WATTSON_URL` to be set:
```
export WATTSON_URL=https://tts-dev.data.kit.edu
```
change the url to fit your needs, alternativly the `--url` flag can be used.

Issuer and Token are set the same way, commands that need those to be set are marked with *AUTH*:
```
export WATTSON_ISSUER=<the issuer id>
export WATTSON_TOKEN=<the access token>
```

## Flags
Flags can be used with any command and change the behaviour of the client:
- `--json` encode the received information using json
- `--protver=X` set the protocol version to X, supported are 0, 1 and 2 (default: 2)
  - 0 is used for WATTS up to version 0.4.x
  - 1 is used for WATTS 1.0.x to get the same results as with 0.4.x
  - 2 is the newest api version for WATTS 1.0.x
- `--debug` enabled debug output
- `--url` set the base url of the TTS, usually done by setting the environment variable `WATTSON_URL`

## Commands
Each Description will include a sample call and its output.

### Get Information about the Token Translation Service (info)
```
$ wattson info
connecting to https://tts-dev.data.kit.edu/api/v2/ using protocol version 2
retrieving information:
WATTS version: 1.0.0
  the redirect path is: /oidc
this connection is *NOT* logged in
```
The WATTS is running version 1.0.0 and we are not in an active session,
this is always the case when using the REST interface.


### List all OpenId Provider (lsprov)
The `lsprov` command lists all the OpenId Providers a WATTS instance supports. The call
needs no additional parameter:
```
$ wattson lsprov
connecting to https://tts-dev.data.kit.edu/api/v2/ using protocol version 2
retrieving provider list:
Provider [iam][ready] INDIGO Datacloud Identity and Access Management (IAM) (https://iam-test.indigo-datacloud.eu/)
Provider [hbp][ready] Human Brain Project (HBP) (https://services.humanbrainproject.eu/oidc/)
Provider [eudat][ready] EUDAT (b2access) (https://b2access.eudat.eu:8443/oauth2)
Provider [egi][ready] European Grid Infrastracture (Development) (https://aai-dev.egi.eu/oidc/)
Provider [google][ready] Google, the well known search giant (https://accounts.google.com)
```
In the example above, the WATTS will be asked to list all the OpenId Connect Providers it supports.
For this example, the WATTS supports four OpenId Connect providers.
Each line contains multiple information:
 - the id of the provider e.g. 'iam'
 - the status, in this example 'ready'
 - a descriptive name, e.g. 'INDIGO Datacloud Identity and Access Management (IAM)'
 - the issuer url of the provider, here 'https://iam-test.indigo-datacloud.eu/'


### List all service for a user (lsserv) *AUTH*
The `lsserv` command lists all the services the WATTS supports for the authorized
user.
```
$ wattson lsserv
connecting to https://tts-dev.data.kit.edu/api/v2/ using protocol version 2
retrieving service list:

Service [x509][enabled/authorized] [ ] A simple, non trusted demo CA
 - credenitals: 0/3
 - parameter sets:
    Empty Parameter Set (allows basic request)


Service [aarc_ssh][enabled/NOT AUTHORIZED] [ ] Ssh Key Deployment on multiple VMs
   Your authorisation is insufficient for this service. This may be due to missing group membership or due to a too low Level of Assurance (LoA) (Yes, we already support that kind of stuff ;D)
 - credenitals: 0/1
 - parameter sets:
    Parameter Set:
      MANDATORY Parameter 'public key' [pub_key]: the public key to upload to the service (textarea)

    Empty Parameter Set (allows basic request)


Service [indigo_ssh][enabled/authorized] [ ] Example Ssh Key Deployment
 - credenitals: 0/1
 - parameter sets:
    Parameter Set:
      MANDATORY Parameter 'public key' [pub_key]: the public key to upload to the service (textarea)

    Empty Parameter Set (allows basic request)


Service [HBP_S3][enabled/NOT AUTHORIZED] [ AT! ] Self Service for your HBP-S3 storage keys
   The S3 key creation is only active when you are a member of the HBP group 'hbp-kit-cloud'
 - credenitals: 0/1
 - parameter sets:
    Empty Parameter Set (allows basic request)


Service [info][enabled/authorized] [ ] Simple Info Service
 - credenitals: 0/1
 - parameter sets:
    Empty Parameter Set (allows basic request)
```
The result is a list of the services for which the user might be allowed to request credentials.
Each block represents one service.
Listing:
 - The Id, e.g. x509
 - The status and authorization status, e.g. enabled/authorized
 - Flags/Icons
   - AT!: this service receives your access-token, only use it if you really trust/need it
 - A description of the service
 - The number of credentials requested and the max. allowed, e.g. 0/3
 - The parameter sets, these are used for advanced requests, desribed later
   - Only if the "Empty Parameter Set (allows basic request)" is present a basic request is possible

To request a credential, one needs the id, in the first square brackets and one parameter set,
which can be empty.

### Listing all credentials (lscred) *AUTH*
The `lscred` command lists all currently requested credentials.
```
$ wattson lscred
connecting to https://tts-dev.data.kit.edu/api/v2/ using protocol version 2
retrieving credential list:

Credential [9dfa0900-930b-462c-8144-da9dd1aa37d2]: for service with id [info] created Wed, 21 Dec 2016 10:48:51 GMT at 'Web App'

```
The output is one line per credential.
- the id is the internal identifier of the credential within TTS.
- the id of the service it has been requested for.
- the creation time
- at which interface the credential was created, it is either the Web App or the REST interface

### Requesting a credential (request) *AUTH*
#### Basic Request (without parameter sets)
A basic request is possible if the service has the 'Empty Parameter Set (allows basic request)' in
the listing (see `lsserv`).
The only parameter a basic request needs is the id of the service to request the credential for:
```
$ wattson request x509
connecting to https://tts-dev.data.kit.edu/api/v2/ using protocol version 2
requesting credential for service [x509]:
Credential [29e28d92-a13f-4f3a-b23b-54c921a4cd82]:
[ Certificate (textfile)] => Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 11 (0xb)
    Signature Algorithm: sha1WithRSAEncryption
        Issuer: C=EU, O=INDIGO, OU=TTS, CN=TTS-CA
        Validity
            Not Before: Dec 21 10:54:18 2016 GMT
            Not After : Jan  1 10:54:18 2017 GMT
        Subject: C=EU, O=INDIGO, OU=TTS, CN=1@google
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (1024 bit)
                Modulus:
                    c8:96:6d:23:2a:10:bd:de:25
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                C2:DD:2F:99:80:7A:6C:54:66:EF:89:DE:02:0A:3A:14:AB:81:66:7B
            X509v3 Authority Key Identifier:
                keyid:E3:64:2D:4D:2B:8A:81:4E:58:0A:71:FE:D7:62:9D:A7:3F:69:C5:5E

            X509v3 Basic Constraints:
                CA:FALSE
            X509v3 Key Usage:
                Digital Signature, Key Encipherment
            X509v3 Subject Alternative Name:
                URI:https://accounts.google.com/109538112780676045413
    Signature Algorithm: sha1WithRSAEncryption
         ac:fd:04:36:81:4f:d8:99:8c:42:ee:92:23:0c:a5:1b:a0:6b:
         aa:48:00:a8
-----BEGIN CERTIFICATE-----
MIIDITCCAgmgAwIBAgIBCzANBgkqhkiG9w0BAQUFADA9MQswCQYDVQQGEwJFVTEP
KROGLtV7daqUGLf8p+BPmnipmUPiuzszzNhIcBfTsN24qkgAqA==
-----END CERTIFICATE-----

[ Private Key (textfile)] => -----BEGIN ENCRYPTED PRIVATE KEY-----
MIICxjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIxFS4nQh/WxQCAggA
sRc6PzBg3g1S0yNedNEQsOUU3krgJchRKmhSvLMeVRlTZSk/xuvb+mTr
-----END ENCRYPTED PRIVATE KEY-----

[ Passphrase (for Private Key) (text)] => 1234
[ CA Certificate (textfile)] => -----BEGIN CERTIFICATE-----
MIIDRTCCAi2gAwIBAgIBADANBgkqhkiG9w0BAQsFADA9MQswCQYDVQQGEwJFVTEP
9D9hyq7aDBPvLiVQ/DcgQ1c+Nf1G12HZpg==
-----END CERTIFICATE-----
```
The output (shortened) contains the credential Id and a list of credential entries,
each representing a part of the credential.
An entry consists of:
 - a name
 - its type
 - and the value

So each entry is of the following format: ` [ <name> (<type>) ] => <value> `

#### Advanced requests
Advanced request only have one additional parameter, the parameter object. The parameter object
is a string containing a json encoded object.

The parameter object MUST contain all mandatory fields of one parameter set.
As an example take thes parameter sets from this service:
```
Service [indigo_ssh][enabled/authorized] Example Ssh Key Deployment
 - credenitals: 0/1
 - parameter sets:
    Parameter Set:
      MANDATORY Parameter 'public key' [pub_key]: the public key to upload to the service (textarea)

    Empty Parameter Set (allows basic request)`
```
It contains two sets, one empty set and one non empty set. The advanced request is only needed for
non empty sets.
Each non-emtpy set contains of a list of parameter with the following information:
 - Mandatory or not
 - Parameter name
 - Parameter key
 - Parameter description

 The parameter object *MUST* contain at least every mandatory parameter of a chosen set.
 The parameter object is then created using the 'parameter key' as key and the wanted
 value as value.

 For example:
 ```
 { "pub_key":"ssh-rsa AAAAAAAAAABBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCCCC me@computer"}
 ```

 the request in total would be:
 ```
 wattson request indigo_ssh '{ "pub_key":"ssh-rsa AAAAAAAAAABBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCCCC me@computer"}'
 ```
 (note the single quotes and double quotes, using them as above makes your life easier)


### Revoking a credential (revoke) *AUTH*
Revoking is very similar to requesting, yet instead of providing the service for
which to request a credential, the credential id is provided.
```
$ wattson revoke 29e28d92-a13f-4f3a-b23b-54c921a4cd82
revoking credential [29e28d92-a13f-4f3a-b23b-54c921a4cd82]:
credential sucessfully revoked
```
Checking the list of credentials using the `lscred` command shows that only one
credential is left, yet not the one just requested:
```
$ wattson lscred
connecting to https://tts-dev.data.kit.edu/api/v2/ using protocol version 2
retrieving credential list:

Credential [9dfa0900-930b-462c-8144-da9dd1aa37d2]: for service with id [info] created Wed, 21 Dec 2016 10:48:51 GMT at 'Web App'

```

### Plugin Developer self signed certificate support
*WARNING* Never do this with operational systems!
If wattson does complain that the certificate of the server can not be verified this has two possible reasons:
 - The server is misconfigured: contact the administrator
 - There is a man in the middle attack


The verification of certificates can be disabled with the following line:
```
export WATTSON_INSECURE=true
```
