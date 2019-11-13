# Web Service - * / WS-*

Node.JS Module to Generate WS-Federation and WS-Trust tokens.

## Installation
```
npm install ws-star
```

A relying party trust must also be configured in your (ADFS) IDP to support the audience / scope.

# Usage

## WS-Federation
```js
var wsfed = require('ws-star').wsfed;

var SigningCert = fs.readFileSync(path.join(__dirname, config.federation.certs.tokensigningcert));
var SigningKey = fs.readFileSync(path.join(__dirname, config.federation.certs.tokensigningkey));

var idp_WA = 'signin1.0'
var idp_WTRealm = 'urn:sharepoint:f5lab'
var idp_WCTX = ''
var idp_Issuer = 'https://localhost'

var options = {};

var wsfed_options = {
  wsaAddress: idp_WTRealm,
  cert: SigningCert,
  key: SigningKey,
  issuer: idp_Issuer,
  lifetimeInSeconds: 1800,
  audiences: idp_WTRealm,
  attributes: {
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': AttrUserName,
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn': AttrUserPrincipal,
    'http://schemas.microsoft.com/ws/2008/06/identity/claims/role': AttrUserRole,
    'http://schemas.microsoft.com/ws/2008/06/identity/claims/userdata': AttrDisplayname,
    'http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid': AttrUserSID
  }
}

var signedAssertion = wsfed.create(wsfed_options)
```

## WS-Trust

WS-Trust has two functions, CreateRST() and CreateRSTR().  To integrate with another IDP you can use the RST to generate your RST, and to eliminate integration CreatRSTR().


```js
var wsfed = require('ws-star').wstrust;

var options = {};

var wstrust_options = {
  endpoint: 'https://adfs.domain.com/adfs/services/trust/13/usernamemixed',
  username: 'user@foo.bar',
  password: 'pass@word1',
  scope: 'urn:ws-trust:app'
}

var rstr = wstrust.createrstr(wstrust_options)
```

## Testing

```
npm test
```

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section.

## Release History

* 0.1.0 Initial release

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.

