var wstrust = require('../lib/index.js').WSTrust;

var fs = require('fs');
var path = require("path");

var rst_options = {
  endpoint: 'https://adfs.domain.com/adfs/services/trust/13/usernamemixed',
  username: 'user@foo.bar',
  password: 'pass@word1',
  scope: 'urn:ws-trust:app'
}

var rst = wstrust.createrst(rst_options)

console.log(rst);
console.log('-------------------------------------------------------------------');

var SigningCert = fs.readFileSync(path.join(__dirname, 'fakeadfs.crt'));
var SigningKey = fs.readFileSync(path.join(__dirname, 'fakeadfs.key'));

var rstr_options = {
  cert: SigningCert,
  key: SigningKey,
  issuer: 'https://fakeadfs.domain.com',
  lifetimeInSeconds: 1800,
  scope: 'urn:wt-trust:client',
  attributes: {
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'Michael',
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn': '8675309@DOMAIN'
  }
}

var rstr = wstrust.createrstr(rstr_options);

console.log(rstr);
