var utils = require('./utils'),
    Parser = require('xmldom').DOMParser,
    SignedXml = require('xml-crypto').SignedXml,
    xmlenc = require('xml-encryption'),
    moment = require('moment'),
    async = require('async'),
    crypto = require('crypto');

var fs = require("fs");
var path = require("path");

var momenttz = require("moment-timezone");

var rst = fs.readFileSync(path.join(__dirname, "wstrust.template")).toString();
var rstr = fs.readFileSync(path.join(__dirname, "wstrustrstr.template")).toString();

var NAMESPACE = "urn:oasis:names:tc:SAML:2.0:assertion";

var algorithms = {
	signature: {
		"rsa-sha256": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
		"rsa-sha1":  "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	},
	digest: {
		"sha256": "http://www.w3.org/2001/04/xmlenc#sha256",
		"sha1": "http://www.w3.org/2000/09/xmldsig#sha1"
	}
};

// Current iteration will only support usernameMixed, can look at adding Certificate and other options later
exports.createrstr = function(options, callback) {
	if (!options.key)
		throw new Error("Expect a private key in pem format");

	if (!options.cert)
		throw new Error("Expect a public key cert in pem format");

	options.signatureAlgorithm = options.signatureAlgorithm || "rsa-sha256";
	options.digestAlgorithm = options.digestAlgorithm || "sha256";

	var cert = utils.pemToCert(options.cert);

	var sig = new SignedXml(null, { signatureAlgorithm: algorithms.signature[options.signatureAlgorithm], idAttribute: "AssertionID" });
	sig.addReference("//*[local-name(.)='Assertion']",
		["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"], algorithms.digest[options.digestAlgorithm]);

	sig.signingKey = options.key;

	sig.keyInfoProvider = {
		getKeyInfo: function () {
			return "<ds:X509Data><ds:X509Certificate>" + cert + "</ds:X509Certificate></ds:X509Data>";
		}
	}

	var doc;
	try {
		doc = new Parser().parseFromString(rstr.toString());
	}
	catch(err){
		return utils.reportError(err, callback);
	}

	var now = moment.utc();
	// there seems to be an issue with windows and order firing and changing timezone for NotBefore...
	var issued = now.format("YYYY-MM-DDTHH:mm:ss.SSS[Z]");

	doc.documentElement.setAttribute("ID", "_" + (options.uid || utils.uid(32)));
	doc.documentElement.setAttribute("IssueInstant", now.format("YYYY-MM-DDTHH:mm:ss.SSS[Z]"));

	var issuerElement = doc.createElement('Issuer');
	if (options.issuer) {
		issuerElement.textContent = options.issuer;
	}
	doc.documentElement.appendChild(issuerElement);

	var confirmationData = doc.documentElement.getElementsByTagName('SubjectConfirmationData')

	var conditions = doc.documentElement.getElementsByTagName("Conditions");
	if (options.lifetimeInSeconds) {
		conditions[0].setAttribute("NotBefore", issued);
		conditions[0].setAttribute("NotOnOrAfter", now.add(options.lifetimeInSeconds, "seconds").format("YYYY-MM-DDTHH:mm:ss.SSS[Z]"));
		confirmationData[0].setAttribute('NotOnOrAfter', now.clone().add(options.lifetimeInSeconds, 'seconds').format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
	}

  if (options.recipient)
    confirmationData[0].setAttribute('Recipient', options.recipient);

  if (options.inResponseTo)
    confirmationData[0].setAttribute('InResponseTo', options.inResponseTo);

	if (options.scope) {
		var audiences = options.scope instanceof Array ? options.scope : [options.scope];
		audiences.forEach(function (audience) {
			var element = doc.createElementNS(NAMESPACE, "Audience");
			element.textContent = audience;
			var audienceCondition = conditions[0].getElementsByTagNameNS(NAMESPACE, "AudienceRestriction")[0];
			audienceCondition.appendChild(element);
		});
	}

	if (options.attributes) {
		var statement = doc.documentElement.getElementsByTagNameNS(NAMESPACE, "AttributeStatement")[0];
		Object.keys(options.attributes).forEach(function(prop) {
			if(typeof options.attributes[prop] === "undefined") return;

			// <saml:Attribute AttributeName="name" AttributeNamespace="http://schemas.xmlsoap.org/claims/identity">
			//    <saml:AttributeValue>Foo Bar</saml:AttributeValue>
			// </saml:Attribute>
			var name = prop.indexOf("/") > -1 ? prop.substring(prop.lastIndexOf("/") + 1) : prop;
			var namespace = prop.indexOf("/") > -1 ? prop.substring(0, prop.lastIndexOf("/")) : "";
			var attributeElement = doc.createElementNS(NAMESPACE, "Attribute");
			attributeElement.setAttribute("AttributeNamespace", namespace);
			attributeElement.setAttribute("AttributeName", name);
			var values = options.attributes[prop] instanceof Array ? options.attributes[prop] : [options.attributes[prop]];
			values.forEach(function (value) {
				var valueElement = doc.createElementNS(NAMESPACE, "AttributeValue");
				valueElement.textContent = value;
				attributeElement.appendChild(valueElement);
			});

			if (values && values.length > 0) {
				// saml:Attribute must have at least one saml:AttributeValue
				statement.appendChild(attributeElement);
			}
		});
	}

	var authnstatement = doc.documentElement.getElementsByTagName("AuthnStatement");
	authnstatement[0].setAttribute("AuthnInstant", now.format("YYYY-MM-DDTHH:mm:ss.SSS[Z]"));

	//if (!options.encryptionCert) return sign(options, sig, doc, callback);
	if (!options.encryptionCert) {
		var signedrstr = sign(options, sig, doc, callback);

		return signedrstr;
	}


};

exports.createrst = function(options, callback) {
	if (!options.endpoint)
		throw new Error("Expect an Endpoint");
	if (!options.username)
		throw new Error("Expect a username");
	if (!options.password)
		throw new Error("Expect a password");
	if (!options.scope)
		throw new Error("Expect an audience");

	options.keytype = options.keytype || 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer';
	options.requesttype = options.requesttype || 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue';
	options.tokentype = options.tokentype || 'urn:oasis:names:tc:SAML:2.0:assertion';

	var message = rst;
	try {
		message = message.replace("[To]", options.endpoint);
		message = message.replace("[Username]", options.username);
		message = message.replace("[Password]", options.password);
		message = message.replace("[ApplyTo]", options.scope);
		message = message.replace("[keytype]", options.keytype);
		message = message.replace("[requesttype]", options.requesttype);
		message = message.replace("[tokentype]", options.tokentype);
	} catch(err){
		return utils.reportError(err, callback);
	}

return message;

};

// Parses the RequestSecurityTokenResponse
function parseRstr(rstr){
	var startOfAssertion = rstr.indexOf('<Assertion ');
	var endOfAssertion = rstr.indexOf('</Assertion>') + '</Assertion>'.length;
	var token = rstr.substring(startOfAssertion, endOfAssertion);
	return token;
}

function sign(options, sig, doc, callback) {
	var token = utils.removeWhitespace(doc.toString());
	var signed;

	try {
		var opts = options.xpathToNodeBeforeSignature ? {
			location: {
				reference: options.xpathToNodeBeforeSignature,
				action: "after"
			}
		} : {};

		sig.computeSignature(token, opts);
		signed = sig.getSignedXml();
	} catch(err){
		return utils.reportError(err, callback);
	}

	if (!callback) return signed;

	return callback(null, signed);
}
