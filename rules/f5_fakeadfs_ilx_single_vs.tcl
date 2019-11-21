when RULE_INIT {
    set static::adfsdebug 1
}
    
when HTTP_REQUEST {

    switch -glob [string tolower [HTTP::path]] {
        "*/federationmetadata/2007-06/federationmetadata.xml" {
            #Act as the STS Metadataprovider
            set fakeadfs_preapm [ILX::init f5_fakeadfs_ilx_extension]
            set issuer "https://[HTTP::host]"
            set endpoint "[HTTP::uri]"
            set metadata_response [ILX::call $fakeadfs_preapm Generate-FederationMetadata $issuer $endpoint]
            if { $static::adfsdebug } { log local0. "ADFS DEBUG: response sent: $metadata_response Content-Type 'application/xml'" }
            HTTP::respond 200 content $metadata_response Content-Type "application/xml"
        }
        "*/STS/Login.aspx*" {
            #Act as STS Login Provider
            #  WIF applications will do a passive redirect to STS to auth.
            #  Maybe let APM handle this landinguri.

        }
        "*adfs/services/trust/*" {
            #Act as WS-Trust Provider
            #Path can determine Auth Type, I dont want to code all of these so will have to pick a few important ones.
            #  *adfs/services/trust/*/certificate
            #  *adfs/services/trust/*/username
            #  *adfs/services/trust/*/issuedtoken*
        }
        "*/adfs/ls*" {
            log local0. ".../adfs/ls path..."
            #  Act as WS-Federation Provider
            #  Wctx: This is some session data that the application wants sent back to
            #  it after the user authenticates.
            set wctx [URI::decode [URI::query [HTTP::uri] wctx]]
            #  Wa=signin1.0: This tells the ADFS server to invoke a login for the user.
            set wa [URI::decode [URI::query [HTTP::uri] wa]]
            #  Wtrealm: This tells ADFS what application I was trying to get to.
            #  This has to match the identifier of one of the relying party trusts
            #  listed in ADFS.  wtrealm is used in the Node.JS side, but we dont need it
            #  here.

            #  Kept getting errors from APM, this fixed it.
            node 127.0.0.1

            #  Make sure that the user has authenticated and APM has created a session.
            if {[HTTP::cookie exists MRHSession] } {

                #log local0. "Generate POST form and Autopost "

                #  tmpresponse is the WS-Fed Assertion data, unencoded, so straight XML
                set tmpresponse [ACCESS::session data get session.custom.idam.wsfedtoken]

                #  This was the pain to figure out.  The assertion has to be POSTed to
                #  SharePoint, this was the easiest way to solve that issue.  Set timeout
                #  to half a second, but can be adjusted as needed.
                set htmltop "<html><script type='text/javascript'>window.onload=function(){ window.setTimeout(document.wsFedAuth.submit.bind(document.wsFedAuth), 500);};</script><body>"
                set htmlform "<form name='wsFedAuth' method=POST action='https://sharepoint.f5lab.com/_trust/default.aspx?trust=FakeADFS'><input type=hidden name=wa value=$wa><input type=hidden name=wresult value='$tmpresponse'><input type=hidden name=wctx value=$wctx><input type='submit' value='Continue'></form/>"
                set htmlbottom "</body></html>"
                set page "$htmltop $htmlform $htmlbottom"
                if { $static::adfsdebug } { log local0. "ADFS DEBUG: response sent: $page" }
                HTTP::respond 200 content $page
            }
        }
        default {
            #  Wctx: This is some session data that the application wants sent back to
            #  it after the user authenticates.
            set wctx [URI::decode [URI::query [HTTP::uri] wctx]]
            #  Wa=signin1.0: This tells the ADFS server to invoke a login for the user.
            set wa [URI::decode [URI::query [HTTP::uri] wa]]
            #  Wtrealm: This tells ADFS what application I was trying to get to.
            #  This has to match the identifier of one of the relying party trusts
            #  listed in ADFS.  wtrealm is used in the Node.JS side, but we dont need it
            #  here.
            set wtrealm [URI::decode [URI::query [HTTP::uri] wtrealm]]
            #  Pull the FQDN out of the wctx field to use for the redirect and post later
            #  Since wctx is in the pattern https://fqdn/uri split on the / and grab the third field.
            set referfqdn [getfield $wctx "/" 3]

            if {[HTTP::cookie exists MRHSession] &&
                ([HTTP::method] ne "POST") &&
                not ( [HTTP::cookie exists FedAuth] ) &&
                [ACCESS::session data get session.custom.idam.wsfedtoken] ne ""} {
                node 127.0.0.1
                log local0. "...MRHSession && WSFedToken Exist, FedAuth Cookie Does Not... "

                #  tmpresponse is the WS-Fed Assertion data, unencoded, so straight XML
                set tmpresponse [ACCESS::session data get session.custom.idam.wsfedtoken]

                #  This was the pain to figure out.  The assertion has to be POSTed to
                #  SharePoint, this was the easiest way to solve that issue.  Set timeout
                #  to half a second, but can be adjusted as needed.
                set currentHost [HTTP::host]
                set htmltop "<html><script type='text/javascript'>window.onload=function(){ window.setTimeout(document.wsFedAuth.submit.bind(document.wsFedAuth), 500);};</script><body>"
                set htmlform "<form name='wsFedAuth' method=POST action='https://$currentHost/_trust/default.aspx?trust=FakeADFS'><input type=hidden name=wa value=$wa><input type=hidden name=wresult value='$tmpresponse'><input type=hidden name=wctx value=$wctx><input type='submit' value='Continue'></form/>"
                set htmlbottom "</body></html>"
                set page "$htmltop $htmlform $htmlbottom"
                if { $static::adfsdebug } { log local0. "ADFS DEBUG: response sent: $page" }
                HTTP::respond 200 content $page
                }
            }
    }
}

when ACCESS_POLICY_AGENT_EVENT {
    #  Create the ILX RPC Handler
    set fakeadfs_handle [ILX::init f5_fakeadfs_plugin f5_fakeadfs_ilx_extension]
    #  Payload is just the incoming Querystring
    set payload [ACCESS::session data get session.server.landinguri]

    #  Wctx: This is some session data that the application wants sent back to
    #  it after the user authenticates.
    set wctx [URI::decode [URI::query $payload wctx]]
    ACCESS::session data set session.custom.fakeadfs.wctx $wctx
    #  Wa=signin1.0: This tells the ADFS server to invoke a login for the user.
    set wa [URI::decode [URI::query $payload wa]]
    ACCESS::session data set session.custom.fakeadfs.wa $wa 
    #  Wtrealm: This tells ADFS what application I was trying to get to.
    #  This has to match the identifier of one of the relying party trusts
    #  listed in ADFS.  wtrealm is used in the Node.JS side, but we dont need it
    #  here.
    set wtrealm [URI::decode [URI::query $payload wtrealm]]
    ACCESS::session data set session.custom.fakeadfs.wtrealm $wtrealm
    #  Pull the FQDN out of the wctx field to use for the redirect and post later
    #  Since wctx is in the pattern https://fqdn/uri split on the / and grab the third field.
    set referfqdn [getfield $wctx "/" 3]
    ACCESS::session data set session.custom.fakeadfs.referfqdn $referfqdn 

    #  Currently, the mapped attributes are Email & UPN.  In some environments,
    #  this may match, for my use case, they will not, so there is an LDAP AAA
    #  which is queried based on the logon name (email), and the UPN is retrieved
    #  from LDAP.
    set AttrUserName [ACCESS::session data get session.logon.last.username]
    set AttrUserPrin [ACCESS::session data get session.ldap.last.attr.userPrincipalName ]
    set AttrSurName [ACCESS::session data get session.ldap.last.attr.sn]
    set AttrGivenName [ACCESS::session data get session.ldap.last.attr.givenName]
    set AttrEmailAddress [ACCESS::session data get session.ldap.last.attr.mail]
    set AttrDisplayName [ACCESS::session data get session.ldap.last.attr.displayName]

    if { $static::adfsdebug } {
        log local0. "ADFS DEBUG: ____________________________"
        log local0. "ADFS DEBUG: Received Process request for FakeADFS, $payload"
        log local0. "ADFS DEBUG: wCtx: $wctx"
        log local0. "ADFS DEBUG: wtRealm: $wtrealm"
        log local0. "ADFS DEBUG: wa: $wa"
        log local0. "ADFS DEBUG: ReferFQDN: $referfqdn"
        log local0. "ADFS DEBUG: AttrSurName= $AttrUserName"
        log local0. "ADFS DEBUG: AttrSurName= $AttrSurName"
        log local0. "ADFS DEBUG: AttrGivenName= $AttrGivenName"
        log local0. "ADFS DEBUG: AttrEmailAddress= $AttrEmailAddress"
        log local0. "ADFS DEBUG: AttrDisplayName= $AttrDisplayName"
        log local0. "ADFS DEBUG: AttrUserPrin= $AttrUserPrin"
        log local0. "ADFS DEBUG: ____________________________"
    }

    #  Current solution uses Node.JS SAML module and can support SAML11, as well
    #  as SAML20.  The APM policy calls the irule even ADFS, with generates the token
    #  based on the submitted QueryString and the logon attributed.
    ##
    #  WS-Trust currentl only supports Username Password (adfs/services/trust/13/usernamemixed)
    switch [ACCESS::policy agent_id] {
               "ADFS" {
                    log local0. "Received Process request for FakeADFS, $AttrUserName, $AttrUserPrin, $payload"
                    set wsfed_response [ILX::call $fakeadfs_handle Generate-WSFedToken $payload $AttrUserName $AttrUserPrin]
                    ACCESS::session data set session.custom.idam.wsfedtoken $wsfed_response
                    if { $static::adfsdebug } {
                        log local0. "ADFS DEBUG: WSFedToken: $wsfed_response"                    
                    }
    }
}

#  This may or may not be needed, they arent populated with actual values, but
#  have not tested WITHOUT yet.
#
#  MSISAuth and MSISAuth1 are the encrypted cookies used to validate the SAML
#  assertion produced for the client. These are what we call the "authentication
#  cookies", and you will see these cookies ONLY when AD FS 2.0 is the IDP.
#  Without these, the client will not experience SSO when AD FS 2.0 is the IDP.
#
#  MSISAuthenticated contains a base64-encoded timestamp value for when the client
#  was authenticated. You will see this cookie set whether AD FS 2.0 is the IDP
#  or not.
#
#  MSISSignout is used to keep track of the IDP and all RPs visited for the SSO
#  session. This cookie is utilized when a WS-Federation sign-out is invoked.
#  You can see the contents of this cookie using a base64 decoder.
#  MSISLoopDetectionCookie is used by the AD FS 2.0 infinite loop detection
#  mechanism to stop clients who have ended up in an infinite redirection loop
#  to the Federation Server. For example, if an RP is having an issue where it
#  cannot consume the SAML assertion from AD FS, the RP may continuously redirect
#  the client to the AD FS 2.0 server. When the redirect loop hits a certain
#  threshold, AD FS 2.0 uses this cookie to detect that threshold being met,
#  and will throw an exception which lands the user on the AD FS 2.0 error page
#  rather than leaving them in the loop. The cookie data is a timestamp that is
#  base64 encoded.
when ACCESS_ACL_ALLOWED {
    HTTP::cookie insert name "MSISAuth" value "ABCD" path "/adfs"
    HTTP::cookie insert name "MSISSignOut" value "ABCD" path "/adfs"
    HTTP::cookie insert name "MSISAuthenticated" value "ABCD" path "/adfs"
    HTTP::cookie insert name "MSISLoopDetectionCookie" value "ABCD" path "/adfs"
}


