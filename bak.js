const querystring = require('querystring');
const url = require('url');
const https = require('https');
const crypto = require('crypto');

const api_hostname = 'api.twitter.com';
const api_root_path = '';
const api_root_url =  'https://' + api_hostname + api_root_path;

const api_version_path = '/1.1';
const api_update_status_path = '/statuses/update.json';
const api_users_show_path = '/users/show.json';

const oauth_request_token_path = '/oauth/request_token';
const oauth_access_token_path = '/oauth/access_token';
const oauth_authorize_path = '/oauth/authorize';

const oauth_signature_method = 'HMAC-SHA1';
const oauth_version = '1.0';

const get_method_str = 'GET';
const post_method_str = 'POST'; 

// Application-specific settings - To get this info you go to dev.twitter.com and select 'My apps'
var apiConsumerKey = null;
var apiConsumerSecret = null;
var oauthCallback = null;

// Response token from the /oauth/request_token
var consumerToken = null;
var consumerTokenSecret = null;

// Response token from /oauth/authorize - user-specific
var oauthTempToken = null;
var oauthVerifier = null;

// // Access Token - user-specific (got from /oauth/access_token)
// var oauthToken = null;
// var oauthTokenSecret = null;

// Current Nonce value - it is not checked for now
var oauthNonce = null;

// // Current user information (user_id and screen_name) retrieved on login
// var currentUser= null;

// Includes all the information included in the Access Token response (e.g. user_id and oauth_token)
var oauthTokenData = null;

module.exports = { 
    setApiConsumerSettings : function(api_consumer_key, api_consumer_secret, oauth_callback){
       apiConsumerKey = api_consumer_key;
       apiConsumerSecret = api_consumer_secret;
       oauthCallback = oauth_callback;
    },
    getAuthorizeUrl : function(callback){
        var oauth_nonce = getNonce();
        oauthNonce = oauth_nonce;

        var timestamp = getTimestamp();

        var oauth_data = {
            oauth_version: oauth_version,
            oauth_nonce: oauth_nonce,
            oauth_callback: oauthCallback,
            oauth_consumer_key: apiConsumerKey,
            oauth_signature_method: oauth_signature_method,
            oauth_timestamp: timestamp,
        }

        var parameterStr = getParameterString(oauth_data);

        var encodedParameterStr = encodeURIComponent(parameterStr);

        var signatureBaseStr = getSignatureBaseStr(post_method_str, encodedParameterStr, api_root_url + oauth_request_token_path);

        oauth_data.oauth_signature = getSignedBaseStr(signatureBaseStr, apiConsumerSecret, null);

        var DST = getDST(oauth_data);

        var options = {
            method: post_method_str,
            host: api_hostname,
            path: oauth_request_token_path,
            headers: {
                'Authorization': DST
            }
        }

        var post_req = https.request(options, function (response) {
            var body = '';

            response.on('data', (chunk) => {
                body += chunk;
            });

            response.on('end', () => {
                var tokenData = querystring.parse(body);
                if (tokenData.oauth_callback_confirmed) {
                    consumerToken = tokenData.oauth_token;
                    consumerTokenSecret = tokenData.oauth_token_secret;
                    var authorizeUrl = url.parse(api_root_url + oauth_authorize_path);

                    authorizeUrl.query = {
                        oauth_token: tokenData.oauth_token
                    };

                    var authorizeUrlStr = url.format(authorizeUrl);
                    callback(null,authorizeUrlStr);
                    return;
                } else {
                    error = {
                        message : 'Twitter Authorization Error - OAuth Callback Problem'
                    };
                    callback(error);
                    return;
                }
            });
        });
        post_req.on('error', function (error) {
            callback(error);
            return;
        });
        post_req.end();
    },
    getAccessToken : function(oauth_token, oauth_verifier, callback){
        var requestToken = oauth_token;
        var oauthVerifier = oauth_verifier;

        if (requestToken) {

            var oauth_nonce = getNonce();
            oauthNonce = oauth_nonce;

            var timestamp = getTimestamp();

            var oauth_data = {
                oauth_version: oauth_version,
                oauth_nonce: oauth_nonce,
                oauth_consumer_key: apiConsumerKey,
                oauth_token : requestToken,
                oauth_signature_method: oauth_signature_method,
                oauth_timestamp: timestamp,
            };

            var body = {
                oauth_verifier : oauthVerifier
            };

            var parameterStr = getParameterString(oauth_data, null, body);

            var encodedParameterStr = encodeURIComponent(parameterStr);

            var signatureBaseStr = getSignatureBaseStr(post_method_str, encodedParameterStr, api_root_url + oauth_access_token_path);

            oauth_data.oauth_signature = getSignedBaseStr(signatureBaseStr, apiConsumerSecret, oauth_token);

            var DST = getDST(oauth_data);

            var options = {
                method: post_method_str,
                host: api_hostname,
                path: oauth_access_token_path,
                headers: {
                    'Authorization': DST,
                    'Content-Type' : 'application/x-www-form-urlencoded'
                }
            }

            var post_req = https.request(options, function(response){
                var responseBody = '';

                response.on('data', function(chunk){
                    responseBody += chunk;
                });

                response.on('end', function(){
                    var tokenData = querystring.parse(responseBody);
                    if(tokenData.oauth_token){
                        // tokenData { 
                        //      oauth_token,
                        //      oauth_token_secret,
                        //      user_id,
                        //      screen_name;
                        oauthTokenData = tokenData;         
                        var callbackMessage = { 
                            user_id: oauthTokenData.user_id,
                            screen_name: oauthTokenData.screen_name
                        };
                        callback(null, callbackMessage);
                        return;
                    } else {
                        var err = {
                                message : 'Invalid Token Data received'
                        };
                        callback(err, null);
                        return;
                    }
                    // var nextStepUrl = req.session.twitter_nextStepUrl;
                    // if (nextStepUrl) {
                    //     return res.redirect(nextStepUrl);
                    // } else {
                    //     return res.ok();
                    // }
                });
            });

            post_req.on('error', function(error){
                callback(error, null);
                return;
            });

            var bodyQuerystring = querystring.stringify(body);
            post_req.write(bodyQuerystring);
            post_req.end();
    }},
    publish : function (message, callback){
        var twitter_user_token = oauthTokenData.oauth_token;
        var twitter_user_secret = oauthTokenData.oauth_token_secret;
        if (twitter_user_token && twitter_user_secret) {
            // User has authorized us to use Twitter
            var oauth_nonce = getNonce();
            oauthNonce = oauth_nonce;

            var timestamp = getTimestamp();

            var oauth_data = {
                oauth_consumer_key: apiConsumerKey,
                oauth_nonce: oauth_nonce,
                oauth_signature_method: oauth_signature_method,
                oauth_timestamp: timestamp,
                oauth_token: twitter_user_token,
                oauth_version: oauth_version,
            }

            var req_body = {
                status: message
            };

            var parameterStr = getParameterString(oauth_data, null ,req_body);

            var encodedParameterStr = encodeURIComponent(parameterStr);

            var signatureBaseStr = getSignatureBaseStr(post_method_str, encodedParameterStr, api_root_url + api_version_path +  api_update_status_path);

            oauth_data.oauth_signature = getSignedBaseStr(signatureBaseStr, apiConsumerSecret, twitter_user_secret);

            var DST = getDST(oauth_data);

            var options = {
                method: post_method_str,
                host: api_hostname,
                path: api_version_path + api_update_status_path,
                headers: { 
                    'Authorization': DST,
                    'Content-Type' : 'application/x-www-form-urlencoded'
                }
            }

            var get_req = https.request(options, function (response) {
                var body = '';  
                response.on('data', (chunk) => {
                    body += chunk;
                });
                response.on('end', () => {
                    var jsonBody = JSON.parse(body);
                    if (jsonBody.errors) {
                        callback(jsonBody.errors[0]);
                        return;
                    }
                    callback(null,true);
                    return;
                });
            });

            post_req.on('error', function (error) {
                callback(error);
                return;
            });

            req_body_query = querystring.stringify(req_body);
            post_req.write(req_body_query);
            post_req.end();
        } else {
            var error = {
                message : 'Need to login first. Please try to call getRequestToken() first'
            }
            callback(error, null);
            return;
        }
    },
    getCurrentUser : function (callback){
        if(!oauthTokenData){
            var error = { message : 'No user is logged in, please call first login()'};
            callback(error);
            return;
        }
        var twitter_user_token = oauthTokenData.oauth_token;
        var twitter_user_secret = oauthTokenData.oauth_token_secret;
        var user_id = oauthTokenData.user_id;
        if (twitter_user_token && twitter_user_secret) {
            // User has authorized us to use Twitter
            var oauth_nonce = getNonce();
            oauthNonce = oauth_nonce;

            var timestamp = getTimestamp();

            var oauth_data = {
                oauth_consumer_key: apiConsumerKey,
                oauth_nonce: oauth_nonce,
                oauth_signature_method: oauth_signature_method,
                oauth_timestamp: timestamp,
                oauth_token: twitter_user_token,
                oauth_version: oauth_version,
            }

            var query = {
                user_id: user_id
            };

            var query_str = querystring.stringify(query);

            var parameterStr = getParameterString(oauth_data, null ,query);

            var encodedParameterStr = encodeURIComponent(parameterStr);

            var signatureBaseStr = getSignatureBaseStr(get_method_str, encodedParameterStr, api_root_url + api_version_path +  api_users_show_path);

            oauth_data.oauth_signature = getSignedBaseStr(signatureBaseStr, apiConsumerSecret, twitter_user_secret);

            var DST = getDST(oauth_data);

            var options = {
                method: get_method_str,
                host: api_hostname,
                path: api_version_path + api_users_show_path + '?' + query_str,
                headers: { 
                    'Authorization': DST,
                    'Content-Type' : 'application/x-www-form-urlencoded'
                }
            }

            var get_req = https.request(options, function (response) {
                var body = '';  
                response.on('data', (chunk) => {
                    body += chunk;
                });
                response.on('end', () => {
                    var jsonBody = JSON.parse(body);
                    if (jsonBody.errors) {
                        callback(jsonBody.errors[0]);
                        return;
                    }
                    callback(null,true);
                    return;
                });
            });

            get_req.on('error', function (error) {
                callback(error);
                return;
            });
            get_req.end();
        } else {
            var error = {
                message : 'Need to login first. Please try to call getRequestToken() first'
            }
            callback(error, null);
            return;
        }
    },
    getLogoutUrl : function (callback){

    }
}

function getParameterString(oauth_data, query, body) {
    var parameterArray = [];

    if(body){
        for (var property in body) {
            if (body.hasOwnProperty(property)) {
                parameterArray
                    .push(encodeURIComponent(property) + '=' + encodeURIComponent(body[property]));
            }
        }
    }
    
    if(query){
        for (var property in query) {
            if (query.hasOwnProperty(property)) {
                parameterArray
                    .push(encodeURIComponent(property) + '=' + encodeURIComponent(query[property]));
            }
        }
    }
   
    for (var property in oauth_data) {
        if (oauth_data.hasOwnProperty(property)) {
            parameterArray
                .push(encodeURIComponent(property) + '=' + encodeURIComponent(oauth_data[property]));
        }
    }

    parameterArray.sort(function (a, b) {
        if (a < b) return -1;
        if (a > b) return 1;
        return 0;
    });


    var parameterStr = '';

    var i = 0;
    while (i != parameterArray.length) {
        parameterStr += parameterArray[i];
        if (i != parameterArray.length - 1) {
            parameterStr += '&';
        }
        i++;
    }
    return parameterStr;
}
function getNonce() {
    var buf = crypto.randomBytes(16);
    return buf.toString('hex');
}
function getSignatureBaseStr(requestMethodStr, encodedParameterStr, requestUrlStr) {
    var signatureBaseStr = requestMethodStr + '&';
    signatureBaseStr += encodeURIComponent(requestUrlStr) + '&';
    signatureBaseStr += encodedParameterStr;
    return signatureBaseStr;
}
function getSignedBaseStr(signatureBaseStr, api_consumer_secret, token_secret) {
    var signature = encodeURIComponent(api_consumer_secret) + '&';
    if (token_secret) {
        signature += encodeURIComponent(token_secret);
    }

    var hmac = crypto.createHmac('sha1', signature);
    hmac.update(signatureBaseStr);
    var base64_signature = hmac.digest('base64');

    return base64_signature;
}
function getDST(oauth_data) {
    var dstArray = [];

    for (var property in oauth_data) {
        if (oauth_data.hasOwnProperty(property)) {
            dstArray.push(encodeURIComponent(property) + '=' + '"' + encodeURIComponent(oauth_data[property]) + '"');
        }
    }

    dstArray.sort(function (a, b) {
        if (a < b) return -1;
        if (a > b) return 1;
        return 0;
    });

    var DST = 'OAuth ';

    var i = 0;
    while (i < dstArray.length) {
        DST += dstArray[i];
        if (i != dstArray.length - 1) {
            DST += ', ';
        }
        i++;
    }
    return DST;
}
function getTimestamp(){
    return Math.floor(Date.now() / 1000);
}
