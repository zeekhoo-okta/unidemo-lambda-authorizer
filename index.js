"use strict";
const S3 = require('aws-sdk/clients/s3');
const AuthPolicy = require('aws-auth-policy');
const atob = require('atob');
const OktaJwtVerifier = require('@okta/jwt-verifier');

exports.handler = function(event, context) {
    var accessTokenString = event.authorizationToken.split(' ')[1];
    var parts = accessTokenString.split('.');
    var unverified_payload = JSON.parse(atob(parts[1]));

    var oktaJwtVerifier = new OktaJwtVerifier({
      issuer: unverified_payload.iss,
      clientId: unverified_payload.cid
    });

    oktaJwtVerifier.verifyAccessToken(accessTokenString)
    .then((jwt) => {
        var apiOptions = {};
        const arnParts = event.methodArn.split(':');
        const apiGatewayArnPart = arnParts[5].split('/');
        const awsAccountId = arnParts[4];
        apiOptions.region = arnParts[3];
        apiOptions.restApiId = apiGatewayArnPart[0];
        apiOptions.stage = apiGatewayArnPart[1];

        const policy = new AuthPolicy(jwt.claims.sub, awsAccountId, apiOptions);
        policy.allowAllMethods();
        var builtPolicy = policy.build();

        var claims = jwt.claims;
        var ctx = {};
        var issuer = null;
        for (var c in claims) {
            if (claims.hasOwnProperty(c)) {
                ctx[c] = JSON.stringify(claims[c]);
                if (c==='iss'){
                    issuer = claims[c];
                }
            }
        }
        const orgUrl = issuer.split('/oauth2')[0];
        ctx.orgUrl = JSON.stringify(orgUrl);

        const oktaOrg = orgUrl.split('https://')[1]
        ctx.oktaOrg = JSON.stringify(oktaOrg);

        const domain = oktaOrg.split('.com')[0].replace('.', '-')
        const configKey = domain + '.private.env';
        getSSWSPromise(configKey)
        .then((sswskey) => {
            ctx.ssws = JSON.stringify(sswskey);
            builtPolicy.context = ctx;
            return context.succeed(builtPolicy);
        })
        .catch((err) => {
            console.log(err);
            return context.fail('Unauthorized');
        })
    })
    .catch((err) => {
        console.log(err);
        return context.fail('Unauthorized');
    });
}


function getSSWSPromise(key) {
    return new Promise((resolve, reject) => {
        console.log('fetching SSWS from protected S3 bucket...');
        var getParams = {
            Bucket: 'unidemo-configurations',
            Key: key
        }
        var s3 = new S3();
        s3.getObject(getParams, function (err, data) {
            if (err) {
                console.log(err);
            } else {
                var config_ssws = JSON.parse(data.Body).ssws;
                console.log('config_ssws='+config_ssws);
                resolve(config_ssws);
            }

        })
    })
}
