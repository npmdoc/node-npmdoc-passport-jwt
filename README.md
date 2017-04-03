# api documentation for  [passport-jwt (v2.2.1)](https://github.com/themikenicholson/passport-jwt)  [![npm package](https://img.shields.io/npm/v/npmdoc-passport-jwt.svg?style=flat-square)](https://www.npmjs.org/package/npmdoc-passport-jwt) [![travis-ci.org build-status](https://api.travis-ci.org/npmdoc/node-npmdoc-passport-jwt.svg)](https://travis-ci.org/npmdoc/node-npmdoc-passport-jwt)
#### Passport authentication strategy using JSON Web Tokens

[![NPM](https://nodei.co/npm/passport-jwt.png?downloads=true)](https://www.npmjs.com/package/passport-jwt)

[![apidoc](https://npmdoc.github.io/node-npmdoc-passport-jwt/build/screenCapture.buildNpmdoc.browser._2Fhome_2Ftravis_2Fbuild_2Fnpmdoc_2Fnode-npmdoc-passport-jwt_2Ftmp_2Fbuild_2Fapidoc.html.png)](https://npmdoc.github.io/node-npmdoc-passport-jwt/build/apidoc.html)

![npmPackageListing](https://npmdoc.github.io/node-npmdoc-passport-jwt/build/screenCapture.npmPackageListing.svg)

![npmPackageDependencyTree](https://npmdoc.github.io/node-npmdoc-passport-jwt/build/screenCapture.npmPackageDependencyTree.svg)



# package.json

```json

{
    "author": {
        "name": "Mike Nicholson"
    },
    "bugs": {
        "url": "https://github.com/themikenicholson/passport-jwt/issues"
    },
    "dependencies": {
        "jsonwebtoken": "^7.0.0",
        "passport-strategy": "^1.0.0"
    },
    "description": "Passport authentication strategy using JSON Web Tokens",
    "devDependencies": {
        "chai": "^3.0.0",
        "chai-passport-strategy": "^1.0.0",
        "istanbul": "^0.4.5",
        "mocha": "^3.0.0",
        "sinon": "^1.0.0"
    },
    "directories": {},
    "dist": {
        "shasum": "0e004c94071319d673d9d9bcfd1574a868011527",
        "tarball": "https://registry.npmjs.org/passport-jwt/-/passport-jwt-2.2.1.tgz"
    },
    "gitHead": "6ff2a4a63ff6e3475fc0fb28207221e9ca4d3d48",
    "homepage": "https://github.com/themikenicholson/passport-jwt",
    "keywords": [
        "Passport",
        "Strategy",
        "JSON",
        "Web",
        "Token",
        "JWT"
    ],
    "license": "MIT",
    "main": "./lib",
    "maintainers": [
        {
            "name": "themikenicholson",
            "email": "themikenicholson@gmail.com"
        }
    ],
    "name": "passport-jwt",
    "optionalDependencies": {},
    "readme": "ERROR: No README data found!",
    "repository": {
        "type": "git",
        "url": "git+https://github.com/themikenicholson/passport-jwt.git"
    },
    "scripts": {
        "test": "mocha --reporter spec --require test/bootstrap test/*test.js",
        "testcov": "istanbul cover node_modules/mocha/bin/_mocha -- --reporter spec --require test/bootstrap test/*test.js"
    },
    "version": "2.2.1"
}
```



# <a name="apidoc.tableOfContents"></a>[table of contents](#apidoc.tableOfContents)

#### [module passport-jwt](#apidoc.module.passport-jwt)
1.  [function <span class="apidocSignatureSpan">passport-jwt.</span>Strategy (options, verify)](#apidoc.element.passport-jwt.Strategy)
1.  [function <span class="apidocSignatureSpan">passport-jwt.</span>Strategy.super_ ()](#apidoc.element.passport-jwt.Strategy.super_)
1.  object <span class="apidocSignatureSpan">passport-jwt.</span>ExtractJwt
1.  object <span class="apidocSignatureSpan">passport-jwt.</span>Strategy.prototype
1.  object <span class="apidocSignatureSpan">passport-jwt.</span>Strategy.super_.prototype
1.  object <span class="apidocSignatureSpan">passport-jwt.</span>auth_header

#### [module passport-jwt.ExtractJwt](#apidoc.module.passport-jwt.ExtractJwt)
1.  [function <span class="apidocSignatureSpan">passport-jwt.ExtractJwt.</span>fromAuthHeader ()](#apidoc.element.passport-jwt.ExtractJwt.fromAuthHeader)
1.  [function <span class="apidocSignatureSpan">passport-jwt.ExtractJwt.</span>fromAuthHeaderWithScheme (auth_scheme)](#apidoc.element.passport-jwt.ExtractJwt.fromAuthHeaderWithScheme)
1.  [function <span class="apidocSignatureSpan">passport-jwt.ExtractJwt.</span>fromBodyField (field_name)](#apidoc.element.passport-jwt.ExtractJwt.fromBodyField)
1.  [function <span class="apidocSignatureSpan">passport-jwt.ExtractJwt.</span>fromExtractors (extractors)](#apidoc.element.passport-jwt.ExtractJwt.fromExtractors)
1.  [function <span class="apidocSignatureSpan">passport-jwt.ExtractJwt.</span>fromHeader (header_name)](#apidoc.element.passport-jwt.ExtractJwt.fromHeader)
1.  [function <span class="apidocSignatureSpan">passport-jwt.ExtractJwt.</span>fromUrlQueryParameter (param_name)](#apidoc.element.passport-jwt.ExtractJwt.fromUrlQueryParameter)
1.  [function <span class="apidocSignatureSpan">passport-jwt.ExtractJwt.</span>versionOneCompatibility (options)](#apidoc.element.passport-jwt.ExtractJwt.versionOneCompatibility)

#### [module passport-jwt.Strategy](#apidoc.module.passport-jwt.Strategy)
1.  [function <span class="apidocSignatureSpan">passport-jwt.</span>Strategy (options, verify)](#apidoc.element.passport-jwt.Strategy.Strategy)
1.  [function <span class="apidocSignatureSpan">passport-jwt.Strategy.</span>JwtVerifier (token, secretOrKey, options, callback)](#apidoc.element.passport-jwt.Strategy.JwtVerifier)
1.  [function <span class="apidocSignatureSpan">passport-jwt.Strategy.</span>super_ ()](#apidoc.element.passport-jwt.Strategy.super_)

#### [module passport-jwt.Strategy.prototype](#apidoc.module.passport-jwt.Strategy.prototype)
1.  [function <span class="apidocSignatureSpan">passport-jwt.Strategy.prototype.</span>authenticate (req, options)](#apidoc.element.passport-jwt.Strategy.prototype.authenticate)

#### [module passport-jwt.Strategy.super_](#apidoc.module.passport-jwt.Strategy.super_)
1.  [function <span class="apidocSignatureSpan">passport-jwt.Strategy.</span>super_ ()](#apidoc.element.passport-jwt.Strategy.super_.super_)
1.  [function <span class="apidocSignatureSpan">passport-jwt.Strategy.super_.</span>Strategy ()](#apidoc.element.passport-jwt.Strategy.super_.Strategy)

#### [module passport-jwt.Strategy.super_.prototype](#apidoc.module.passport-jwt.Strategy.super_.prototype)
1.  [function <span class="apidocSignatureSpan">passport-jwt.Strategy.super_.prototype.</span>authenticate (req, options)](#apidoc.element.passport-jwt.Strategy.super_.prototype.authenticate)

#### [module passport-jwt.auth_header](#apidoc.module.passport-jwt.auth_header)
1.  [function <span class="apidocSignatureSpan">passport-jwt.auth_header.</span>parse (hdrValue)](#apidoc.element.passport-jwt.auth_header.parse)



# <a name="apidoc.module.passport-jwt"></a>[module passport-jwt](#apidoc.module.passport-jwt)

#### <a name="apidoc.element.passport-jwt.Strategy"></a>[function <span class="apidocSignatureSpan">passport-jwt.</span>Strategy (options, verify)](#apidoc.element.passport-jwt.Strategy)
- description and source-code
```javascript
function JwtStrategy(options, verify) {

    passport.Strategy.call(this);
    this.name = 'jwt';

    this._secretOrKey = options.secretOrKey;
    if (!this._secretOrKey) {
        throw new TypeError('JwtStrategy requires a secret or key');
    }

    this._verify = verify;
    if (!this._verify) {
        throw new TypeError('JwtStrategy requires a verify callback');
    }

    this._jwtFromRequest = options.jwtFromRequest;
    if (!this._jwtFromRequest) {
        throw new TypeError('JwtStrategy requires a function to retrieve jwt from requests (see option jwtFromRequest)');
    }

    this._passReqToCallback = options.passReqToCallback;
    this._verifOpts = {};

    if (options.issuer) {
        this._verifOpts.issuer = options.issuer;
    }

    if (options.audience) {
        this._verifOpts.audience = options.audience;
    }

    if (options.algorithms) {
        this._verifOpts.algorithms = options.algorithms;
    }

    if (options.ignoreExpiration != null) {
        this._verifOpts.ignoreExpiration = options.ignoreExpiration;
    }

}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.passport-jwt.Strategy.super_"></a>[function <span class="apidocSignatureSpan">passport-jwt.</span>Strategy.super_ ()](#apidoc.element.passport-jwt.Strategy.super_)
- description and source-code
```javascript
function Strategy() {
}
```
- example usage
```shell
n/a
```



# <a name="apidoc.module.passport-jwt.ExtractJwt"></a>[module passport-jwt.ExtractJwt](#apidoc.module.passport-jwt.ExtractJwt)

#### <a name="apidoc.element.passport-jwt.ExtractJwt.fromAuthHeader"></a>[function <span class="apidocSignatureSpan">passport-jwt.ExtractJwt.</span>fromAuthHeader ()](#apidoc.element.passport-jwt.ExtractJwt.fromAuthHeader)
- description and source-code
```javascript
fromAuthHeader = function () {
    return extractors.fromAuthHeaderWithScheme(DEFAULT_AUTH_SCHEME);
}
```
- example usage
```shell
...
An example configuration which reads the JWT from the http
Authorization header with the scheme 'JWT':

'''js
var JwtStrategy = require('passport-jwt').Strategy,
ExtractJwt = require('passport-jwt').ExtractJwt;
var opts = {}
opts.jwtFromRequest = ExtractJwt.fromAuthHeader();
opts.secretOrKey = 'secret';
opts.issuer = "accounts.examplesoft.com";
opts.audience = "yoursite.net";
passport.use(new JwtStrategy(opts, function(jwt_payload, done) {
User.findOne({id: jwt_payload.sub}, function(err, user) {
    if (err) {
        return done(err, false);
...
```

#### <a name="apidoc.element.passport-jwt.ExtractJwt.fromAuthHeaderWithScheme"></a>[function <span class="apidocSignatureSpan">passport-jwt.ExtractJwt.</span>fromAuthHeaderWithScheme (auth_scheme)](#apidoc.element.passport-jwt.ExtractJwt.fromAuthHeaderWithScheme)
- description and source-code
```javascript
fromAuthHeaderWithScheme = function (auth_scheme) {
    return function (request) {

        var token = null;
        if (request.headers[AUTH_HEADER]) {
            var auth_params = auth_hdr.parse(request.headers[AUTH_HEADER]);
            if (auth_params && auth_scheme === auth_params.scheme) {
                token = auth_params.value;
            }
        }
        return token;
    };
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.passport-jwt.ExtractJwt.fromBodyField"></a>[function <span class="apidocSignatureSpan">passport-jwt.ExtractJwt.</span>fromBodyField (field_name)](#apidoc.element.passport-jwt.ExtractJwt.fromBodyField)
- description and source-code
```javascript
fromBodyField = function (field_name) {
    return function (request) {
        var token = null;
        if (request.body && Object.prototype.hasOwnProperty.call(request.body, field_name)) {
            token = request.body[field_name];
        }
        return token;
    };
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.passport-jwt.ExtractJwt.fromExtractors"></a>[function <span class="apidocSignatureSpan">passport-jwt.ExtractJwt.</span>fromExtractors (extractors)](#apidoc.element.passport-jwt.ExtractJwt.fromExtractors)
- description and source-code
```javascript
fromExtractors = function (extractors) {
    if (!Array.isArray(extractors)) {
        throw new TypeError('extractors.fromExtractors expects an array')
    }

    return function (request) {
        var token = null;
        var index = 0;
        while(!token && index < extractors.length) {
            token = extractors[index].call(this, request);
            index ++;
        }
        return token;
    }
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.passport-jwt.ExtractJwt.fromHeader"></a>[function <span class="apidocSignatureSpan">passport-jwt.ExtractJwt.</span>fromHeader (header_name)](#apidoc.element.passport-jwt.ExtractJwt.fromHeader)
- description and source-code
```javascript
fromHeader = function (header_name) {
    return function (request) {
        var token = null;
        if (request.headers[header_name]) {
            token = request.headers[header_name];
        }
        return token;
    };
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.passport-jwt.ExtractJwt.fromUrlQueryParameter"></a>[function <span class="apidocSignatureSpan">passport-jwt.ExtractJwt.</span>fromUrlQueryParameter (param_name)](#apidoc.element.passport-jwt.ExtractJwt.fromUrlQueryParameter)
- description and source-code
```javascript
fromUrlQueryParameter = function (param_name) {
    return function (request) {
        var token = null,
            parsed_url = url.parse(request.url, true);
        if (parsed_url.query && Object.prototype.hasOwnProperty.call(parsed_url.query, param_name)) {
            token = parsed_url.query[param_name];
        }
        return token;
    };
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.passport-jwt.ExtractJwt.versionOneCompatibility"></a>[function <span class="apidocSignatureSpan">passport-jwt.ExtractJwt.</span>versionOneCompatibility (options)](#apidoc.element.passport-jwt.ExtractJwt.versionOneCompatibility)
- description and source-code
```javascript
versionOneCompatibility = function (options) {
    var authScheme = options.authScheme || DEFAULT_AUTH_SCHEME,
        bodyField = options.tokenBodyField || 'auth_token',
        queryParam = options.tokenQueryParameterName || 'auth_token';

    return function (request) {
        var authHeaderExtractor = extractors.fromAuthHeaderWithScheme(authScheme);
        var token =  authHeaderExtractor(request);

        if (!token) {
            var bodyExtractor = extractors.fromBodyField(bodyField);
            token = bodyExtractor(request);
        }

        if (!token) {
            var queryExtractor = extractors.fromUrlQueryParameter(queryParam);
            token = queryExtractor(request);
        }

        return token;
    };
}
```
- example usage
```shell
...

Identical behavior can be achieved under v2 with the versionOneCompatibility extractor:

'''js
var JwtStrategy = require('passport-jwt').Strategy,
    ExtractJwt = require('passport-jwt').ExtractJwt;
var opts = {}
opts.jwtFromRequest = ExtractJwt.versionOneCompatibility({ tokenBodyField = "MY_CUSTOM_BODY_FIELD" });
opts.opts.secretOrKey = 'secret';
opts.issuer = "accounts.examplesoft.com";
opts.audience = "yoursite.net";
passport.use(new JwtStrategy(opts, verifyFunction));
'''
...
```



# <a name="apidoc.module.passport-jwt.Strategy"></a>[module passport-jwt.Strategy](#apidoc.module.passport-jwt.Strategy)

#### <a name="apidoc.element.passport-jwt.Strategy.Strategy"></a>[function <span class="apidocSignatureSpan">passport-jwt.</span>Strategy (options, verify)](#apidoc.element.passport-jwt.Strategy.Strategy)
- description and source-code
```javascript
function JwtStrategy(options, verify) {

    passport.Strategy.call(this);
    this.name = 'jwt';

    this._secretOrKey = options.secretOrKey;
    if (!this._secretOrKey) {
        throw new TypeError('JwtStrategy requires a secret or key');
    }

    this._verify = verify;
    if (!this._verify) {
        throw new TypeError('JwtStrategy requires a verify callback');
    }

    this._jwtFromRequest = options.jwtFromRequest;
    if (!this._jwtFromRequest) {
        throw new TypeError('JwtStrategy requires a function to retrieve jwt from requests (see option jwtFromRequest)');
    }

    this._passReqToCallback = options.passReqToCallback;
    this._verifOpts = {};

    if (options.issuer) {
        this._verifOpts.issuer = options.issuer;
    }

    if (options.audience) {
        this._verifOpts.audience = options.audience;
    }

    if (options.algorithms) {
        this._verifOpts.algorithms = options.algorithms;
    }

    if (options.ignoreExpiration != null) {
        this._verifOpts.ignoreExpiration = options.ignoreExpiration;
    }

}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.passport-jwt.Strategy.JwtVerifier"></a>[function <span class="apidocSignatureSpan">passport-jwt.Strategy.</span>JwtVerifier (token, secretOrKey, options, callback)](#apidoc.element.passport-jwt.Strategy.JwtVerifier)
- description and source-code
```javascript
JwtVerifier = function (token, secretOrKey, options, callback) {
    return jwt.verify(token, secretOrKey, options, callback);
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.passport-jwt.Strategy.super_"></a>[function <span class="apidocSignatureSpan">passport-jwt.Strategy.</span>super_ ()](#apidoc.element.passport-jwt.Strategy.super_)
- description and source-code
```javascript
function Strategy() {
}
```
- example usage
```shell
n/a
```



# <a name="apidoc.module.passport-jwt.Strategy.prototype"></a>[module passport-jwt.Strategy.prototype](#apidoc.module.passport-jwt.Strategy.prototype)

#### <a name="apidoc.element.passport-jwt.Strategy.prototype.authenticate"></a>[function <span class="apidocSignatureSpan">passport-jwt.Strategy.prototype.</span>authenticate (req, options)](#apidoc.element.passport-jwt.Strategy.prototype.authenticate)
- description and source-code
```javascript
authenticate = function (req, options) {
    var self = this;

    var token = self._jwtFromRequest(req);

    if (!token) {
        return self.fail(new Error("No auth token"));
    }

    // Verify the JWT
    JwtStrategy.JwtVerifier(token, this._secretOrKey, this._verifOpts, function(jwt_err, payload) {
        if (jwt_err) {
            return self.fail(jwt_err);
        } else {
            // Pass the parsed token to the user
            var verified = function(err, user, info) {
                if(err) {
                    return self.error(err);
                } else if (!user) {
                    return self.fail(info);
                } else {
                    return self.success(user, info);
                }
            };

            try {
                if (self._passReqToCallback) {
                    self._verify(req, payload, verified);
                } else {
                    self._verify(payload, verified);
                }
            } catch(ex) {
                self.error(ex);
            }
        }
    });
}
```
- example usage
```shell
...
    }
    return token;
};
'''

### Authenticate requests

Use 'passport.authenticate()' specifying ''JWT'' as the strategy.

'''js
app.post('/profile', passport.authenticate('jwt', { session: false}),
    function(req, res) {
        res.send(req.user.profile);
    }
);
...
```



# <a name="apidoc.module.passport-jwt.Strategy.super_"></a>[module passport-jwt.Strategy.super_](#apidoc.module.passport-jwt.Strategy.super_)

#### <a name="apidoc.element.passport-jwt.Strategy.super_.super_"></a>[function <span class="apidocSignatureSpan">passport-jwt.Strategy.</span>super_ ()](#apidoc.element.passport-jwt.Strategy.super_.super_)
- description and source-code
```javascript
function Strategy() {
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.passport-jwt.Strategy.super_.Strategy"></a>[function <span class="apidocSignatureSpan">passport-jwt.Strategy.super_.</span>Strategy ()](#apidoc.element.passport-jwt.Strategy.super_.Strategy)
- description and source-code
```javascript
function Strategy() {
}
```
- example usage
```shell
n/a
```



# <a name="apidoc.module.passport-jwt.Strategy.super_.prototype"></a>[module passport-jwt.Strategy.super_.prototype](#apidoc.module.passport-jwt.Strategy.super_.prototype)

#### <a name="apidoc.element.passport-jwt.Strategy.super_.prototype.authenticate"></a>[function <span class="apidocSignatureSpan">passport-jwt.Strategy.super_.prototype.</span>authenticate (req, options)](#apidoc.element.passport-jwt.Strategy.super_.prototype.authenticate)
- description and source-code
```javascript
authenticate = function (req, options) {
  throw new Error('Strategy#authenticate must be overridden by subclass');
}
```
- example usage
```shell
...
    }
    return token;
};
'''

### Authenticate requests

Use 'passport.authenticate()' specifying ''JWT'' as the strategy.

'''js
app.post('/profile', passport.authenticate('jwt', { session: false}),
    function(req, res) {
        res.send(req.user.profile);
    }
);
...
```



# <a name="apidoc.module.passport-jwt.auth_header"></a>[module passport-jwt.auth_header](#apidoc.module.passport-jwt.auth_header)

#### <a name="apidoc.element.passport-jwt.auth_header.parse"></a>[function <span class="apidocSignatureSpan">passport-jwt.auth_header.</span>parse (hdrValue)](#apidoc.element.passport-jwt.auth_header.parse)
- description and source-code
```javascript
function parseAuthHeader(hdrValue) {
    if (typeof hdrValue !== 'string') {
        return null;
    }
    var matches = hdrValue.match(re);
    return matches && { scheme: matches[1], value: matches[2] };
}
```
- example usage
```shell
n/a
```



# misc
- this document was created with [utility2](https://github.com/kaizhu256/node-utility2)
