# npmdoc-passport-jwt

#### basic api documentation for  [passport-jwt (v2.2.1)](https://github.com/themikenicholson/passport-jwt)  [![npm package](https://img.shields.io/npm/v/npmdoc-passport-jwt.svg?style=flat-square)](https://www.npmjs.org/package/npmdoc-passport-jwt) [![travis-ci.org build-status](https://api.travis-ci.org/npmdoc/node-npmdoc-passport-jwt.svg)](https://travis-ci.org/npmdoc/node-npmdoc-passport-jwt)

#### Passport authentication strategy using JSON Web Tokens

[![NPM](https://nodei.co/npm/passport-jwt.png?downloads=true&downloadRank=true&stars=true)](https://www.npmjs.com/package/passport-jwt)

- [https://npmdoc.github.io/node-npmdoc-passport-jwt/build/apidoc.html](https://npmdoc.github.io/node-npmdoc-passport-jwt/build/apidoc.html)

[![apidoc](https://npmdoc.github.io/node-npmdoc-passport-jwt/build/screenCapture.buildCi.browser.%252Ftmp%252Fbuild%252Fapidoc.html.png)](https://npmdoc.github.io/node-npmdoc-passport-jwt/build/apidoc.html)

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
            "name": "themikenicholson"
        }
    ],
    "name": "passport-jwt",
    "optionalDependencies": {},
    "repository": {
        "type": "git",
        "url": "git+https://github.com/themikenicholson/passport-jwt.git"
    },
    "scripts": {
        "test": "mocha --reporter spec --require test/bootstrap test/*test.js",
        "testcov": "istanbul cover node_modules/mocha/bin/_mocha -- --reporter spec --require test/bootstrap test/*test.js"
    },
    "version": "2.2.1",
    "bin": {}
}
```



# misc
- this document was created with [utility2](https://github.com/kaizhu256/node-utility2)
