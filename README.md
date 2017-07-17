# Kitura-CSRF
Kitura CSRF prevention middleware

[![Build Status](https://travis-ci.org/IBM-Swift/Kitura-CSRF.svg?branch=master)](https://travis-ci.org/IBM-Swift/Kitura-CSRF)
![macOS](https://img.shields.io/badge/os-macOS-green.svg?style=flat)
![Linux](https://img.shields.io/badge/os-linux-green.svg?style=flat)
![Apache 2](https://img.shields.io/badge/license-Apache2-blue.svg?style=flat)
[![codecov](https://codecov.io/gh/IBM-Swift/Kitura-CSRF/branch/master/graph/badge.svg)](https://codecov.io/gh/IBM-Swift/Kitura-CSRF)

## Summary
Kitura [CSRF](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29) prevention middleware.

## API

To create an instance of Kitura-CSRF middleware use:

```swift
public init(ignoredMethods: [String] = ["GET", "HEAD", "OPTIONS"], retrieveToken: RetrieveTokenFunction?=nil)
```
where:

- *ignoredMethods* - an array of methods to be ignored by CSRF middleware. The default is `["GET","HEAD","OPTIONS"]`.
- *retrieveToken* - a custom callback to extract CSRF token from the request. If not set `defaultRetriveToken` is called. It looks for the token in this order:    
    - request.body["_csrf"] - if the body is URL Encoded
    - request.queryParameters["_csrf"]
    - request.headers["csrf-token"]
    - request.headers["xsrf-token"]
    - request.headers["x-csrf-token"]
    - request.headers["x-xsrf-token"]

To connect Kitura-CSRF middleware to the desired path use one of the `Router` methods, e.g.:

```swift
    router.all(<path>, middleware: CSRF())
```

Kitura-CSRF requires Kitura-Session middleware:

```swift
import KituraSession
import KituraCSRF

router.all(middleware: Session(secret: "Very very secret....."))
router.all(<path>, middleware:  CSRF())

```
## License
This library is licensed under Apache 2.0. Full license text is available in [LICENSE](LICENSE.txt).
