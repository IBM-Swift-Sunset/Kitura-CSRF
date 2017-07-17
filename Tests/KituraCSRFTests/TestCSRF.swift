/**
 * Copyright IBM Corporation 2016, 2017
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

import XCTest
import Foundation

import SwiftyJSON
import Kitura
import KituraNet
import KituraSession

@testable import KituraCSRF

#if os(Linux)
    import Glibc
#else
    import Darwin
#endif

#if os(Linux)
    typealias PropValue = Any
#else
    typealias PropValue = AnyObject
#endif

let cookieDefaultName = "kitura-session-id"

class TestCSRF : XCTestCase {
    
    static var allTests : [(String, (TestCSRF) -> () throws -> Void)] {
        return [
            ("testHeaderToken", testHeaderToken),
            ("testWrongToken", testWrongToken),
            ("testNoToken", testNoToken),
            ("testCustomRetrieveToken", testCustomRetrieveToken),
            ("testIgnoredMethods", testIgnoredMethods),
            ("testURLEncoded", testURLEncoded),
            ("testQueryParameters", testQueryParameters),
        ]
    }
    
    override func tearDown() {
        doTearDown()
    }
    
    let router = TestCSRF.setupRouter()
    
    func testHeaderToken() {
        performServerTest(router) { expectation in
            self.performRequest("get", path: "qwer", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                guard (response != nil) else {
                    return
                }
                
                XCTAssertNotNil(response!.headers["csrf-token"], "No CSRF header in the response")
                guard let tokenHeaders = response!.headers["csrf-token"], tokenHeaders.count > 0 else {
                    return
                }
                let token = tokenHeaders[0]
                let (cookie, _) = CookieUtils.cookieFrom(response: response!, named: cookieDefaultName)
                XCTAssertNotNil(cookie, "Cookie \(cookieDefaultName) wasn't found in the response.")
                guard (cookie != nil) else {
                    return
                }
                let cookieValue = cookie!.value
                
                self.performRequest("post", path: "qwer", callback: {response in
                    XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                    guard (response != nil) else {
                        return
                    }
                    XCTAssertEqual(response!.statusCode, HTTPStatusCode.noContent, "HTTP Status code was \(response!.statusCode)")
                    expectation.fulfill()
                }) { request in
                    request.headers["csrf-token"] = token
                    request.headers["Cookie"] = "\(cookieDefaultName)=\(cookieValue)"
                    request.write(from: "swift=rocks")
                }
            })
        }
    }
    
    func testWrongToken() {
        performServerTest(router) { expectation in
            self.performRequest("get", path: "qwer", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                guard (response != nil) else {
                    return
                }
                let (cookie, _) = CookieUtils.cookieFrom(response: response!, named: cookieDefaultName)
                XCTAssertNotNil(cookie, "Cookie \(cookieDefaultName) wasn't found in the response.")
                guard (cookie != nil) else {
                    return
                }
                let cookieValue = cookie!.value
                
                self.performRequest("post", path: "qwer", callback: {response in
                    XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                    guard (response != nil) else {
                        return
                    }
                    XCTAssertEqual(response!.statusCode, HTTPStatusCode.forbidden, "HTTP Status code was \(response!.statusCode)")
                    expectation.fulfill()
                }) { request in
                    request.headers["csrf-token"] = "cb01dc722f4cb34c-da9396d543ec478675587ea789643553"
                    request.headers["Cookie"] = "\(cookieDefaultName)=\(cookieValue)"
                    request.write(from: "swift=rocks")
                }
            })
        }
    }
    
    func testNoToken() {
        performServerTest(router) { expectation in
            self.performRequest("get", path: "qwer", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                guard (response != nil) else {
                    return
                }
                
                XCTAssertNotNil(response!.headers["csrf-token"], "No CSRF header in the response")
                guard let tokenHeaders = response!.headers["csrf-token"],tokenHeaders.count > 0 else {
                    return
                }
                let token = tokenHeaders[0]
                let (cookie, _) = CookieUtils.cookieFrom(response: response!, named: cookieDefaultName)
                XCTAssertNotNil(cookie, "Cookie \(cookieDefaultName) wasn't found in the response.")
                guard (cookie != nil) else {
                    return
                }
                let cookieValue = cookie!.value
                
                self.performRequest("post", path: "qwer", callback: {response in
                    XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                    guard (response != nil) else {
                        return
                    }
                    XCTAssertEqual(response!.statusCode, HTTPStatusCode.forbidden, "HTTP Status code was \(response!.statusCode)")
                    expectation.fulfill()
                }) { request in
                    request.headers["lalala-token"] = token
                    request.headers["Cookie"] = "\(cookieDefaultName)=\(cookieValue)"
                    request.write(from: "swift=rocks")
                }
            })
        }
    }

    func testCustomRetrieveToken() {
        performServerTest(router) { expectation in
            self.performRequest("get", path: "zxcv", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                guard (response != nil) else {
                    return
                }
                
                XCTAssertNotNil(response!.headers["lalala-token"], "No CSRF header in the response")
                guard let tokenHeaders = response!.headers["lalala-token"], tokenHeaders.count > 0 else {
                    return
                }
                let token = tokenHeaders[0]
                let (cookie, _) = CookieUtils.cookieFrom(response: response!, named: cookieDefaultName)
                XCTAssertNotNil(cookie, "Cookie \(cookieDefaultName) wasn't found in the response.")
                guard (cookie != nil) else {
                    return
                }
                let cookieValue = cookie!.value
                
                self.performRequest("post", path: "zxcv", callback: {response in
                    XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                    guard (response != nil) else {
                        return
                    }
                    XCTAssertEqual(response!.statusCode, HTTPStatusCode.noContent, "HTTP Status code was \(response!.statusCode)")
                    expectation.fulfill()
                }) { request in
                    request.headers["lalala-token"] = token
                    request.headers["Cookie"] = "\(cookieDefaultName)=\(cookieValue)"
                    request.write(from: "swift=rocks")
                }
            })
        }
    }
    
    func testIgnoredMethods() {
        performServerTest(router) { expectation in
            self.performRequest("get", path: "asdf", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                guard (response != nil) else {
                    return
                }
                XCTAssertEqual(response!.statusCode, HTTPStatusCode.forbidden, "HTTP Status code was \(response!.statusCode)")
                expectation.fulfill()
            })
        }
    }

    func testURLEncoded() {
        performServerTest(router) { expectation in
            self.performRequest("get", path: "qwer", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                guard (response != nil) else {
                    return
                }
                XCTAssertNotNil(response!.headers["csrf-token"], "No CSRF header in the response")
                guard let tokenHeaders = response!.headers["csrf-token"], tokenHeaders.count > 0 else {
                    return
                }
                let token = tokenHeaders[0]
                let form = "type=form&_csrf=" + token + "&color=blue&name=Jane"
                let (cookie, _) = CookieUtils.cookieFrom(response: response!, named: cookieDefaultName)
                XCTAssertNotNil(cookie, "Cookie \(cookieDefaultName) wasn't found in the response.")
                guard (cookie != nil) else {
                    return
                }
                let cookieValue = cookie!.value
                
                self.performRequest("post", path: "qwer", callback: {response in
                    XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                    guard (response != nil) else {
                        return
                    }
                    XCTAssertEqual(response!.statusCode, HTTPStatusCode.noContent, "HTTP Status code was \(response!.statusCode)")
                    expectation.fulfill()
                }) { request in
                    request.headers["Cookie"] = "\(cookieDefaultName)=\(cookieValue)"
                    request.headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8"
                    request.write(from: form)
                }
            })
        }
    }
    
    func testQueryParameters() {
        performServerTest(router) { expectation in
            self.performRequest("get", path: "qwer", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                guard (response != nil) else {
                    return
                }
                XCTAssertNotNil(response!.headers["csrf-token"], "No CSRF header in the response")
                guard let tokenHeaders = response!.headers["csrf-token"], tokenHeaders.count > 0 else {
                    return
                }
                let token = tokenHeaders[0]
                let form = "type=form&_csrf=" + token + "&color=blue&name=Jane"
                let (cookie, _) = CookieUtils.cookieFrom(response: response!, named: cookieDefaultName)
                XCTAssertNotNil(cookie, "Cookie \(cookieDefaultName) wasn't found in the response.")
                guard (cookie != nil) else {
                    return
                }
                let cookieValue = cookie!.value
                
                self.performRequest("post", path: "qwer?" + form, callback: {response in
                    XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                    guard (response != nil) else {
                        return
                    }
                    XCTAssertEqual(response!.statusCode, HTTPStatusCode.noContent, "HTTP Status code was \(response!.statusCode)")
                    expectation.fulfill()
                }) { request in
                    request.headers["Cookie"] = "\(cookieDefaultName)=\(cookieValue)"
                    request.write(from: "swift=rocks")
                }
            })
        }
    }

    
    static func setupRouter() -> Router {
        let router = Router()
        let sessionTestKey = "sessionKey"
        let sessionTestValue = "sessionValue"
        
        router.all(middleware: Session(secret: "Very very secret....."))
        router.all(middleware: BodyParser())
        let csrf1 = CSRF()
        router.all("/qwer", middleware: csrf1)
        
        router.get("/qwer") { request, response, next in
            let token = csrf1.createToken(request: request)
            response.headers["csrf-token"] = token
            request.session?[sessionTestKey] = JSON(sessionTestValue as PropValue)
            response.status(.noContent)
            next()
        }
        
        router.post("/qwer") { request, response, next in
            response.status(.noContent)
            next()
        }
        
        
        let csrf2 = CSRF(retrieveToken: retrieveToken)
        router.all("/zxcv", middleware: csrf2)
        
        router.get("/zxcv") { request, response, next in
            let token = csrf2.createToken(request: request)
            response.headers["lalala-token"] = token
            request.session?[sessionTestKey] = JSON(sessionTestValue as PropValue)
            response.status(.noContent)
            next()
        }
        
        router.post("/zxcv") { request, response, next in
            response.status(.noContent)
            next()
        }
        
        
        let csrf3 = CSRF(ignoredMethods: [], retrieveToken: retrieveToken)
        router.all("/asdf", middleware: csrf3)
        
        router.get("/asdf") { request, response, next in
            let token = csrf3.createToken(request: request)
            response.headers["csrf-token"] = token
            request.session?[sessionTestKey] = JSON(sessionTestValue as PropValue)
            response.status(.noContent)
            next()
        }
        return router
    }
    
    static func retrieveToken(request: RouterRequest) -> String? {
        return request.headers["lalala-token"]
    }

}
