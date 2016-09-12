/*
 * Copyright IBM Corporation 2016
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
 */

import Kitura
import KituraSession
import Cryptor
import LoggerAPI
import SwiftyJSON

import Foundation

// MARK CSRF

/// Cross-site request forgery prevention middleware.
public class CSRF: RouterMiddleware {

    private let ignoredMethods: [String]
    
    private var retrieveToken: RetrieveTokenFunction!
    
    /// Initialize an instance of `CSRF`.
    /// 
    /// - Parameter ignoredMethods: An array of HTTP methods to be ignored by the CSRF middleware.
    /// - Parameter retrieveToken: The custom callback to extract a CSRF token from the request.
    ///                             If not set, `CSRF.defaultRetrieveToken` is called.
    public init(ignoredMethods: [String] = ["GET", "HEAD", "OPTIONS"], retrieveToken: RetrieveTokenFunction?=nil) {
        self.ignoredMethods = ignoredMethods
        self.retrieveToken = retrieveToken ?? defaultRetrieveToken
    }
    
    /// Handle an incoming request by verifying the CSRF token in the request.
    ///
    /// - Parameter request: The `RouterRequest` object used to get information
    ///                     about the request.
    /// - Parameter response: The `RouterResponse` object used to respond to the
    ///                       request.
    /// - Parameter next: The closure to invoke to enable the Router to check for
    ///                  other handlers or middleware to work with this request.
    ///
    /// - Throws: Any `ErrorType`. If an error is thrown, processing of the request
    ///          is stopped, the error handlers, if any are defined, will be invoked,
    ///          and the user will get a response with a status code of 500.
    public func handle(request: RouterRequest, response: RouterResponse, next: @escaping () -> Void) throws {
        guard let session = request.session else {
            Log.error("Failed to check CSRF token - no session")
            next()
            return
        }
        
        let secret = createSecret(session: session)
        
        if ignoredMethods.contains(request.method.rawValue) {
            next()
            return
        }

        guard let token = retrieveToken(request) else {
            fail(response: response)
            return
        }
        
        if isValidToken(secret: secret, token: token) {
            next()
        }
        else {
            fail(response: response)
        }
    }
    
    private func defaultRetrieveToken(request: RouterRequest) -> String? {
        if let body = request.body {
            switch body {
            case .urlEncoded(let urlEncodedBody):
                if let token = urlEncodedBody["_csrf"] {
                    return token
                }
            default: break
            }
        }
        if let token = request.queryParameters["_csrf"] {
            return token
        }
        if let token = request.headers["csrf-token"] {
            return token
        }
        if let token = request.headers["xsrf-token"] {
            return token
        }
        if let token = request.headers["x-csrf-token"] {
            return token
        }
        if let token = request.headers["x-xsrf-token"] {
            return token
        }
        return nil
    }
    
    /// Create a CSRF token.
    ///
    /// - Parameter request: The `RouterRequest` object used to get information
    ///                     about the request.
    /// - Returns: A String containing the created token.
    public func createToken(request: RouterRequest) -> String? {
        guard let session = request.session else {
            Log.error("Failed to create CSRF token - no session")
            return nil
        }
        
        let secret = createSecret(session: session)
        
        do {
            let saltByteArray = try Random.generate(byteCount: 8)
            let salt = CryptoUtils.hexString(from: saltByteArray)
            return generateToken(secret: secret, salt: salt)
        } catch {
            Log.error("Failed to create CSRF token - error generating random salt")
            return nil
        }
    }
    
    private func fail(response: RouterResponse) {
        do {
            try response.status(.forbidden).send("Invalid CSRF token").end()
        } catch {
            Log.error("Failed to send response")
        }
    }
    
    private func createSecret(session: SessionState) -> String {
        var secret: String
        let sessionSecret = session["CSRFSecret"]
        if sessionSecret.type != .null {
            secret = sessionSecret.stringValue
        }
        else {
            secret = NSUUID().uuidString
            session["CSRFSecret"] = JSON(secret)
        }
        return secret
    }

    private func generateToken(secret: String, salt: String) -> String? {
        if let digest = Digest(using: .md5).update(string: salt + "-" + secret)?.final() {
            return salt + "-" + CryptoUtils.hexString(from: digest)
        }
        return nil
    }
    
    private func isValidToken(secret: String, token: String) -> Bool {
        let salt = token.components(separatedBy: "-")[0]
        let expectedToken = generateToken(secret: secret, salt: salt)
        return expectedToken == token
    }
}
