<a name="OidcConsumer"></a>

## OidcConsumer
Middlewares and utilities for OIDC

**Kind**: global class  

* [OidcConsumer](#OidcConsumer)
    * [.scope](#OidcConsumer+scope)
    * [.sessionRetryDelayMS](#OidcConsumer+sessionRetryDelayMS)
    * [.callback_route](#OidcConsumer+callback_route)
    * [.callback_url](#OidcConsumer+callback_url)
    * [.allowedRedirectURIs](#OidcConsumer+allowedRedirectURIs)
    * [.sessionOptions](#OidcConsumer+sessionOptions)
    * [.session](#OidcConsumer+session)
    * [.clientConfig](#OidcConsumer+clientConfig)
    * [.serve()](#OidcConsumer+serve) ⇒
    * [.authRedirect(request, response, queryParams)](#OidcConsumer+authRedirect) ⇒
    * [.parseCallback()](#OidcConsumer+parseCallback)
    * [.authCallback(request, response, next, queryParams, [httpOptions])](#OidcConsumer+authCallback)
    * [.refresh(token, scope, [httpOptions])](#OidcConsumer+refresh) ⇒
    * [.loadSession(request, response, next, retryOnFailure)](#OidcConsumer+loadSession)
    * [.revoke(token, token_type, [httpOptions])](#OidcConsumer+revoke) ⇒

<a name="OidcConsumer+scope"></a>

### oidcConsumer.scope
scope in which the tokens are issued

**Kind**: instance property of [<code>OidcConsumer</code>](#OidcConsumer)  
<a name="OidcConsumer+sessionRetryDelayMS"></a>

### oidcConsumer.sessionRetryDelayMS
sessionRetryDelayMS dictates how long to wait when verifying session

**Kind**: instance property of [<code>OidcConsumer</code>](#OidcConsumer)  
<a name="OidcConsumer+callback_route"></a>

### oidcConsumer.callback\_route
route (internal) on server where idp would redirect to (optional)

**Kind**: instance property of [<code>OidcConsumer</code>](#OidcConsumer)  
<a name="OidcConsumer+callback_url"></a>

### oidcConsumer.callback\_url
route (internal) on server where idp would redirect to (optional)
defaults to {{response.baseURL}}/callback

**Kind**: instance property of [<code>OidcConsumer</code>](#OidcConsumer)  
<a name="OidcConsumer+allowedRedirectURIs"></a>

### oidcConsumer.allowedRedirectURIs
array of allowed-origins; supported types: glob-string, reg-exp

**Kind**: instance property of [<code>OidcConsumer</code>](#OidcConsumer)  
<a name="OidcConsumer+sessionOptions"></a>

### oidcConsumer.sessionOptions
options to be passed to setup express-sessions

**Kind**: instance property of [<code>OidcConsumer</code>](#OidcConsumer)  
<a name="OidcConsumer+session"></a>

### oidcConsumer.session
session-instance created using config passed from the user

**Kind**: instance property of [<code>OidcConsumer</code>](#OidcConsumer)  
<a name="OidcConsumer+clientConfig"></a>

### oidcConsumer.clientConfig
configuration for initiating an Authorization-Code (grant-type) client

**Kind**: instance property of [<code>OidcConsumer</code>](#OidcConsumer)  
<a name="OidcConsumer+serve"></a>

### oidcConsumer.serve() ⇒
serves the authorization redirect route after initiating an express-session (as a middleware) to store state

**Kind**: instance method of [<code>OidcConsumer</code>](#OidcConsumer)  
**Returns**: void  
<a name="OidcConsumer+authRedirect"></a>

### oidcConsumer.authRedirect(request, response, queryParams) ⇒
redirects to authorization-url generated based on provided config

**Kind**: instance method of [<code>OidcConsumer</code>](#OidcConsumer)  
**Returns**: void  
**Throws**:

- MISSING_DESTINATION
- DISALLOWED_REDIRECT_URI


| Param | Description |
| --- | --- |
| request | Express request object |
| response | Express response object |
| queryParams | Additional params to be passed in the redirect-url |

<a name="OidcConsumer+parseCallback"></a>

### oidcConsumer.parseCallback()
serves the auth-callback route after initiating an express-session (as a middleware) to store state

**Kind**: instance method of [<code>OidcConsumer</code>](#OidcConsumer)  
<a name="OidcConsumer+authCallback"></a>

### oidcConsumer.authCallback(request, response, next, queryParams, [httpOptions])
middleware that parses redirection call from the authentication-server, generates tokens for given auth-code and stores in response.headers

**Kind**: instance method of [<code>OidcConsumer</code>](#OidcConsumer)  
**Throws**:

- SECRET_MISMATCH
- MISSING_DESTINATION
- FAILURE_DESTROYING_SESSION


| Param | Description |
| --- | --- |
| request | Express request object |
| response | Express response object |
| next | Express next object |
| queryParams | Additional params to be passed in the redirect-url |
| [httpOptions] | Optional http options passed through the underlying http library for auth-code and token exchange |

<a name="OidcConsumer+refresh"></a>

### oidcConsumer.refresh(token, scope, [httpOptions]) ⇒
refresh stale or expired tokens based on a given scope

**Kind**: instance method of [<code>OidcConsumer</code>](#OidcConsumer)  
**Returns**: refreshedToken  

| Param | Description |
| --- | --- |
| token | stale or expired token that needs to be refreshed |
| scope | scope for issuing the refreshed tokens (default scope is considered if one isn't passed here) |
| [httpOptions] | Optional http options passed through the underlying http library while refreshing token |

<a name="OidcConsumer+loadSession"></a>

### oidcConsumer.loadSession(request, response, next, retryOnFailure)
Load the session in request

**Kind**: instance method of [<code>OidcConsumer</code>](#OidcConsumer)  
**Throws**:

- SESSION_LOAD_FAILED if session load fails.


| Param | Default | Description |
| --- | --- | --- |
| request |  | Express request object |
| response |  | Express response object |
| next |  | Express next object |
| retryOnFailure | <code>true</code> | Flag to throw error if found or recursively call itself |

<a name="OidcConsumer+revoke"></a>

### oidcConsumer.revoke(token, token_type, [httpOptions]) ⇒
revokes a given token for a given type

**Kind**: instance method of [<code>OidcConsumer</code>](#OidcConsumer)  
**Returns**: void  

| Param | Description |
| --- | --- |
| token | issued token that needs to be revoked |
| token_type | which type of token needs to be revoked |
| [httpOptions] | Optional http options passed through the underlying http library while revoking token |

