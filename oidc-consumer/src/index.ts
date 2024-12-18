import { NextFunction, Request, Response } from "express";
import session, { SessionOptions } from "express-session";
import { AuthorizationCode, AuthorizationTokenConfig, ModuleOptions, WreckHttpOptions } from "simple-oauth2";
import { IConsumerOptions, ICustomSession } from "./interfaces/index.js";
import { v4 as uuidv4 } from "uuid";
import { AuthDefault, ClientDefault, OptionsDefault } from "./constants/index.js";
import { minimatch } from "minimatch";

/**
 * Middlewares and utilities for OIDC
 * @class
 */
class OidcConsumer {
  scope: string;
  sessionRetryDelayMS: number;
  callback_route?: string;
  callback_url?: string;
  allowedRedirectURIs: Array<RegExp | string>;

  session: typeof session;
  #expressSession: typeof session;
  sessionOptions: SessionOptions;

  #oauth2client: AuthorizationCode<"client-id">;
  clientConfig: ModuleOptions<string>;

  constructor(options?: IConsumerOptions) {
    /**
     * scope in which the tokens are issued
     */
    this.scope = options?.scope || "";

    /**
     * sessionRetryDelayMS dictates how long to wait when verifying session
     */
    this.sessionRetryDelayMS = options?.sessionRetryDelayMS || 500;

    /**
     * route (internal) on server where idp would redirect to (optional)
     */
    this.callback_route = options?.callback_route;
    /**
     * route (internal) on server where idp would redirect to (optional)
     * defaults to {{response.baseURL}}/callback
     */
    this.callback_url = options?.callback_url;

    /**
     * array of allowed-origins; supported types: glob-string, reg-exp
     */
    this.allowedRedirectURIs = options.allowedRedirectURIs;

    /**
     * options to be passed to setup express-sessions
     */
    this.sessionOptions = options.sessionOptions;
    this.#expressSession = session(this.sessionOptions).bind(this);

    /**
     * session-instance created using config passed from the user
     */
    this.session = session(this.sessionOptions).bind(this);

    /**
     * configuration for initiating an Authorization-Code (grant-type) client
     */
    this.clientConfig = options.clientConfig;

    this.#oauth2client = new AuthorizationCode({
      auth: AuthDefault,
      client: ClientDefault,
      options: OptionsDefault,
      ...this.clientConfig,
    });
  }

  /**
   * serves the authorization redirect route after initiating an express-session (as a middleware) to store state
   * @returns void
   */
  serve() {
    return [this.#expressSession.bind(this), this.#defaultAuthRedirect.bind(this)];
  }

  /**
   * wrapper allowing usage of authRedirect method w/o the use of addition url-params
   * @param request - Express request object
   * @param response - Express response object
   * @param next - Express next object
   * @returns authCallback utility
   * @throws MISSING_DESTINATION
   * @throws DISALLOWED_REDIRECT_URI
   */
  #defaultAuthRedirect(request: Request, response: Response, _next: NextFunction) {
    return this.authRedirect(request, response, undefined);
  }

  /**
   * redirects to authorization-url generated based on provided config
   * @param request - Express request object
   * @param response - Express response object
   * @param queryParams - Additional params to be passed in the redirect-url
   * @returns void
   * @throws MISSING_DESTINATION
   * @throws DISALLOWED_REDIRECT_URI
   */
  async authRedirect(request: Request, response: Response, next: NextFunction, queryParams?: Object) {
    const { redirectUri: destination } = request.query;

    if (!destination)  return next(new Error("MISSING_DESTINATION"));

    if (!this.isRedirectUriAllowed(String(destination), this.allowedRedirectURIs)) {
      request.session.destroy((error) => {
        if (!error) return;
        console.error(error);
      });

      return next(new Error("DISALLOWED_REDIRECT_URI"));
    }

    (request.session as ICustomSession).redirect_uri = String(destination);

    const state = this.#setRandomSessionState(request);
    const callbackRedirectURI = this.getCallbackURL(request);

    const authorizationURI = this.#oauth2client.authorizeURL({
      redirect_uri: callbackRedirectURI,
      scope: this.scope,
      state,
      ...(queryParams || {}),
    });

    request.session.save(async () => {
      await this.loadSession(request, response, next, false);
      response.redirect(authorizationURI);
    });

  }

  isRedirectUriAllowed(url: string, allowedUris: any) {
    if (allowedUris instanceof String || typeof allowedUris === "string") return minimatch(url, allowedUris as string);
    else if (allowedUris instanceof RegExp) return allowedUris.test(url);
    else if (Array.isArray(allowedUris))
      for (const allowedOrigin of allowedUris) {
        if (this.isRedirectUriAllowed(url, allowedOrigin)) return true;
      }
    else return false;
  }

  getCallbackURL(request: Request) {
    return this.callback_url || `https://${request.headers.host}${this.callback_route || `${request.baseUrl}/callback`}`; // parse and assign callback route
  }

  // returns and stores state for a request
  #setRandomSessionState(request) {
    const state = uuidv4();
    (request.session as ICustomSession).state = state;
    return state;
  }

  /**
   * serves the auth-callback route after initiating an express-session (as a middleware) to store state
   */
  parseCallback() {
    return [this.#expressSession.bind(this), this.#defaultAuthCallback.bind(this)];
  }

  /**
   * wrapper allowing usage of authCallback methods w/o the use of optional http-options
   * @param request - Express request object
   * @param response - Express response object
   * @param next - Express next object
   * @returns authCallback utility
   * @throws SECRET_MISMATCH
   * @throws MISSING_DESTINATION
   * @throws FAILURE_DESTROYING_SESSION
   */
  #defaultAuthCallback(request: Request, response: Response, next: NextFunction) {
    return this.authCallback(request, response, next, undefined, undefined);
  }

  /**
   * middleware that parses redirection call from the authentication-server, generates tokens for given auth-code and stores in response.headers
   * @param request - Express request object
   * @param response - Express response object
   * @param next - Express next object
   * @param queryParams - Additional params to be passed in the redirect-url
   * @param [httpOptions] Optional http options passed through the underlying http library for auth-code and token exchange
   * @throws SECRET_MISMATCH
   * @throws MISSING_DESTINATION
   * @throws FAILURE_DESTROYING_SESSION
   */

  async authCallback(request: Request, response: Response, next: NextFunction, queryParams: Object, httpOptions?: WreckHttpOptions) {
    const { code, state } = request.query;

    if (!(request.session as ICustomSession).state) {
      console.log("Reloading session because no state in session.");
      await this.loadSession(request, response, next);
    }
  
    const sessionState = (request.session as ICustomSession).state;
    if (!sessionState) return;

    if (state !== sessionState)  return next(new Error("SECRET_MISMATCH"));

    const destination = (request.session as ICustomSession).redirect_uri;

    if (!destination) return next(new Error("MISSING_DESTINATION"));

    try {
      response.locals.sessionData = request.session;
      if (request.session)
        request.session.destroy((error) => {
          if (!error) return;
          return next(new Error("FAILURE_DESTROYING_SESSION"));
        });

      const token = await this.#oauth2client.getToken(
        {
          code: code as string,
          redirect_uri: this.getCallbackURL(request),
          scope: this.scope,
          ...queryParams, // permits passing additional query-params to the IDP
        } as AuthorizationTokenConfig, // simple-oauth2 doesn't permit passing additional params; hence forcing via types
        httpOptions
      );

      response.locals.token = token;
      next();
    } catch (error) {
      console.log({ error });
      if (error.message === "FAILURE_DESTROYING_SESSION") return next(new Error("FAILURE_DESTROYING_SESSION"));
    }
  }

  /**
   * refresh stale or expired tokens based on a given scope
   * @param token - stale or expired token that needs to be refreshed
   * @param scope - scope for issuing the refreshed tokens (default scope is considered if one isn't passed here)
   * @param [httpOptions] Optional http options passed through the underlying http library while refreshing token
   * @returns refreshedToken
   */
  async refresh(token: any, scope?: string, httpOptions?: WreckHttpOptions) {
    const accessToken = this.#oauth2client.createToken(token);
    try {
      const refreshedToken = await accessToken.refresh(
        {
          scope: scope || this.scope,
        },
        httpOptions
      );

      return refreshedToken;
    } catch (error) {
      throw error;
    }
  }

  /**
   * Load the session in request
   * @param request - Express request object
   * @param response - Express response object
   * @param next - Express next object
   * @param retryOnFailure - Flag to throw error if found or recursively call itself
   * @throws SESSION_LOAD_FAILED if session load fails.
   */ 
  async loadSession(request: Request, response: Response, next: NextFunction, retryOnFailure: Boolean = true, sessionRetryDelayMS: number = this.sessionRetryDelayMS) {
    await new Promise<void>(resolve => {
      request.session.reload((err) => {
        if(err) {
          console.log(err);
        }
      });
      resolve();
    }).catch((error) => {
      console.log(error);
      console.log("error loading session from store")
    });

    const state = (request.session as ICustomSession).state;

    if (!state) {
      if (retryOnFailure) {
        await new Promise<void>((resolve) => {
          setTimeout(async () => {
            await this.loadSession(request, response, next, false);
            resolve();
          }, sessionRetryDelayMS);
        }).catch((error) => {
          console.log(error);
          console.log("error in retry");
        });
      } else return next(new Error("SESSION_LOAD_FAILED"));
    }
  };

  /**
   * revokes a given token for a given type
   * @param token - issued token that needs to be revoked
   * @param token_type - which type of token needs to be revoked
   * @param [httpOptions] Optional http options passed through the underlying http library while revoking token
   * @returns void
   */
  async revoke(token: any, token_type: "access_token" | "refresh_token" | "all", httpOptions?: WreckHttpOptions) {
    const accessToken = this.#oauth2client.createToken(token);
    try {
      if (token_type === "all") await accessToken.revokeAll();
      else await accessToken.revoke(token_type, httpOptions);
    } catch (error) {
      throw error;
    }
  }
}

export default OidcConsumer;
