import { NextFunction, Request, Response } from "express";
import session, { SessionOptions } from "express-session";
import { AuthorizationCode, AuthorizationTokenConfig, ModuleOptions, WreckHttpOptions } from "simple-oauth2";
import { IConsumerOptions, ICustomSession } from "./interfaces/index.js";
import { v4 as uuidv4 } from "uuid";
import { AuthDefault, ClientDefault, OptionsDefault } from "./constants/index.js";

/**
 * Middlewares and utilities for OIDC
 * @class
 */
class OidcConsumer {
  scope: string;

  callback_route?: string;
  default_callback_route?: string;
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
     * route (internal) on server where idp would redirect to (optional)
     */
    this.callback_route = options?.callback_route;
    /**
     * route (internal) on server where idp would redirect to (optional)
     * defaults to {{response.baseURL}}/callback
     */
    this.callback_url = options?.callback_url;

    /**
     * list of allowed-origins
     */
    this.allowedRedirectURIs = options.allowedRedirectURIs;

    /**
     * options to be passed to setup express-sessions
     */
    this.sessionOptions = options.sessionOptions;
    this.#expressSession = session(this.sessionOptions).bind(this);

    /**
     * session-instance created using config passed from the user (read-only)
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
   * @throws 400 - Missing Callback URL
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
   * @throws 400 - Missing Callback URL
   */
  async authRedirect(request: Request, response: Response, queryParams?: Object) {
    const { redirectUri: destination } = request.query;

    if (!destination && !this.callback_url && !this.callback_route) return response.status(400).json({ message: "Missing Callback URL" });

    const callbackRedirectURI = this.getCallbackURL(request);

    if (!this.isOriginAllowed(String(destination), this.allowedRedirectURIs)) {
      request.session.destroy((error) => {
        if (!error) return;
        console.error(error);
      });
      return response.status(403).json({ message: "Redirects are not permitted to provided URL" });
    }

    (request.session as unknown as ICustomSession).redirect_uri = String(destination);

    const state = this.#getSessionState(request);

    const authorizationURI = this.#oauth2client.authorizeURL({
      redirect_uri: callbackRedirectURI,
      scope: this.scope,
      state,
      ...(queryParams || {}),
    });

    request.session.save();

    response.redirect(authorizationURI);
  }

  isOriginAllowed(url: string, allowedOrigins: any) {
    if (allowedOrigins instanceof String || typeof allowedOrigins === "string") {
      const { origin } = new URL(url);
      return origin === allowedOrigins;
    } else if (allowedOrigins instanceof RegExp) return allowedOrigins.test(url);
    else if (Array.isArray(allowedOrigins))
      for (const allowedOrigin of allowedOrigins) {
        if (this.isOriginAllowed(url, allowedOrigin)) return true;
      }
    else return false;
  }

  getCallbackURL(request: Request) {
    return this.callback_url || `https://${request.headers.host}${this.callback_route || `${request.baseUrl}/callback`}`; // parse and assign callback route
  }

  // returns and stores state for a request
  #getSessionState(request) {
    const state = uuidv4();
    (request.session as unknown as ICustomSession).state = state;
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
   * @throws 424 - Session State not found
   * @throws 409 - Secret Mismatch
   * @throws 400 - Missing Destination
   * @throws 500 - Couldn't destroy session
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
   * @throws 424 - Session State not found
   * @throws 409 - Secret Mismatch
   * @throws 400 - Missing Destination
   * @throws 500 - Couldn't destroy session
   */
  async authCallback(request: Request, response: Response, next: NextFunction, queryParams: Object, httpOptions?: WreckHttpOptions) {
    const { code, state } = request.query;

    const sessionState = (request.session as unknown as ICustomSession).state;
    if (!sessionState) {
      console.log("Session state not found", request);
      return response.status(424).json({ message: "Unable to locate session" });
    }
    if (state !== sessionState) return response.status(409).json({ message: "Secret Mismatch" });

    const destination = (request.session as unknown as ICustomSession).redirect_uri;

    if (!destination) return response.status(400).json({ message: "Missing destination" });

    try {
      response.locals.sessionData = request.session;
      if (request.session)
        request.session.destroy((error) => {
          if (!error) return;
          throw { message: "Couldn't destroy session", payload: error };
        });

      const token = await this.#oauth2client.getToken(
        {
          code: code as string,
          redirect_uri: this.getCallbackURL(request),
          scope: this.scope,
          ...queryParams, // permits passing additional query-params to the IDP
        } as unknown as AuthorizationTokenConfig, // simple-oauth2 doesn't permit passing additional params; hence forcing via types
        httpOptions
      );

      response.locals.token = token;
      next();
    } catch (error) {
      console.log({ error });
      if (error.message === "Couldn't destroy session") return response.send(500).json({ message: error.message });
      return response.sendStatus(500);
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
