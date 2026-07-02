import OidcConsumer from "../dist/cjs/index";
import * as sinon from 'sinon';
import { mockReq, mockRes } from 'sinon-express-mock';
import { MemoryStore } from 'express-session';
const realm = process.env.REALM || 'default_realm'; 

const allowedRedirectURIs: string[] = (process.env.ALLOWED_REDIRECT_URIS?.split(",") || []);

const consumer = new OidcConsumer({
    scope: "openid profile email",
    callback_route: `/${realm}/callback`,
    allowedRedirectURIs,
    clientConfig: {
        client: {
            id: process.env.CLIENT_ID || 'your-client-id',
            secret: process.env.CLIENT_SECRET || 'your-client-secret',
        },
        auth: {
            tokenHost: 'https://your-token-host-url.com',
            tokenPath: `/auth/realms/${realm}/protocol/openid-connect/token`,
            revokePath: `/auth/realms/${realm}/protocol/openid-connect/logout`,
            authorizePath: `/auth/realms/${realm}/protocol/openid-connect/auth`,
        },
        options: {
            authorizationMethod: "body",
        },
    },
    sessionOptions: {
        store: new MemoryStore(),
        secret: process.env.SESSION_SECRET || 'your-session-secret', 
        resave: false,
        saveUninitialized: false,
    },
});

describe("Authentication Functions", () => {
  describe('loadSession', () => {
  
    it('should successfully load session if session state is present', async () => {
      const req = mockReq();
      req.session = { state: 'valid state', reload: jest.fn((cb) => cb()) };
      
      await consumer.loadSession(req.session, true);
      expect(req.session.reload).toHaveBeenCalledTimes(1);
    });

    it('should throw an error if session.reload fails (rejects)', async () => {
      const req = mockReq();
      req.session = { reload: jest.fn((cb) => cb(new Error('Failed to load session')))};
  
      try {
        await consumer.loadSession(req.session, true);
      } catch (error) {
        expect(error).toEqual('SESSION_LOAD_FAILED');
      }
  
      expect(req.session.reload).toHaveBeenCalledTimes(2);
    });
  
    it('should throw an error if session state is missing and retryOnFailure is false', async () => {
      const req = mockReq();
      req.session = { reload: jest.fn((cb) => cb()) };

      try {
        await consumer.loadSession(req.session, false);
      } catch (error) {
        expect(error).toEqual('SESSION_LOAD_FAILED');
      }
  
      expect(req.session.reload).toHaveBeenCalledTimes(1);
    });

  
  });
  

  describe('authCallback', () => {
    it('should call next() if state matches session state', async () => {
      const req = mockReq();
      const res = mockRes();
      req.session = { state: 'dummy_state' };

      const next = sinon.spy();

      await consumer.authCallback(req, res, next, {});

      expect(next.calledOnce).toBe(true);
    });

    it('should throw an error if state does not match session state', async () => {
      const req = mockReq({
        query: { code: 'dummy_code', state: 'invalid_state' },
      });
      const res = mockRes();
      req.session = { state: 'dummy_state' };

      const next = sinon.spy();

      try {
        await consumer.authCallback(req, res, next, {});
      } catch (error) {
        expect(error.message).toEqual('SECRET_MISMATCH');
      }
    });
  });

  describe('isRedirectUriAllowedAsync', () => {
    const makeConsumer = (overrides: object = {}) => new OidcConsumer({
      scope: "openid profile email",
      callback_route: `/${realm}/callback`,
      allowedRedirectURIs: ["https://allowed.example.com/*"],
      clientConfig: consumer.clientConfig,
      sessionOptions: consumer.sessionOptions,
      ...overrides,
    });

    it('should allow a uri matching the static allowedRedirectURIs without calling the fallback', async () => {
      const fallback = jest.fn().mockResolvedValue(false);
      const testConsumer = makeConsumer({ fallbackRedirectUriValidator: fallback });

      await expect(testConsumer.isRedirectUriAllowedAsync('https://allowed.example.com/callback')).resolves.toBe(true);
      expect(fallback).not.toHaveBeenCalled();
    });

    it('should deny a uri failing the static check when no fallback is configured', async () => {
      const testConsumer = makeConsumer();

      await expect(testConsumer.isRedirectUriAllowedAsync('https://unknown.example.com/callback')).resolves.toBe(false);
    });

    it('should consult the fallback when the static check fails', async () => {
      const fallback = jest.fn().mockResolvedValue(true);
      const testConsumer = makeConsumer({ fallbackRedirectUriValidator: fallback });

      await expect(testConsumer.isRedirectUriAllowedAsync('https://team.example.com/callback')).resolves.toBe(true);
      expect(fallback).toHaveBeenCalledWith('https://team.example.com/callback');
    });

    it('should deny when the fallback returns false', async () => {
      const fallback = jest.fn().mockResolvedValue(false);
      const testConsumer = makeConsumer({ fallbackRedirectUriValidator: fallback });

      await expect(testConsumer.isRedirectUriAllowedAsync('https://unknown.example.com/callback')).resolves.toBe(false);
    });

    it('should deny (fail closed) when the fallback throws', async () => {
      const fallback = jest.fn().mockRejectedValue(new Error('lookup down'));
      const testConsumer = makeConsumer({ fallbackRedirectUriValidator: fallback });

      await expect(testConsumer.isRedirectUriAllowedAsync('https://unknown.example.com/callback')).resolves.toBe(false);
    });
  });

  describe('authRedirect with fallbackRedirectUriValidator', () => {
    it('should error DISALLOWED_REDIRECT_URI when static check and fallback both fail', async () => {
      const fallback = jest.fn().mockResolvedValue(false);
      const testConsumer = new OidcConsumer({
        scope: "openid profile email",
        callback_route: `/${realm}/callback`,
        allowedRedirectURIs: ["https://allowed.example.com/*"],
        fallbackRedirectUriValidator: fallback,
        clientConfig: consumer.clientConfig,
        sessionOptions: consumer.sessionOptions,
      });

      const req = mockReq({ query: { redirectUri: 'https://unknown.example.com/callback' } });
      const res = mockRes();
      req.session = { destroy: jest.fn((cb) => cb()) };
      const next = sinon.spy();

      await testConsumer.authRedirect(req, res, next);

      expect(fallback).toHaveBeenCalledWith('https://unknown.example.com/callback');
      expect(next.calledOnce).toBe(true);
      expect(next.firstCall.args[0].message).toEqual('DISALLOWED_REDIRECT_URI');
    });
  });
});
