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
});
