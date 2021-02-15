'use strict';

var events = require('events');
var rewire = require('rewire');
var regexp = require('uuid-regexp/regexp');
var ewdSession = rewire('../../lib/ewdSession', {
  ignore: ['setInterval']
});
var documentStoreMock = require('./mocks/documentStore');
var documentNodeMock = require('./mocks/documentNode');
var requestMock = require('./mocks/request');

describe('unit/ewdSession:', function () {
  var documentStore;
  var SessionFactory;
  var Session;
  var TokenFactory;
  var Token;
  var Worker;
  var sessionSpy;
  var tokenSpy;
  var uuid;
  var jwt;

  var revert = function (obj) {
    obj.revert();
    delete obj.revert;
  };

  beforeAll(function () {
    SessionFactory = function () {
      return Session.apply(this, arguments);
    };

    TokenFactory = function () {
      return Token.apply(this, arguments);
    };

    Worker = function (documentStore) {
      this.documentStore = documentStore;
      events.EventEmitter.call(this);
    };

    Worker.prototype = Object.create(events.EventEmitter.prototype);
    Worker.prototype.constructor = Worker;
  });

  beforeEach(function () {
    jasmine.clock().install();

    documentStore = documentStoreMock.mock();

    sessionSpy = jasmine.createSpy().and.callFake(SessionFactory);
    sessionSpy.revert = ewdSession.__set__('Session', sessionSpy);

    tokenSpy = jasmine.createSpy().and.callFake(TokenFactory);
    tokenSpy.revert = ewdSession.__set__('Token', tokenSpy);

    jwt = jasmine.createSpyObj('jwt', ['encode', 'decode']);
    jwt.revert = ewdSession.__set__('jwt', jwt);

    uuid = jasmine.createSpy();
    uuid.revert = ewdSession.__set__('uuid', uuid);
  });

  afterEach(function () {
    jasmine.clock().uninstall();

    ewdSession.__set__('documentStore', undefined);
    ewdSession.__set__('documentName', undefined);

    revert(sessionSpy);
    revert(tokenSpy);
    revert(jwt);
    revert(uuid);
  });

  describe('#init', function () {
    it('should be function', function () {
      expect(ewdSession.init).toEqual(jasmine.any(Function));
    });

    it('should initialize module', function () {
      ewdSession.init(documentStore);

      expect(ewdSession.__get__('documentStore')).toBe(documentStore);
      expect(ewdSession.__get__('documentName')).toBe('%zewdSession');
    });

    it('should initialize module with custom document name', function () {
      ewdSession.init(documentStore, 'foobar');

      expect(ewdSession.__get__('documentStore')).toBe(documentStore);
      expect(ewdSession.__get__('documentName')).toBe('foobar');
    });
  });

  describe('#addTo', function () {
    it('should be function', function () {
      expect(ewdSession.addTo).toEqual(jasmine.any(Function));
    });

    it('should be reference to init method', function () {
      expect(ewdSession.addTo).toBe(ewdSession.init);
    });
  });

  describe('#create', function () {
    beforeEach(function () {
      ewdSession.init(documentStore);

      var nowTime = Date.UTC(2017, 0, 1); // 1483228800 * 1000, now
      jasmine.clock().mockDate(new Date(nowTime));
    });

    it('should be function', function () {
      expect(ewdSession.create).toEqual(jasmine.any(Function));
    });

    it('called without parameters', function () {
      var session = {
        id: '12345',
        data: documentNodeMock.mock()
      };
      var token = {
        value: 'tokenValue'
      };

      Session = function () {
        return session;
      };

      Token = function () {
        return token;
      };

      var actual = ewdSession.create();

      expect(sessionSpy).toHaveBeenCalledWith(documentStore, null, undefined, '%zewdSession');
      expect(session.data.delete).toHaveBeenCalled();
      expect(tokenSpy).toHaveBeenCalledWith(documentStore, null, '%zewdSession');
      expect(session.data.setDocument).toHaveBeenCalledWith({
        'ewd-session': {
          token: 'tokenValue',
          id: '12345',
          timeout: 3600,
          expiry: 1483232400,
          application: 'undefined',
          authenticated: false
        }
      });
      expect(actual).toBe(session);
    });

    it('called with custom parameters', function () {
      var application = 'myApp';
      var timeout = 10000;
      var updateExpiry = true;

      var session = {
        id: '12345',
        data: documentNodeMock.mock()
      };
      var token = {
        value: 'tokenValue'
      };

      Session = function () {
        return session;
      };

      Token = function () {
        return token;
      };

      var actual = ewdSession.create(application, timeout, updateExpiry);

      expect(sessionSpy).toHaveBeenCalledWith(documentStore, null, true, '%zewdSession');
      expect(session.data.delete).toHaveBeenCalled();
      expect(tokenSpy).toHaveBeenCalledWith(documentStore, null, '%zewdSession');
      expect(session.data.setDocument).toHaveBeenCalledWith({
        'ewd-session': {
          token: 'tokenValue',
          id: '12345',
          timeout: 10000,
          expiry: 1483238800,
          application: 'myApp',
          authenticated: false
        }
      });
      expect(actual).toBe(session);
    });

    it('called with application is object', function () {
      var application = {
        timeout: 20000,
        updateExpiry: false,
        jwtPayload: {
          foo: 'bar'
        },
        application: 'myApp'
      };
      var timeout = 10000;
      var updateExpiry = true;

      var session = {
        id: '12345',
        data: documentNodeMock.mock()
      };
      var token = {
        value: 'tokenValue'
      };

      Session = function () {
        return session;
      };

      Token = function () {
        return token;
      };

      uuid.and.returnValue('jwtSecretValue');
      jwt.encode.and.returnValue('jwtTokenValue');

      var actual = ewdSession.create(application, timeout, updateExpiry);

      expect(sessionSpy).toHaveBeenCalledWith(documentStore, null, false, '%zewdSession');
      expect(session.data.delete).toHaveBeenCalled();
      expect(tokenSpy).toHaveBeenCalledWith(documentStore, null, '%zewdSession');
      expect(uuid).toHaveBeenCalled();
      expect(jwt.encode).toHaveBeenCalledWith({
        foo: 'bar',
        exp: 1483248800,
        iat: 1483228800,
        iss: 'qewd:myApp',
        jti: 'tokenValue.1483228800'
      }, 'jwtSecretValue');
      expect(session.data.setDocument).toHaveBeenCalledWith({
        'ewd-session': {
          token: 'tokenValue',
          id: '12345',
          timeout: 20000,
          expiry: 1483248800,
          application: 'myApp',
          authenticated: false,
          jwt: {
            secret: 'jwtSecretValue',
            token: 'jwtTokenValue'
          }
        }
      });
      expect(actual).toBe(session);
    });
  });

  describe('#uuid', function () {
    it('should return uuid', function () {
      expect(ewdSession.uuid).toMatch(regexp.versioned.source);
    });
  });

  describe('#symbolTable', function () {
    it('should return symbolTable factory', function () {
      expect(ewdSession.symbolTable).toEqual(jasmine.any(Function));

      var methods = ['clear', 'save', 'restore', 'get', 'setVar', 'getVar', 'killVar'];
      var symbolTable = ewdSession.symbolTable();

      methods.forEach(function (method) {
        expect(symbolTable[method]).toEqual(jasmine.any(Function));
      });
    });
  });

  /*
  describe('#garbageCollector', function () {
    var node;
    var worker;

    beforeEach(function () {
      Session = function (documentStore, id) {
        return {
          id: id,
          expired: id === '12345'
        };
      };

      node = documentNodeMock.mock();
      node.forEachChild.and.callFake(function (cb) {
        cb('12345');
        cb('98765');
      });

      spyOn(documentStore, 'DocumentNode').and.returnValue(node);

      worker = new Worker(documentStore);
    });

    it('should be function', function () {
      expect(ewdSession.garbageCollector).toEqual(jasmine.any(Function));
    });

    it('should clear expired session', function () {
      ewdSession.garbageCollector(worker);

      jasmine.clock().tick(6 * 60 * 1000);
      worker.emit('stop');

      expect(documentStore.DocumentNode).toHaveBeenCalledWith('%zewdSession', ['session']);
      expect(sessionSpy).toHaveBeenCalledTimes(2);
      expect(sessionSpy.calls.argsFor(0)).toEqual([documentStore, '12345', false, '%zewdSession']);
      expect(sessionSpy.calls.argsFor(1)).toEqual([documentStore, '98765', false, '%zewdSession']);
    });

    it('should clear using custom document name', function () {
      ewdSession.init(documentStore, 'foobar');

      ewdSession.garbageCollector(worker);

      jasmine.clock().tick(6 * 60 * 1000);
      worker.emit('stop');

      expect(documentStore.DocumentNode).toHaveBeenCalledWith('foobar', ['session']);
      expect(sessionSpy).toHaveBeenCalledTimes(2);
      expect(sessionSpy.calls.argsFor(0)).toEqual([documentStore, '12345', false, 'foobar']);
      expect(sessionSpy.calls.argsFor(1)).toEqual([documentStore, '98765', false, 'foobar']);
    });

    it('should clear using custom delay', function () {
      ewdSession.init(documentStore, 'foobar');

      ewdSession.garbageCollector(worker, 2 * 60);

      jasmine.clock().tick(3 * 60 * 1000);
      worker.emit('stop');

      expect(sessionSpy).toHaveBeenCalledTimes(2);
    });
  });
  */

  describe('#authenticate', function () {
    beforeEach(function () {
      ewdSession.init(documentStore);
    });

    it('should be function', function () {
      expect(ewdSession.authenticate).toEqual(jasmine.any(Function));
    });

    it('should return missing authorization header error', function () {
      var expected = {
        error: 'Missing authorization header',
        status: {
          code: 403,
          text: 'Forbidden'
        }
      };

      var actual = ewdSession.authenticate();

      expect(tokenSpy).not.toHaveBeenCalled();
      expect(actual).toEqual(expected);
    });

    it('should return invalid token or session expired error', function () {
      var expected = {
        error: 'Invalid token or session expired',
        status: {
          code: 403,
          text: 'Forbidden'
        }
      };

      var token = 'tokenValue';
      var sessionInstance = {
        exists: false
      };
      var tokenInstance = {
        session: sessionInstance
      };

      Token = function () {
        return tokenInstance;
      };

      var actual = ewdSession.authenticate(token);

      expect(tokenSpy).toHaveBeenCalledWith(documentStore, 'tokenValue', '%zewdSession');
      expect(actual).toEqual(expected);
    });

    it('should return session expired error', function () {
      var expected = {
        error: 'Session expired',
        status: {
          code: 403,
          text: 'Forbidden'
        }
      };

      var token = 'tokenValue';
      var sessionInstance = {
        exists: true,
        expired: true
      };
      var tokenInstance = {
        session: sessionInstance
      };

      Token = function () {
        return tokenInstance;
      };

      var actual = ewdSession.authenticate(token);

      expect(tokenSpy).toHaveBeenCalledWith(documentStore, 'tokenValue', '%zewdSession');
      expect(actual).toEqual(expected);
    });

    it('should return session when no check', function () {
      var token = 'tokenValue';
      var loggingIn = 'noCheck';
      var sessionInstance = {
        exists: true,
        expired: false
      };
      var tokenInstance = {
        session: sessionInstance
      };

      Token = function () {
        return tokenInstance;
      };

      var actual = ewdSession.authenticate(token, loggingIn);

      expect(tokenSpy).toHaveBeenCalledWith(documentStore, 'tokenValue', '%zewdSession');
      expect(actual).toEqual({
        session: sessionInstance
      });
    });

    it('should return user already logged in error', function () {
      var expected = {
        error: 'User already logged in',
        status: {
          code: 403,
          text: 'Forbidden'
        }
      };

      var token = 'tokenValue';
      var loggingIn = true;
      var sessionInstance = {
        exists: true,
        expired: false,
        authenticated: true
      };
      var tokenInstance = {
        session: sessionInstance
      };

      Token = function () {
        return tokenInstance;
      };

      var actual = ewdSession.authenticate(token, loggingIn);

      expect(tokenSpy).toHaveBeenCalledWith(documentStore, 'tokenValue', '%zewdSession');
      expect(actual).toEqual(expected);
    });

    it('should return session if logging in and not authenticated', function () {
      var token = 'tokenValue';
      var loggingIn = true;
      var sessionInstance = {
        exists: true,
        expired: false,
        authenticated: false
      };
      var tokenInstance = {
        session: sessionInstance
      };

      Token = function () {
        return tokenInstance;
      };

      var actual = ewdSession.authenticate(token, loggingIn);

      expect(tokenSpy).toHaveBeenCalledWith(documentStore, 'tokenValue', '%zewdSession');
      expect(actual).toEqual({
        session: sessionInstance
      });
    });

    it('should return user has not logged in error', function () {
      var expected = {
        error: 'User has not logged in',
        status: {
          code: 403,
          text: 'Forbidden'
        }
      };

      var token = 'tokenValue';
      var loggingIn = false;
      var sessionInstance = {
        exists: true,
        expired: false,
        authenticated: false
      };
      var tokenInstance = {
        session: sessionInstance
      };

      Token = function () {
        return tokenInstance;
      };

      var actual = ewdSession.authenticate(token, loggingIn);

      expect(tokenSpy).toHaveBeenCalledWith(documentStore, 'tokenValue', '%zewdSession');
      expect(actual).toEqual(expected);
    });

    it('should update expiry', function () {
      var token = 'tokenValue';
      var loggingIn = false;
      var sessionInstance = {
        exists: true,
        expired: false,
        authenticated: true,
        updateExpiry: jasmine.createSpy()
      };
      var tokenInstance = {
        session: sessionInstance
      };

      Token = function () {
        return tokenInstance;
      };

      var actual = ewdSession.authenticate(token, loggingIn);

      expect(tokenSpy).toHaveBeenCalledWith(documentStore, 'tokenValue', '%zewdSession');
      expect(sessionInstance.updateExpiry).toHaveBeenCalled();
      expect(actual).toEqual({
        session: sessionInstance
      });
    });
  });

  describe('#authenticateByJWT', function () {
    var tokenAuthenticateSpy;

    beforeEach(function () {
      tokenAuthenticateSpy = jasmine.createSpy();
      tokenAuthenticateSpy.revert = ewdSession.__set__('tokenAuthenticate', tokenAuthenticateSpy);
    });

    afterEach(function () {
      revert(tokenAuthenticateSpy);
    });

    it('should be function', function () {
      expect(ewdSession.authenticateByJWT).toEqual(jasmine.any(Function));
    });

    it('should return invalid JWT error', function () {
      var expected = {
        error: 'Invalid JWT: Error: decode error',
        status: {
          code: 403,
          text: 'Forbidden'
        }
      };

      var jwtToken = 'jwtTokenValue';

      jwt.decode.and.throwError('decode error');

      var actual = ewdSession.authenticateByJWT(jwtToken);

      expect(jwt.decode).toHaveBeenCalledWith('jwtTokenValue', null, true);
      expect(actual).toEqual(expected);
    });

    it('should return missing or empty QEWD token error', function () {
      var expected = {
        error: 'Missing or empty QEWD token',
        status: {
          code: 403,
          text: 'Forbidden'
        }
      };

      var jwtToken = 'jwtTokenValue';

      jwt.decode.and.returnValues(
        null,
        {},
        {
          jti: ''
        }
      );

      [1, 2, 3].forEach(function () {
        var actual = ewdSession.authenticateByJWT(jwtToken);

        expect(jwt.decode).toHaveBeenCalledWith('jwtTokenValue', null, true);
        expect(actual).toEqual(expected);
      });
    });

    it('should return token authenticate error', function () {
      var expected = {
        error: 'Session expired',
        status: {
          code: 403,
          text: 'Forbidden'
        }
      };

      tokenAuthenticateSpy.and.returnValue(expected);

      var jwtToken = 'jwtTokenValue';
      var loggingIn = 'noCheck';

      jwt.decode.and.returnValue({
        foo: 'bar',
        exp: 1483248800,
        iat: 1483228800,
        iss: 'qewd:myApp',
        jti: 'tokenValue.1483228800'
      });

      var actual = ewdSession.authenticateByJWT(jwtToken, loggingIn);

      expect(jwt.decode).toHaveBeenCalledWith('jwtTokenValue', null, true);
      expect(tokenAuthenticateSpy).toHaveBeenCalledWith('tokenValue', 'noCheck');
      expect(jwt.encode).not.toHaveBeenCalled();
      expect(actual).toEqual(expected);
    });

    it('should return invalid JWT error', function () {
      var expected = {
        error: 'Invalid JWT',
        status: {
          code: 403,
          text: 'Forbidden'
        }
      };

      tokenAuthenticateSpy.and.returnValue({
        session: {
          jwtSecret: 'jwtSecretValue'
        }
      });

      var jwtToken = 'jwtTokenValue';
      var loggingIn = 'noCheck';

      var payload = {
        foo: 'bar',
        exp: 1483248800,
        iat: 1483228800,
        iss: 'qewd:myApp',
        jti: 'tokenValue.1483228800'
      };

      jwt.decode.and.returnValue(payload);
      jwt.encode.and.returnValue('foobar');

      var actual = ewdSession.authenticateByJWT(jwtToken, loggingIn);

      expect(jwt.decode).toHaveBeenCalledWith('jwtTokenValue', null, true);
      expect(tokenAuthenticateSpy).toHaveBeenCalledWith('tokenValue', 'noCheck');
      expect(jwt.encode).toHaveBeenCalledWith(payload, 'jwtSecretValue');
      expect(actual).toEqual(expected);
    });

    it('should return status', function () {
      var sessionInstance = {
        jwtSecret: 'jwtSecretValue'
      };

      tokenAuthenticateSpy.and.returnValue({
        session: sessionInstance
      });

      var jwtToken = 'jwtTokenValue';
      var loggingIn = 'noCheck';

      var payload = {
        foo: 'bar',
        exp: 1483248800,
        iat: 1483228800,
        iss: 'qewd:myApp',
        jti: 'tokenValue.1483228800'
      };

      jwt.decode.and.returnValue(payload);
      jwt.encode.and.returnValue(jwtToken);

      var actual = ewdSession.authenticateByJWT(jwtToken, loggingIn);

      expect(jwt.decode).toHaveBeenCalledWith('jwtTokenValue', null, true);
      expect(tokenAuthenticateSpy).toHaveBeenCalledWith('tokenValue', 'noCheck');
      expect(jwt.encode).toHaveBeenCalledWith(payload, 'jwtSecretValue');
      expect(actual).toEqual({
        session: sessionInstance,
        payload: payload
      });
    });
  });

  describe('#httpAuthenticate', function () {
    var tokenAuthenticateSpy;

    beforeEach(function () {
      tokenAuthenticateSpy = jasmine.createSpy();
      tokenAuthenticateSpy.revert = ewdSession.__set__('tokenAuthenticate', tokenAuthenticateSpy);
    });

    afterEach(function () {
      revert(tokenAuthenticateSpy);
    });

    it('should be function', function () {
      expect(ewdSession.httpAuthenticate).toEqual(jasmine.any(Function));
    });

    it('should return missing authorization or cookie header error', function () {
      var expected = {
        error: 'Missing Authorization or Cookie Header',
        status: {
          code: 403,
          text: 'Forbidden'
        }
      };

      var httpHeaders = {};

      var actual = ewdSession.httpAuthenticate(httpHeaders);

      expect(actual).toEqual(expected);
    });

    describe('via authorization header', function () {
      it('should return missing or empty QEWD session token error', function () {
        var expected = {
          error: 'Missing or Empty QEWD Session Token',
          status: {
            code: 403,
            text: 'Forbidden'
          }
        };

        var httpHeaders = {
          authorization: 'QEWD token='
        };

        var actual = ewdSession.httpAuthenticate(httpHeaders);

        expect(actual).toEqual(expected);
      });

      it('should return missing or empty QEWD session token error with custom credentials', function () {
        var expected = {
          error: 'Missing or Empty QEWD Session Token',
          status: {
            code: 403,
            text: 'Forbidden'
          }
        };

        var httpHeaders = {
          authorization: 'foo='
        };
        var credentials = {
          authorization: 'foo'
        };

        var actual = ewdSession.httpAuthenticate(httpHeaders, credentials);

        expect(actual).toEqual(expected);
      });

      it('should return tokenAuthenticate result', function () {
        var sessionInstance = {};

        tokenAuthenticateSpy.and.returnValue({
          session: sessionInstance
        });

        var httpHeaders = {
          authorization: 'QEWD token=tokenValue'
        };

        var actual = ewdSession.httpAuthenticate(httpHeaders);

        expect(tokenAuthenticateSpy).toHaveBeenCalledWith('tokenValue', 'noCheck');
        expect(actual).toEqual({
          session: sessionInstance
        });
      });
    });

    describe('via cookie', function () {
      it('should return missing or empty QEWD session token error', function () {
        var expected = {
          error: 'Missing or Empty QEWD Session Token',
          status: {
            code: 403,
            text: 'Forbidden'
          }
        };

        var httpHeaders = {
          cookie: 'QEWDTOKEN='
        };

        var actual = ewdSession.httpAuthenticate(httpHeaders);

        expect(actual).toEqual(expected);
      });

      it('should return missing or empty QEWD session token error with custom credentials', function () {
        var expected = {
          error: 'Missing or Empty QEWD Session Token',
          status: {
            code: 403,
            text: 'Forbidden'
          }
        };

        var httpHeaders = {
          cookie: 'bar='
        };
        var credentials = {
          cookie: 'bar'
        };

        var actual = ewdSession.httpAuthenticate(httpHeaders, credentials);

        expect(actual).toEqual(expected);
      });

      it('should return tokenAuthenticate result', function () {
        var sessionInstance = {};

        tokenAuthenticateSpy.and.returnValue({
          session: sessionInstance
        });

        var httpHeaders = {
          cookie: 'QEWDTOKEN=tokenValue;foo=bar;'
        };

        var actual = ewdSession.httpAuthenticate(httpHeaders);

        expect(tokenAuthenticateSpy).toHaveBeenCalledWith('tokenValue', 'noCheck');
        expect(actual).toEqual({
          session: sessionInstance
        });
      });
    });
  });

  describe('#authenticateRestRequest', function () {
    var tokenAuthenticateSpy;

    beforeEach(function () {
      ewdSession.init(documentStore);

      tokenAuthenticateSpy = jasmine.createSpy();
      tokenAuthenticateSpy.revert = ewdSession.__set__('tokenAuthenticate', tokenAuthenticateSpy);
    });

    afterEach(function () {
      revert(tokenAuthenticateSpy);
    });

    it('should be function', function () {
      expect(ewdSession.authenticateRestRequest).toEqual(jasmine.any(Function));
    });

    it('should return authorization header missing error', function () {
      var req = requestMock.mock();
      var finished = jasmine.createSpy();
      var bearer = null;
      var loggingIn = 'noCheck';

      var actual = ewdSession.authenticateRestRequest(req, finished, bearer, loggingIn);

      expect(finished).toHaveBeenCalledWith({
        error: 'Authorization header missing'
      });
      expect(actual).toBeFalsy();
    });

    describe('bearer === false', function () {
      it('should return token authenticate error', function () {
        var req = requestMock.mock();
        var finished = jasmine.createSpy();
        var bearer = false;
        var loggingIn = 'noCheck';

        req.headers.authorization = 'authorizationValue';

        tokenAuthenticateSpy.and.returnValue({
          error: 'Invalid token or session expired',
          status: {
            code: 403,
            text: 'Forbidden'
          }
        });

        var actual = ewdSession.authenticateRestRequest(req, finished, bearer, loggingIn);

        expect(tokenAuthenticateSpy).toHaveBeenCalledWith('authorizationValue', 'noCheck');
        expect(finished).toHaveBeenCalledWith({
          error: 'Invalid token or session expired',
          status: {
            code: 403,
            text: 'Forbidden'
          }
        });
        expect(actual).toBeFalsy();
      });

      it('should set session to request', function () {
        var sessionInstance = {};

        var req = requestMock.mock();
        var finished = jasmine.createSpy();
        var bearer = false;
        var loggingIn = 'noCheck';

        req.headers.authorization = 'authorizationValue';

        tokenAuthenticateSpy.and.returnValue({
          session: sessionInstance
        });

        var actual = ewdSession.authenticateRestRequest(req, finished, bearer, loggingIn);

        expect(tokenAuthenticateSpy).toHaveBeenCalledWith('authorizationValue', 'noCheck');
        expect(req.session).toBe(sessionInstance);
        expect(actual).toBeTruthy();
      });
    });

    it('should return authorization header invalid error', function () {
      var req = requestMock.mock();
      var finished = jasmine.createSpy();
      var bearer = null;
      var loggingIn = 'noCheck';

      req.headers.authorization = 'invalid';

      var actual = ewdSession.authenticateRestRequest(req, finished, bearer, loggingIn);

      expect(finished).toHaveBeenCalledWith({
        error: 'Authorization header invalid - expected format: Bearer {{token}}'
      });
      expect(actual).toBeFalsy();
    });

    it('should set session to request', function () {
      var sessionInstance = {};

      var req = requestMock.mock();
      var finished = jasmine.createSpy();
      var bearer = null;
      var loggingIn = 'noCheck';

      req.headers.authorization = 'Bearer AbCdEf123456';

      tokenAuthenticateSpy.and.returnValue({
        session: sessionInstance
      });

      var actual = ewdSession.authenticateRestRequest(req, finished, bearer, loggingIn);

      expect(tokenAuthenticateSpy).toHaveBeenCalledWith('AbCdEf123456', 'noCheck');
      expect(req.session).toBe(sessionInstance);
      expect(actual).toBeTruthy();
    });
  });

  describe('#active', function () {
    beforeEach(function () {
      ewdSession.init(documentStore);
    });

    it('should be function', function () {
      expect(ewdSession.active).toEqual(jasmine.any(Function));
    });

    it('should return active sessions', function () {
      var expected = [
        {
          id: '98765',
          expired: false
        }
      ];

      Session = function (documentStore, id) {
        return {
          id: id,
          expired: id === '12345'
        };
      };

      var node = documentNodeMock.mock();
      node.forEachChild.and.callFake(function (cb) {
        cb('12345');
        cb('98765');
      });

      spyOn(documentStore, 'DocumentNode').and.returnValue(node);

      var actual = ewdSession.active();

      expect(documentStore.DocumentNode).toHaveBeenCalledWith('%zewdSession', ['session']);
      expect(sessionSpy).toHaveBeenCalledTimes(2);
      expect(sessionSpy.calls.argsFor(0)).toEqual([documentStore, '12345', false, '%zewdSession']);
      expect(sessionSpy.calls.argsFor(1)).toEqual([documentStore, '98765', false, '%zewdSession']);
      expect(actual).toEqual(expected);
    });
  });

  describe('#byToken', function () {
    beforeEach(function () {
      ewdSession.init(documentStore);
    });

    it('should be function', function () {
      expect(ewdSession.byToken).toEqual(jasmine.any(Function));
    });

    it('should return nothing', function () {
      [null, undefined, ''].forEach(function (token) {
        var actual = ewdSession.byToken(token);

        expect(actual).toBeUndefined();
      });
    });

    it('should return nothing when no session id', function () {
      spyOn(documentStore, 'DocumentNode').and.returnValue({
        value: ''
      });

      var token = 'tokenValue';

      var actual = ewdSession.byToken(token);

      expect(documentStore.DocumentNode).toHaveBeenCalledWith('%zewdSession', ['sessionsByToken', 'tokenValue']);
      expect(actual).toBeUndefined();
    });

    it('should return nothing when session expired', function () {
      Session = function () {
        return {
          expired: true
        };
      };

      spyOn(documentStore, 'DocumentNode').and.returnValue({value: '12345'});

      var token = 'tokenValue';

      var actual = ewdSession.byToken(token);

      expect(documentStore.DocumentNode).toHaveBeenCalledWith('%zewdSession', ['sessionsByToken', 'tokenValue']);
      expect(sessionSpy).toHaveBeenCalledWith(documentStore, '12345', false, '%zewdSession');
      expect(actual).toBeUndefined();
    });

    it('should return nothing when session expired', function () {
      var sessionInstance = {
        expired: false
      };

      Session = function () {
        return sessionInstance;
      };

      spyOn(documentStore, 'DocumentNode').and.returnValue({value: '12345'});

      var token = 'tokenValue';

      var actual = ewdSession.byToken(token);

      expect(documentStore.DocumentNode).toHaveBeenCalledWith('%zewdSession', ['sessionsByToken', 'tokenValue']);
      expect(sessionSpy).toHaveBeenCalledWith(documentStore, '12345', false, '%zewdSession');
      expect(actual).toBe(sessionInstance);
    });
  });
});
