/*

 ----------------------------------------------------------------------------
 | ewd-session: Session management using ewd-document-store                 |
 |                                                                          |
 | Copyright (c) 2016-20 M/Gateway Developments Ltd,                        |
 | Reigate, Surrey UK.                                                      |
 | All rights reserved.                                                     |
 |                                                                          |
 | http://www.mgateway.com                                                  |
 | Email: rtweed@mgateway.com                                               |
 |                                                                          |
 |                                                                          |
 | Licensed under the Apache License, Version 2.0 (the "License");          |
 | you may not use this file except in compliance with the License.         |
 | You may obtain a copy of the License at                                  |
 |                                                                          |
 |     http://www.apache.org/licenses/LICENSE-2.0                           |
 |                                                                          |
 | Unless required by applicable law or agreed to in writing, software      |
 | distributed under the License is distributed on an "AS IS" BASIS,        |
 | WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. |
 | See the License for the specific language governing permissions and      |
 |  limitations under the License.                                          |
 ----------------------------------------------------------------------------

  9 July 2020

*/

var uuid = require('uuid/v4');
var jwt = require('jwt-simple');
var Session = require('./session');
var Token = require('./token');
var symbolTable = require('./proto/symbolTable');

var DEFAULT_DOCUMENT_NAME = require('./constants').DEFAULT_DOCUMENT_NAME;
var documentName;
var documentStore;

function init(docStore, docName) {
  documentStore = docStore;
  documentName = docName || DEFAULT_DOCUMENT_NAME;
}

function clearExpiredSessions(worker) {
  var docName = documentName || DEFAULT_DOCUMENT_NAME;
  console.log(process.pid + ': Checking for expired sessions in ' + docName);
  var sessGlo = new worker.documentStore.DocumentNode(docName, ['session']);
  sessGlo.lock(10);
  sessGlo.forEachChild(function(id) {
    var session = new Session(worker.documentStore, id, false, docName);
    var ok = session.expired; // deletes expired ones as a side effect of checking their expiration status
    if (ok) console.log('session ' + id + ' deleted');
  });
  var sessionIndex = new worker.documentStore.DocumentNode(docName, ['sessionsByToken']);
  sessionIndex.forEachChild(function(sessionId, node) {
    if (!sessGlo.$(node.value).exists) {
      node.delete();
    }
  });
  sessGlo.unlock();
  console.log('Finished checking sessions');
}

var garbageCollector = function garbageCollector(worker, delay) {

  delay = delay*1000 || 300000; // every 5 minutes
  var garbageCollector;

  worker.on('stop', function() {
    // thanks to Ward De Backer for bug fix here:
    clearInterval(garbageCollector);
    console.log('Session Garbage Collector has stopped');
  });

  garbageCollector = setInterval(function() {
    clearExpiredSessions(worker);
  }, delay);

  console.log('Session Garbage Collector has started in worker ' + process.pid);
};

function create(application, timeout, updateExpiry) {
  var jwtPayload;
  if (typeof application === 'object') {
    timeout = application.timeout;
    updateExpiry = application.updateExpiry;
    jwtPayload = application.jwtPayload;  // if defined, it should contain the payload
    application = application.application;
  }
  timeout = timeout || 3600;
  application = application || 'undefined';
  var session = new Session(documentStore, null, updateExpiry, documentName);
  session.data.delete();
  var token = new Token(documentStore, null, documentName);
  token.sessionId = session.id;
  var now = Math.floor(new Date().getTime()/1000);
  var expiry = now + timeout;

  var jwtToken;
  var jwtSecret;

  if (jwtPayload) {
    jwtPayload.exp = expiry;
    jwtPayload.iat = now;
    jwtPayload.iss = 'qewd:' + application;
    jwtPayload.jti = token.value + '.' + now;
    jwtSecret = uuid();
    jwtToken = jwt.encode(jwtPayload, jwtSecret);
  }

  var params = {
    'ewd-session': {
      token: token.value,
      id: session.id,
      timeout: timeout,
      expiry: expiry,
      application: application,
      authenticated: false
    }
  };

  if (jwtPayload) {
    params['ewd-session'].jwt = {
      secret: jwtSecret,
      token: jwtToken
    };
  }

  session.data.setDocument(params);
  return session;
}

function tokenAuthenticate(token, loggingIn) {
  if (!token) return {
    error: 'Missing authorization header',
    status: {
      code: 403,
      text: 'Forbidden'
    }
  };
  var session = new Token(documentStore, token, documentName).session;
  if (!session.exists) return {
    error: 'Invalid token or session expired',
    status: {
      code: 403,
      text: 'Forbidden'
    }
  };
  if (session.expired) return {
    error: 'Session expired',
    status: {
      code: 403,
      text: 'Forbidden'
    }
  };
  if (loggingIn === 'noCheck') {
    return {session: session};
  }
  if (loggingIn === true) {
    if (session.authenticated) return {
      error: 'User already logged in',
      status: {
      code: 403,
      text: 'Forbidden'
      }
    };
  }
  else {
    if (!session.authenticated) return {
      error: 'User has not logged in',
      status: {
      code: 403,
      text: 'Forbidden'
      }
    };
    session.updateExpiry();
  }
  return {session: session};
}

function authenticateByJWT(jwtToken, loggingIn) {
  var payload;

  try {
    payload = jwt.decode(jwtToken, null, true);
  }
  catch(err) {
    return {
      error: 'Invalid JWT: ' + err,
      status: {
        code: 403,
        text: 'Forbidden'
      }
    };
  }
  if (!payload || !payload.jti || payload.jti === '') {
    return {
      error: 'Missing or empty QEWD token',
      status: {
        code: 403,
        text: 'Forbidden'
      }
    };
  }

  var qewdToken = payload.jti.split('.')[0];
  var status = tokenAuthenticate(qewdToken, loggingIn);
  if (status.error) return status;

  // try re-encoding the JWT and check it's identical

  var secret = status.session.jwtSecret;
  var token = jwt.encode(payload, secret);
  //console.log('** incoming JWT: ' +  jwtToken);
  //console.log('** re-encoded  : ' +  token);

  if (token !== jwtToken) {
    return {
      error: 'Invalid JWT',
      status: {
        code: 403,
        text: 'Forbidden'
      }
    };
  }
  status.payload = payload;
  return status;
}

function httpAuthenticate(httpHeaders, credentials) {
  var cookie = httpHeaders.cookie;
  var authorization = httpHeaders.authorization;

  if (!cookie && !authorization) {
    return {
      error: 'Missing Authorization or Cookie Header',
      status: {
        code: 403,
        text: 'Forbidden'
      }
    };
  }

  credentials = credentials || {};
  if (!credentials.authorization) credentials.authorization = 'QEWD token';
  if (!credentials.cookie) credentials.cookie = 'QEWDTOKEN';

  var token;

  if (authorization) {
    // authorization, if present, over-rides cookie
    token = authorization.split(credentials.authorization + '=')[1];
  }
  else {
    var pieces = cookie.split(';');
    pieces.forEach(function(piece) {
      if (piece.indexOf(credentials.cookie) !== -1) {
        token = piece.split(credentials.cookie + '=')[1];
      }
    });
  }

  if (!token || token === '') {
    return {
      error: 'Missing or Empty QEWD Session Token',
      status: {
        code: 403,
        text: 'Forbidden'
      }
    };
  }

  return tokenAuthenticate(token, 'noCheck');
}

function authenticateRestRequest(req, finished, bearer, loggingIn) {
  var auth = req.headers.authorization;
  if (!auth) {
    finished({error: 'Authorization header missing'});
    return false;
  }
  var token;
  if (bearer === false) {
    token = auth;
  }
  else {
    var pieces = auth.split('Bearer ');
    if (pieces.length !== 2) {
      finished({error: 'Authorization header invalid - expected format: Bearer {{token}}'});
      return false;
    }
    token = pieces[1];
  }
  var status = tokenAuthenticate(token, loggingIn);
  if (status.error) {
    finished(status);
    return false;
  }
  req.session = status.session;
  return true;
}

function getActiveSessions() {
  var sessions = [];
  var sessGlo = new documentStore.DocumentNode(documentName, ['session']);
  sessGlo.forEachChild(function(id) {
    var session = new Session(documentStore, id, false, documentName);
    if (!session.expired) sessions.push(session);
  });
  return sessions;
}

function getSessionByToken(token) {
  if (!token || token === '') return;
  var id = new documentStore.DocumentNode(documentName, ['sessionsByToken', token]).value;
  if (id === '') return;
  var session = new Session(documentStore, id, false, documentName);
  if (session.expired) return;
  return session;
}

module.exports = {
  init: init,
  addTo: init,
  create: create,
  uuid: uuid(),
  symbolTable: symbolTable,
  garbageCollector: garbageCollector,
  authenticate: tokenAuthenticate,
  authenticateByJWT: authenticateByJWT,
  httpAuthenticate: httpAuthenticate,
  authenticateRestRequest: authenticateRestRequest,
  active: getActiveSessions,
  byToken: getSessionByToken
};
