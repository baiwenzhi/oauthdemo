/**
 * Mini IDP —— 基于 Node.js + Express + EJS 的 OAuth 2.0 授权服务
 *
 * 支持：
 *  - 授权码模式（Authorization Code）+ PKCE（仅 S256）
 *  - /oauth/authorize  授权端点
 *  - /oauth/token      令牌端点（authorization_code / refresh_token）
 *  - /oauth/userinfo   资源端点（Bearer token）
 *  - 自身首页 + 账号密码登录（右上角展示用户信息）
 *
 * 说明：所有数据（用户、授权码、令牌）均存内存，仅用于演示。
 */
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;
const CODE_TTL = 5 * 60 * 1000;          // 授权码有效期 5 分钟
const ACCESS_TOKEN_TTL = 60 * 60 * 1000; // access_token 有效期 1 小时
const REFRESH_TOKEN_TTL = 7 * 24 * 60 * 60 * 1000;

/* ---------------- 内存数据 ---------------- */
const users = {
  alice: { username: 'alice', password: '123456', name: 'Alice Chen', email: 'alice@example.com' },
  bob:   { username: 'bob',   password: '654321', name: 'Bob Wang',  email: 'bob@example.com' },
};

const clients = {
  'web-app': {
    name: 'Web 演示应用',
    client_id: 'web-app',
    client_secret: 'web-app-secret',                     // 机密客户端
    redirect_uris: [
      'http://localhost:3001/auth/callback',        // 整页重定向流程
      'http://localhost:3001/auth/embed-callback',  // iframe 嵌入流程（落地页 postMessage 通知父窗口）
    ],
    scopes: ['profile'],
    pkce_required: true,
  },
  'cli-app': {
    name: 'Node CLI 应用',
    client_id: 'cli-app',
    client_secret: null,                                 // 公共客户端，仅依赖 PKCE
    redirect_uris: ['http://localhost:3002/callback'],
    scopes: ['profile'],
    pkce_required: true,
  },
};

/** code -> { clientId, redirectUri, scope, codeChallenge, username, expiresAt } */
const authorizationCodes = new Map();
/** access_token -> { username, clientId, scope, expiresAt } */
const accessTokens = new Map();
/** refresh_token -> { username, clientId, scope, expiresAt } */
const refreshTokens = new Map();

/* ---------------- 中间件 ---------------- */
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  name: 'idp.sid',
  secret: 'idp-demo-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax' },
}));
app.use(express.static(path.join(__dirname, 'public')));

const currentUser = (req) => (req.session.user ? users[req.session.user] : null);

function tokenError(res, error, description, status = 400) {
  res.status(status).json({ error, error_description: description });
}

/* ---------------- 页面路由 ---------------- */
app.get('/', (req, res) => {
  res.render('index', { user: currentUser(req), clients: Object.values(clients) });
});

app.get('/login', (req, res) => {
  // embed=1：iframe 嵌入模式，渲染无框架的紧凑登录页
  res.render('login', { user: currentUser(req), error: null, embed: req.query.embed === '1' });
});

app.post('/login', (req, res) => {
  const embed = req.body.embed === '1';
  const { username, password } = req.body;
  const user = users[username];
  if (!user || user.password !== password) {
    return res.status(401).render('login', { user: null, error: '用户名或密码错误', embed });
  }
  req.session.user = user.username;
  const returnTo = req.session.returnTo;
  req.session.returnTo = null;
  res.redirect(returnTo || '/');
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

/* ---------------- OAuth 2.0 授权端点 ---------------- */
app.get('/oauth/authorize', (req, res) => {
  const { response_type, client_id, redirect_uri, scope = 'profile', state = '', code_challenge, code_challenge_method } = req.query;
  const client = clients[client_id];

  if (!client) return res.status(400).send('错误：无效的 client_id');
  if (!redirect_uri || !client.redirect_uris.includes(redirect_uri)) {
    return res.status(400).send('错误：redirect_uri 未在客户端注册列表中');
  }
  if (response_type !== 'code') {
    return res.status(400).send('错误：仅支持 response_type=code（授权码模式）');
  }
  if (client.pkce_required && (!code_challenge || code_challenge_method !== 'S256')) {
    return res.status(400).send('错误：该客户端必须使用 PKCE（code_challenge_method=S256）');
  }

  // 未登录 -> 跳转登录页，登录后回跳继续授权
  if (!currentUser(req)) {
    req.session.returnTo = req.originalUrl; // originalUrl 已包含 embed=1，登录后自动回到嵌入流程
    return res.redirect(req.query.embed === '1' ? '/login?embed=1' : '/login');
  }

  // 简化处理：跳过同意（consent）页面，直接颁发授权码
  const code = crypto.randomBytes(24).toString('base64url');
  authorizationCodes.set(code, {
    clientId: client_id,
    redirectUri: redirect_uri,
    scope,
    codeChallenge: code_challenge || null,
    username: req.session.user,
    expiresAt: Date.now() + CODE_TTL,
  });

  const sep = redirect_uri.includes('?') ? '&' : '?';
  res.redirect(`${redirect_uri}${sep}code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`);
});

/* ---------------- OAuth 2.0 令牌端点 ---------------- */
app.post('/oauth/token', (req, res) => {
  const { grant_type, code, redirect_uri, client_id, code_verifier, refresh_token } = req.body;
  let { client_secret } = req.body;

  // 支持 HTTP Basic 认证携带客户端凭据
  const authHeader = req.headers.authorization;
  if (!client_secret && authHeader && authHeader.startsWith('Basic ')) {
    try {
      const decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
      const idx = decoded.indexOf(':');
      client_secret = decoded.slice(idx + 1);
    } catch { /* ignore */ }
  }

  const client = clients[client_id];
  if (!client) return tokenError(res, 'invalid_client', 'unknown client_id', 401);
  if (client.client_secret && client_secret !== client.client_secret) {
    return tokenError(res, 'invalid_client', 'client_secret 不正确', 401);
  }

  if (grant_type === 'authorization_code') {
    const entry = authorizationCodes.get(code);
    if (!entry) return tokenError(res, 'invalid_grant', '授权码不存在或已被使用');
    authorizationCodes.delete(code); // 授权码一次性使用
    if (entry.expiresAt < Date.now()) return tokenError(res, 'invalid_grant', '授权码已过期');
    if (entry.clientId !== client_id) return tokenError(res, 'invalid_grant', '授权码与 client_id 不匹配');
    if (entry.redirectUri !== redirect_uri) return tokenError(res, 'invalid_grant', 'redirect_uri 不匹配');

    // PKCE 校验：S256(code_verifier) == code_challenge
    if (entry.codeChallenge) {
      if (!code_verifier || code_verifier.length < 43 || code_verifier.length > 128) {
        return tokenError(res, 'invalid_grant', '缺少或非法的 code_verifier');
      }
      const expected = crypto.createHash('sha256').update(code_verifier).digest('base64url');
      if (expected !== entry.codeChallenge) {
        return tokenError(res, 'invalid_grant', 'PKCE 校验失败');
      }
    }

    return res.json(issueTokens(entry.username, client_id, entry.scope));
  }

  if (grant_type === 'refresh_token') {
    const entry = refreshTokens.get(refresh_token);
    if (!entry || entry.expiresAt < Date.now()) {
      refreshTokens.delete(refresh_token);
      return tokenError(res, 'invalid_grant', 'refresh_token 无效或已过期');
    }
    if (entry.clientId !== client_id) return tokenError(res, 'invalid_grant', 'refresh_token 与 client_id 不匹配');
    refreshTokens.delete(refresh_token); // 简化的轮换策略
    return res.json(issueTokens(entry.username, client_id, entry.scope));
  }

  return tokenError(res, 'unsupported_grant_type', '仅支持 authorization_code / refresh_token');
});

function issueTokens(username, clientId, scope) {
  const access_token = crypto.randomBytes(32).toString('base64url');
  const refresh_token = crypto.randomBytes(32).toString('base64url');
  accessTokens.set(access_token, { username, clientId, scope, expiresAt: Date.now() + ACCESS_TOKEN_TTL });
  refreshTokens.set(refresh_token, { username, clientId, scope, expiresAt: Date.now() + REFRESH_TOKEN_TTL });
  return {
    access_token,
    token_type: 'Bearer',
    expires_in: Math.floor(ACCESS_TOKEN_TTL / 1000),
    refresh_token,
    scope,
  };
}

/* ---------------- 资源端点：用户信息 ---------------- */
app.get('/oauth/userinfo', (req, res) => {
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) {
    res.set('WWW-Authenticate', 'Bearer');
    return tokenError(res, 'invalid_token', '缺少 Bearer access_token', 401);
  }
  const token = authHeader.slice(7).trim();
  const entry = accessTokens.get(token);
  if (!entry) return tokenError(res, 'invalid_token', 'access_token 无效', 401);
  if (entry.expiresAt < Date.now()) {
    accessTokens.delete(token);
    return tokenError(res, 'invalid_token', 'access_token 已过期', 401);
  }
  const { password, ...userinfo } = users[entry.username];
  res.json({ sub: userinfo.username, ...userinfo, scope: entry.scope });
});

app.listen(PORT, () => {
  console.log(`\n[Mini IDP] 已启动: http://localhost:${PORT}`);
  console.log(`  授权端点   GET  /oauth/authorize  (PKCE S256)`);
  console.log(`  令牌端点   POST /oauth/token      (authorization_code / refresh_token)`);
  console.log(`  用户信息   GET  /oauth/userinfo   (Bearer)`);
  console.log(`  演示账号   alice/123456  bob/654321\n`);
});
