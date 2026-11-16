/**
 * Web 演示应用 —— 接入 Mini IDP 的机密客户端（@openid/appauth）
 *
 * 流程：
 *  1. GET /auth/login 用 @openid/appauth 构造授权请求（PKCE S256），
 *     code_verifier 暂存自身 session，302 跳转 IDP 授权页。
 *  2. 用户在 IDP 登录并授权后，IDP 302 回 GET /auth/callback?code=...&state=...。
 *  3. 回调页在【后台】用授权码 + code_verifier + client_secret 换取 token，
 *     再调 /oauth/userinfo 拉取用户信息，写入自身 session。
 *  4. GET / 展示账号信息。
 */
const path = require('path');
const express = require('express');
const session = require('express-session');
const {
  AuthorizationServiceConfiguration,
  AuthorizationRequest,
  BaseTokenRequestHandler,
  FetchRequestor,
  TokenRequest,
  GRANT_TYPE_AUTHORIZATION_CODE,
  GRANT_TYPE_REFRESH_TOKEN,
} = require('@openid/appauth');
const { NodeCrypto, buildAuthorizationUrl } = require('../shared/appauth-node');

const PORT = 3001;
const WEB_ORIGIN = `http://localhost:${PORT}`;
const IDP_BASE = 'http://localhost:3000';
const CLIENT_ID = 'web-app';
const CLIENT_SECRET = 'web-app-secret';
const REDIRECT_URI = `${WEB_ORIGIN}/auth/callback`;            // 整页重定向流程
const EMBED_REDIRECT_URI = `${WEB_ORIGIN}/auth/embed-callback`; // iframe 流程落地页
const SCOPE = 'profile';

const configuration = new AuthorizationServiceConfiguration({
  authorization_endpoint: `${IDP_BASE}/oauth/authorize`,
  token_endpoint: `${IDP_BASE}/oauth/token`,
  revocation_endpoint: `${IDP_BASE}/oauth/revoke`,
});
const tokenHandler = new BaseTokenRequestHandler(new FetchRequestor());

const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(session({
  name: 'webapp.sid',
  secret: 'web-app-demo-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax' },
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

/* ---------- 公共：换取 token / 拉取用户信息 ---------- */
async function exchangeCodeForTokens(code, verifier, redirectUri) {
  // 后台用授权码换取 token（机密客户端：带 client_secret；同时带 PKCE code_verifier）
  return tokenHandler.performTokenRequest(configuration, new TokenRequest({
    grant_type: GRANT_TYPE_AUTHORIZATION_CODE,
    code,
    redirect_uri: redirectUri,
    client_id: CLIENT_ID,
    extras: {
      code_verifier: verifier,
      client_secret: CLIENT_SECRET,
    },
  }));
}

async function fetchUserinfo(accessToken) {
  const uiResp = await fetch(`${IDP_BASE}/oauth/userinfo`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!uiResp.ok) throw new Error(`userinfo HTTP ${uiResp.status}`);
  return uiResp.json();
}

/** 建立自身会话 */
function saveSession(req, tokens, userinfo) {
  req.session.tokens = tokens;
  req.session.userinfo = userinfo;
  req.session.expiresAt = Date.now() + tokens.expiresIn * 1000;
}

/* ---------- 首页：展示账号信息 ---------- */
app.get('/', async (req, res) => {
  const s = req.session;
  if (s.userinfo && s.tokens) {
    // access_token 过期则用 refresh_token 续期（简化演示）
    if (Date.now() >= s.expiresAt) {
      try {
        const refreshed = await tokenHandler.performTokenRequest(configuration, new TokenRequest({
          grant_type: GRANT_TYPE_REFRESH_TOKEN,
          refresh_token: s.tokens.refreshToken,
          redirect_uri: REDIRECT_URI,
          client_id: CLIENT_ID,
          extras: { client_secret: CLIENT_SECRET },
        }));
        s.tokens = refreshed;
        s.expiresAt = Date.now() + refreshed.expiresIn * 1000;
      } catch {
        s.userinfo = null; s.tokens = null; // 续期失败，要求重新登录
        return res.render('index', { user: null, tokens: null, expiresAt: 0 });
      }
    }
    // 用 access_token 拉取最新用户信息
    try {
      const resp = await fetch(`${IDP_BASE}/oauth/userinfo`, {
        headers: { Authorization: `Bearer ${s.tokens.accessToken}` },
      });
      if (!resp.ok) throw new Error(`userinfo HTTP ${resp.status}`);
      s.userinfo = await resp.json();
    } catch {
      s.userinfo = null; s.tokens = null;
      return res.render('index', { user: null, tokens: null, expiresAt: 0 });
    }
  }
  res.render('index', { user: s.userinfo, tokens: s.tokens, expiresAt: s.expiresAt });
});

/* ---------- 发起授权：整页重定向流程（PKCE S256） ---------- */
app.get('/auth/login', async (req, res) => {
  const request = new AuthorizationRequest(
    { client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, scope: SCOPE, response_type: 'code' },
    new NodeCrypto(),
    true, // usePkce
  );
  await request.setupCodeVerifier(); // 生成 code_verifier 并派生 S256 code_challenge
  req.session.oauth = {
    state: request.state,
    verifier: request.internal['code_verifier'],
    redirectUri: REDIRECT_URI,
  };
  res.redirect(buildAuthorizationUrl(configuration, request));
});

/* ---------- 授权回调：后台换 token，建立自身会话 ---------- */
app.get('/auth/callback', async (req, res) => {
  const pending = req.session.oauth;
  if (!pending) return res.status(400).send('会话中没有待处理的授权请求，请从首页重新登录');

  if (req.query.error) {
    req.session.oauth = null;
    return res.status(400).send(`授权失败: ${req.query.error} - ${req.query.error_description || ''}`);
  }
  if (req.query.state !== pending.state) {
    req.session.oauth = null;
    return res.status(400).send('state 校验失败，可能存在 CSRF 风险');
  }
  req.session.oauth = null;

  try {
    const tokenResponse = await exchangeCodeForTokens(req.query.code, pending.verifier, pending.redirectUri);
    const userinfo = await fetchUserinfo(tokenResponse.accessToken);
    saveSession(req, tokenResponse, userinfo);
    res.redirect('/');
  } catch (err) {
    res.status(500).send(`换取 token 失败: ${err.message || err}`);
  }
});

/* ================= iframe 嵌入登录流程（postMessage，页面无感刷新） ================= */

/** 前端发起：生成 iframe 加载用的授权 URL（JSON 返回，不整页跳转） */
app.get('/auth/embed/start', async (req, res) => {
  const request = new AuthorizationRequest(
    {
      client_id: CLIENT_ID,
      redirect_uri: EMBED_REDIRECT_URI,
      scope: SCOPE,
      response_type: 'code',
      extras: { embed: '1' }, // 通知 IDP 使用嵌入模式登录页
    },
    new NodeCrypto(),
    true,
  );
  await request.setupCodeVerifier();
  req.session.oauth = {
    state: request.state,
    verifier: request.internal['code_verifier'],
    redirectUri: EMBED_REDIRECT_URI,
  };
  res.json({ authorizeUrl: buildAuthorizationUrl(configuration, request) });
});

/**
 * iframe 落地页：web 应用自己的页面。
 * 后台在此一次性完成「校验 state -> 换取 token -> 建立自身会话」，
 * 页面仅负责 postMessage 通知父窗口刷新；授权码不经前端 JS / postMessage 传递。
 */
app.get('/auth/embed-callback', async (req, res) => {
  const pending = req.session.oauth;
  const fail = (error, errorDescription) => {
    req.session.oauth = null;
    res.status(400).render('embed-callback', {
      ok: false,
      error,
      errorDescription,
      parentOrigin: WEB_ORIGIN,
    });
  };

  if (!pending) return fail('no_pending', '会话中没有待处理的授权请求');
  if (req.query.error) return fail(req.query.error, req.query.error_description || '');
  if (req.query.state !== pending.state) return fail('state_mismatch', 'state 校验失败');
  req.session.oauth = null; // 授权码一次性：无论成败，消费掉 pending 状态

  try {
    // 后台直接换 token（PKCE code_verifier + client_secret）并建立会话
    const tokens = await exchangeCodeForTokens(req.query.code, pending.verifier, pending.redirectUri);
    const userinfo = await fetchUserinfo(tokens.accessToken);
    saveSession(req, tokens, userinfo);
    res.render('embed-callback', {
      ok: true,
      error: null,
      errorDescription: null,
      parentOrigin: WEB_ORIGIN,
    });
  } catch (err) {
    fail('exchange_failed', err.message || String(err));
  }
});

/** 登录成功后的页面片段：供前端无刷新替换顶栏与主内容 */
app.get('/account/fragment', (req, res) => {
  const { userinfo, tokens, expiresAt } = req.session;
  if (!userinfo || !tokens) {
    return res.status(401).json({ ok: false, error: 'unauthenticated' });
  }
  const render = (view, locals) => new Promise((resolve, reject) =>
    app.render(view, locals, (err, html) => (err ? reject(err) : resolve(html))));
  Promise.all([
    render('partials/topnav-auth', { user: userinfo }),
    render('partials/account', { user: userinfo, tokens, expiresAt }),
  ]).then(([topnav, main]) => res.json({ ok: true, topnav, main }))
    .catch((err) => res.status(500).json({ ok: false, error: 'render_failed', message: err.message }));
});

/* ---------- 本地登出（仅清除自身会话） ---------- */
app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

app.listen(PORT, () => {
  console.log(`\n[Web 演示应用] 已启动: http://localhost:${PORT}`);
  console.log(`  client_id: ${CLIENT_ID}（机密客户端，后台用 client_secret + PKCE 换 token）`);
  console.log(`  点击首页"使用 Mini IDP 登录"开始授权流程\n`);
});
