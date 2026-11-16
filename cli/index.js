/**
 * Node CLI 授权进程 —— 使用 @openid/appauth 对 Mini IDP 进行 OAuth 2.0 + PKCE 授权
 *
 * 流程：
 *  1. 本地启动回调服务器（:3002），生成 PKCE 并构造授权 URL。
 *  2. 自动打开系统浏览器（失败则手动复制链接），用户在 IDP 登录授权。
 *  3. IDP 携带 code 重定向到本地回调服务器，CLI 拿到 code。
 *  4. 用 code + code_verifier（公共客户端，无 client_secret）后台换取 token。
 *  5. 用 access_token 请求 /oauth/userinfo，打印用户信息。
 *
 * 用法：npm run cli   （或 node cli/index.js）
 */
const http = require('http');
const { spawn } = require('child_process');
const {
  AuthorizationServiceConfiguration,
  AuthorizationRequest,
  BaseTokenRequestHandler,
  FetchRequestor,
  TokenRequest,
  GRANT_TYPE_AUTHORIZATION_CODE,
} = require('@openid/appauth');
const { NodeCrypto, buildAuthorizationUrl } = require('../shared/appauth-node');

const IDP_BASE = 'http://localhost:3000';
const CLIENT_ID = 'cli-app';
const REDIRECT_URI = 'http://localhost:3002/callback';
const CALLBACK_PORT = 3002;
const SCOPE = 'profile';

const configuration = new AuthorizationServiceConfiguration({
  authorization_endpoint: `${IDP_BASE}/oauth/authorize`,
  token_endpoint: `${IDP_BASE}/oauth/token`,
  revocation_endpoint: `${IDP_BASE}/oauth/revoke`,
});
const tokenHandler = new BaseTokenRequestHandler(new FetchRequestor());

/** 在本地起一个一次性 HTTP 服务器，等待 IDP 携带授权码重定向回来 */
function waitForAuthorizationCode() {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const url = new URL(req.url, REDIRECT_URI);
      if (url.pathname !== '/callback') {
        res.writeHead(404).end();
        return;
      }
      const error = url.searchParams.get('error');
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');
      const ok = !error && !!code;
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(ok
        ? '<h2>✅ CLI 授权成功</h2><p>授权码已送达 CLI 进程，可以关闭此页面回到终端。</p>'
        : `<h2>❌ 授权失败</h2><p>${error}: ${url.searchParams.get('error_description') || ''}</p>`);
      setTimeout(() => server.close(), 100);
      ok ? resolve({ code, state }) : reject(new Error(`${error}: ${url.searchParams.get('error_description') || ''}`));
    });
    server.on('error', reject);
    server.listen(CALLBACK_PORT, () => console.log(`[CLI] 本地回调服务器已就绪: ${REDIRECT_URI}`));
  });
}

function openBrowser(url) {
  const cmd = process.platform === 'win32' ? 'cmd'
    : process.platform === 'darwin' ? 'open' : 'xdg-open';
  const args = process.platform === 'win32' ? ['/c', 'start', '', url] : [url];
  try { spawn(cmd, args, { detached: true, stdio: 'ignore' }).unref(); } catch { /* 用户手动打开 */ }
}

async function main() {
  console.log('=== Mini IDP Node CLI 授权演示 (@openid/appauth + PKCE) ===\n');

  // 1. 构造授权请求（PKCE S256，公共客户端）
  const request = new AuthorizationRequest(
    { client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, scope: SCOPE, response_type: 'code' },
    new NodeCrypto(),
    true, // usePkce
  );
  await request.setupCodeVerifier();
  const verifier = request.internal['code_verifier'];
  const authUrl = buildAuthorizationUrl(configuration, request);
  console.log('[1] 已生成 PKCE code_verifier / code_challenge，等待用户授权...');

  // 2. 等待回调 + 打开浏览器
  const waiting = waitForAuthorizationCode();
  console.log('\n[2] 请在浏览器中完成登录授权。若未自动打开，请手动访问：\n');
  console.log('    ' + authUrl + '\n');
  if (!process.env.CLI_NO_OPEN) openBrowser(authUrl); // 测试时可设 CLI_NO_OPEN=1 跳过自动打开

  const { code, state } = await waiting;
  if (state !== request.state) throw new Error('state 校验失败');
  console.log(`[3] 收到授权码: ${code.slice(0, 12)}...`);

  // 3. 后台换取 token（公共客户端：只有 PKCE code_verifier，无 client_secret）
  const tokenResponse = await tokenHandler.performTokenRequest(configuration, new TokenRequest({
    grant_type: GRANT_TYPE_AUTHORIZATION_CODE,
    code,
    redirect_uri: REDIRECT_URI,
    client_id: CLIENT_ID,
    extras: { code_verifier: verifier },
  }));
  console.log(`[4] 已换取 access_token: ${tokenResponse.accessToken.slice(0, 18)}...`);
  console.log(`    token_type=${tokenResponse.tokenType}  expires_in=${tokenResponse.expiresIn}s  scope=${tokenResponse.scope}`);

  // 4. 获取用户信息
  const resp = await fetch(`${IDP_BASE}/oauth/userinfo`, {
    headers: { Authorization: `Bearer ${tokenResponse.accessToken}` },
  });
  if (!resp.ok) throw new Error(`获取用户信息失败: HTTP ${resp.status}`);
  const userinfo = await resp.json();

  console.log('\n[5] 用户信息 (/oauth/userinfo)：');
  console.log(JSON.stringify(userinfo, null, 2));
  console.log('\n✅ 授权流程完成。');
}

main().catch((err) => {
  console.error('\n❌ 授权失败:', err.message || err);
  process.exit(1);
});
