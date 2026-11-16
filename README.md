# Mini IDP 演示项目 —— OAuth 2.0 + PKCE

基于 **Node.js + Express + EJS** 的统一认证中心（IdP），并附带两个使用
**@openid/appauth** 的接入示例：Web 应用（有自身会话）与 Node CLI 进程。

## 目录结构

```
idp-demo/
├── idp/                 # Mini IDP 授权服务（:3000）
│   ├── server.js        # /oauth/authorize、/oauth/token、/oauth/userinfo + 首页/登录
│   ├── views/           # EJS 模板（首页右上角用户信息/登录按钮；登录页含嵌入模式）
│   └── public/          # 样式
├── web-app/             # Web 接入应用（:3001，机密客户端）
│   ├── server.js        # 整页跳转流程 + iframe 无感登录流程（落地页后台直换 token）
│   ├── views/           # 首页、embed-callback 落地页、登录后页面片段
│   └── public/app.js    # iframe 弹窗 + postMessage + 无刷新 DOM 替换
├── cli/                 # Node CLI 授权进程（:3002 回调端口，公共客户端）
│   └── index.js         # 打开浏览器授权 -> 本地回调收 code -> 换 token -> 打印用户信息
├── shared/
│   └── appauth-node.js  # @openid/appauth 的 Node 适配层（NodeCrypto S256 + 授权 URL 构造）
└── package.json
```

## 快速开始

```bash
npm install

# 终端 1：启动 IDP
npm run idp        # http://localhost:3000

# 终端 2：启动 Web 应用
npm run web        # http://localhost:3001

# 终端 3：CLI 授权（会自动打开浏览器）
npm run cli
```

演示账号：`alice / 123456`，`bob / 654321`（内存存储，重启即失效）。

## 已注册客户端

| client_id | 类型 | redirect_uri | 认证方式 |
|-----------|------|--------------|----------|
| `web-app` | 机密客户端 | `http://localhost:3001/auth/callback` | client_secret + PKCE(S256) |
| `cli-app` | 公共客户端 | `http://localhost:3002/callback` | 仅 PKCE(S256) |

## 授权流程（授权码模式 + PKCE）

1. 客户端生成 `code_verifier`，将 `S256(code_verifier)` 作为 `code_challenge`
   发起 `GET /oauth/authorize`（`response_type=code`）。
2. 未登录的用户被引导至 IDP 登录页（账号密码），登录后继续授权。
3. IDP 颁发一次性授权码（5 分钟有效），携带 `code & state` 重定向回客户端。
4. 客户端在后台 `POST /oauth/token` 提交授权码 + `code_verifier`
   （机密客户端额外带 `client_secret`），IDP 校验 S256 哈希后颁发 token。
5. 客户端用 `Bearer access_token` 调 `GET /oauth/userinfo` 获取用户信息。

## 端点一览（IDP :3000）

| 端点 | 说明 |
|------|------|
| `GET /oauth/authorize` | 授权端点，强制 PKCE S256，支持 scope/state |
| `POST /oauth/token` | 令牌端点，支持 `authorization_code` / `refresh_token`，兼容 HTTP Basic 客户端认证 |
| `GET /oauth/userinfo` | 用户信息资源端点（Bearer） |
| `GET /login` `POST /login` | 账号密码登录 |
| `POST /logout` | 退出 IDP 会话 |

## @openid/appauth 在 Node 中的适配要点

- 官方 `DefaultCrypto` 依赖浏览器 `window.crypto.subtle`，Node 下需实现
  `Crypto` 接口（`generateRandom` / `deriveChallenge`）注入给
  `AuthorizationRequest` —— 见 `shared/appauth-node.js` 的 `NodeCrypto`。
- 官方授权 URL 构造绑定浏览器 RedirectBasedHandler，Node 下从
  `request.toJson()` 手动拼接 —— 同见 `buildAuthorizationUrl`。
- HTTP 请求可直接使用包内自带的 `FetchRequestor`（Node 18+ 原生 fetch）。
- 注意：v1.4.0 的发布产物（ESM 缺扩展名）无法直接加载，本项目固定 `@openid/appauth@1.3.1`。

## Web 应用两种接入方式

### 方式 A：整页重定向（传统授权码流程）

点击「跳转登录」→ 302 到 IDP 授权页 → 登录后重定向回 `/auth/callback` →
后台换 token 建立自身会话 → 重定向首页。

### 方式 B：iframe 弹窗无感登录（postMessage）

点击「使用 Mini IDP 登录（无感）」后全程不发生整页跳转：

1. 前端调 `GET /auth/embed/start`，后台生成 PKCE 并暂存 verifier，返回授权 URL
   （`redirect_uri` 指向本应用落地页 `/auth/embed-callback`，附带 `embed=1`）。
2. 前端弹出 iframe 加载授权 URL；IDP 以嵌入模式渲染紧凑登录页。
   若用户在 IDP 已有会话，iframe 内直接静默授权，弹窗一闪而过。
3. IDP 授权后 iframe 内 302 到落地页；**落地页后台一次性完成
   「校验 state → 用授权码换 token → 建立自身会话」**，授权码不经前端 JS 传递。
4. 落地页 `postMessage` 仅向父窗口发送 `{ok, error}` 结果信号（targetOrigin 限定本站，
   父窗口校验 event.origin 与 event.source）。
5. 父窗口收到成功信号后 `GET /account/fragment` 拉取登录后的顶栏与主内容片段，
   原地替换 DOM —— 页面无感刷新。

若 iframe 内登录失败或落地页出错，postMessage 携带错误信息，父窗口 alert 提示。

## 演示说明 / 安全提示

- 所有数据（用户、授权码、令牌、会话）存内存，仅用于演示。
- 授权端点跳过了 consent（用户同意）页面；生产环境必须加。
- 生产环境需替换会话密钥、接入真实用户存储、启用 HTTPS，并考虑
  refresh_token 轮换、CORS、令牌吊销等。
