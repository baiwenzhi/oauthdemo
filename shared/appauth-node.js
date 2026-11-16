/**
 * @openid/appauth 在 Node 环境下的适配层。
 *
 * 1) NodeCrypto —— 官方 DefaultCrypto 依赖浏览器的 window.crypto.subtle，
 *    在 Node 中不可用；这里按 Crypto 接口（generateRandom / deriveChallenge）
 *    用 node:crypto 实现 S256 挑战派生。
 * 2) buildAuthorizationUrl —— 官方授权 URL 构造绑定浏览器 RedirectBasedHandler，
 *    这里从 AuthorizationRequest.toJson() 手动拼接授权端点 URL。
 */
const nodeCrypto = require('crypto');

class NodeCrypto {
  /** 生成随机字符串（PKCE code_verifier / state），字符集与官方实现一致 */
  generateRandom(size) {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const bytes = nodeCrypto.randomBytes(size);
    let out = '';
    for (let i = 0; i < size; i++) out += charset[bytes[i] % charset.length];
    return out;
  }

  /** S256：base64url(SHA-256(code_verifier))，RFC 7636 附录 B */
  async deriveChallenge(code) {
    if (code.length < 43 || code.length > 128) {
      throw new Error(`Invalid code verifier length: ${code.length}`);
    }
    return nodeCrypto.createHash('sha256').update(code, 'ascii').digest('base64url');
  }
}

/**
 * 构造跳转到授权端点的完整 URL。
 * @param {import('@openid/appauth').AuthorizationServiceConfiguration} configuration
 * @param {import('@openid/appauth').AuthorizationRequest} request  需先完成 setupCodeVerifier()
 */
function buildAuthorizationUrl(configuration, request) {
  const url = new URL(configuration.authorizationEndpoint);
  const params = {
    response_type: request.responseType,
    client_id: request.clientId,
    redirect_uri: request.redirectUri,
    scope: request.scope,
    state: request.state,
    ...request.extras, // 包含 code_challenge / code_challenge_method
  };
  for (const [k, v] of Object.entries(params)) {
    if (v != null) url.searchParams.set(k, String(v));
  }
  return url.toString();
}

module.exports = { NodeCrypto, buildAuthorizationUrl };
