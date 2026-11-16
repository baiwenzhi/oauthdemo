/**
 * iframe 无感登录前端逻辑
 *
 * 流程：
 *  1. 点击登录 -> 后端 /auth/embed/start 返回授权 URL（PKCE verifier 已暂存会话）。
 *  2. 弹出 iframe 加载该 URL（IDP 嵌入式登录页；若 IDP 会话已存在则直接静默授权）。
 *  3. IDP 授权后 iframe 内 302 到本应用落地页 /auth/embed-callback，
 *     落地页后台直接完成「校验 state -> 换 token -> 建立会话」，
 *     再通过 postMessage 只向父窗口发送成功/失败信号（不携带授权码）。
 *  4. 父窗口收到成功信号后拉取 /account/fragment 页面片段，原地替换 DOM —— 全程无刷新。
 */
(function () {
  // 落地页（消息发送方）运行在本应用 origin 下，故校验本站 origin；
  // 真正的防伪造由服务端 state 校验保证
  const EXPECTED_ORIGIN = window.location.origin;
  const modal = document.getElementById('embed-modal');
  const frame = document.getElementById('embed-frame');
  const btnLogin = document.getElementById('btn-embed-login');
  const btnClose = document.getElementById('modal-close');
  const btnMask = document.getElementById('modal-mask');

  function openModal() {
    modal.classList.remove('hidden');
    modal.setAttribute('aria-hidden', 'false');
  }
  function closeModal() {
    modal.classList.add('hidden');
    modal.setAttribute('aria-hidden', 'true');
    frame.src = 'about:blank';
  }

  async function startEmbedLogin() {
    btnLogin.disabled = true;
    try {
      const resp = await fetch('/auth/embed/start');
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      const data = await resp.json();
      frame.src = data.authorizeUrl;
      openModal();
    } catch (err) {
      alert('发起授权失败: ' + err.message);
    } finally {
      btnLogin.disabled = false;
    }
  }

  if (btnLogin) btnLogin.addEventListener('click', startEmbedLogin);
  if (btnClose) btnClose.addEventListener('click', closeModal);
  if (btnMask) btnMask.addEventListener('click', closeModal);

  async function refreshAccountArea() {
    // 拉取登录后的页面片段，原地替换顶栏与主内容（无感刷新）
    const fragResp = await fetch('/account/fragment');
    if (!fragResp.ok) throw new Error('获取页面片段失败: HTTP ' + fragResp.status);
    const frag = await fragResp.json();
    document.getElementById('topnav').innerHTML = frag.topnav;
    document.getElementById('main-content').innerHTML = frag.main;
  }

  window.addEventListener('message', (event) => {
    if (event.origin !== EXPECTED_ORIGIN) return;
    if (event.source !== frame.contentWindow) return; // 只接受当前授权弹窗的消息
    const msg = event.data;
    if (!msg || msg.source !== 'mini-idp-embed' || msg.type !== 'authorization_response') return;

    closeModal();
    // 落地页后台已完成换 token 与建会话，这里只处理结果信号
    if (!msg.ok) {
      alert('授权失败: ' + (msg.errorDescription || msg.error));
      return;
    }
    refreshAccountArea().catch((err) => {
      // 极端情况：会话已建立但片段拉取失败，兜底整页刷新
      console.warn('片段替换失败，回退整页刷新', err);
      window.location.reload();
    });
  });
})();
