const configPath = 'video-config.json';
const allowedOrigin = 'https://wholabel.github.io';

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...extra }
  });
}

function cors(origin) {
  return origin === allowedOrigin
    ? { 'access-control-allow-origin': origin, 'access-control-allow-credentials': 'true' }
    : {};
}

function githubToken(request) {
  return request.headers.get('cookie')?.match(/(?:^|; )wl_session=([^;]*)/)?.[1] || null;
}

async function github(request, env, path, init = {}) {
  const token = githubToken(request);
  return fetch(`https://api.github.com${path}`, {
    ...init,
    headers: {
      accept: 'application/vnd.github+json',
      'user-agent': 'Who-Label-Admin',
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...init.headers
    }
  });
}

async function requireAdmin(request, env) {
  const response = await github(request, env, '/user');
  if (!response.ok) return null;
  const user = await response.json();
  return user.login?.toLowerCase() === env.GITHUB_ADMIN_USERNAME.toLowerCase() ? user : null;
}

function base64(bytes) {
  let binary = '';
  for (let index = 0; index < bytes.length; index += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  }
  return btoa(binary);
}

function base64Text(text) {
  return base64(new TextEncoder().encode(text));
}

async function updateFile(request, env, path, content, message, binary = false) {
  const apiPath = `/repos/${env.GITHUB_OWNER}/${env.GITHUB_REPO}/contents/${path}`;
  const existing = await github(request, env, `${apiPath}?ref=${encodeURIComponent(env.GITHUB_BRANCH)}`);
  const current = existing.ok ? await existing.json() : {};
  return github(request, env, apiPath, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      message,
      branch: env.GITHUB_BRANCH,
      content: binary ? base64(new Uint8Array(content)) : base64Text(content),
      ...(current.sha ? { sha: current.sha } : {})
    })
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('origin');

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          ...cors(origin),
          'access-control-allow-methods': 'GET,POST,OPTIONS',
          'access-control-allow-headers': 'content-type'
        }
      });
    }

    if (url.pathname === '/auth/github') {
      const callback = `${url.origin}/auth/github/callback`;
      const params = new URLSearchParams({
        client_id: env.GITHUB_CLIENT_ID,
        redirect_uri: callback,
        scope: 'repo'
      });
      return Response.redirect(`https://github.com/login/oauth/authorize?${params}`, 302);
    }

    if (url.pathname === '/auth/github/callback') {
      const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: { accept: 'application/json', 'content-type': 'application/json' },
        body: JSON.stringify({
          client_id: env.GITHUB_CLIENT_ID,
          client_secret: env.GITHUB_CLIENT_SECRET,
          code: url.searchParams.get('code')
        })
      });
      const token = await tokenResponse.json();
      if (!token.access_token) return new Response('GitHub login failed', { status: 502 });

      const userResponse = await fetch('https://api.github.com/user', {
        headers: {
          authorization: `Bearer ${token.access_token}`,
          accept: 'application/vnd.github+json',
          'user-agent': 'Who-Label-Admin'
        }
      });
      const user = await userResponse.json();
      if (user.login?.toLowerCase() !== env.GITHUB_ADMIN_USERNAME.toLowerCase()) {
        return new Response('Forbidden', { status: 403 });
      }

      return new Response(null, {
        status: 302,
        headers: {
          location: `${allowedOrigin}/wholabelsongchords/admin.html`,
          'set-cookie': `wl_session=${token.access_token}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=28800`
        }
      });
    }

    if (url.pathname === '/api/me') {
      const user = await requireAdmin(request, env);
      return user
        ? json({ login: user.login }, 200, cors(origin))
        : json({ error: 'Unauthorized' }, 401, cors(origin));
    }

    if (url.pathname === '/api/videos' && request.method === 'POST') {
      if (!await requireAdmin(request, env)) {
        return json({ error: 'Unauthorized' }, 401, cors(origin));
      }

      const form = await request.formData();
      const side = form.get('side');
      const file = form.get('video');
      if (!['left', 'right'].includes(side) || !(file instanceof File)) {
        return json({ error: 'Invalid upload' }, 400, cors(origin));
      }
      if (file.size > 100 * 1024 * 1024) {
        return json({ error: 'File exceeds GitHub 100 MB limit' }, 413, cors(origin));
      }

      const safeName = file.name.replace(/[^a-zA-Z0-9._-]/g, '_');
      const videoPath = `video present/${safeName}`;
      const videoResponse = await updateFile(
        request,
        env,
        videoPath,
        await file.arrayBuffer(),
        `admin: upload ${videoPath}`,
        true
      );
      if (!videoResponse.ok) {
        return json({ error: 'GitHub video upload failed' }, 502, cors(origin));
      }

      const configResponse = await github(
        request,
        env,
        `/repos/${env.GITHUB_OWNER}/${env.GITHUB_REPO}/contents/${configPath}?ref=${encodeURIComponent(env.GITHUB_BRANCH)}`
      );
      const configFile = configResponse.ok ? await configResponse.json() : {};
      const config = configFile.content
        ? JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(configFile.content.replace(/\n/g, '')), char => char.charCodeAt(0))))
        : {};
      config[side] = videoPath;

      const savedConfig = await updateFile(
        request,
        env,
        configPath,
        `${JSON.stringify(config, null, 2)}\n`,
        `admin: set ${side} preview video`
      );
      if (!savedConfig.ok) {
        return json({ error: 'GitHub config update failed' }, 502, cors(origin));
      }
      return json({ ok: true }, 200, cors(origin));
    }

    return new Response('Who Label Admin Worker');
  }
};
