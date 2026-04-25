// We'll update the imports and add state handling
import React, { useState } from "react";
import { Copy, Check, Terminal, FileCode, CheckCircle2, Rocket, ExternalLink, Loader2, AlertCircle } from "lucide-react";
import { motion } from "motion/react";

// (Worker Code blocks omitted here for brevity, they match existing logic)

const WORKER_CODE = `import { connect } from 'cloudflare:sockets';
/**
 * Cloudflare Worker - ProxyIP Scanner, Filter & Dashboard
 * Features: Auth, Settings (Domains/Password), DO Support, Latency Testing.
 */

const CF_IP_RANGES = [
  "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
  "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
  "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
  "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
];

function isCloudflareIP(ip) {
  const ipNum = ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0;
  for (const range of CF_IP_RANGES) {
    const [network, mask] = range.split('/');
    const netNum = network.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0;
    const maskNum = (0xffffffff << (32 - parseInt(mask))) >>> 0;
    if ((ipNum & maskNum) === (netNum & maskNum)) return true;
  }
  return false;
}

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(this.updateIPs(env));
  },

  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const cookie = request.headers.get('Cookie') || '';
    
    // Auth Check
    const settings = await this.getSettings(env);
    const token = cookie.split('; ').find(row => row.startsWith('auth='))?.split('=')[1];
    const isAuthenticated = token === settings.password;

    // Login API
    if (url.pathname === '/api/login' && request.method === 'POST') {
      const { password } = await request.json();
      if (password === settings.password) {
        return new Response(JSON.stringify({ success: true }), {
          headers: { 
            'Content-Type': 'application/json',
            'Set-Cookie': \`auth=\${password}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000\` 
          }
        });
      }
      return new Response(JSON.stringify({ error: '密码错误' }), { status: 401 });
    }

    // Public Routes end here
    if (!isAuthenticated) {
      if (url.pathname.startsWith('/api/')) return new Response('Unauthorized', { status: 401 });
      return new Response(this.getLoginHTML(), { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
    }

    // Authenticated API Routes
    if (url.pathname === '/api/ips') {
      const data = await env.PROXY_IP_KV.get('latest_ips_json');
      return new Response(data || '[]', { 
        headers: { 
          'Content-Type': 'application/json',
          'Cache-Control': 'no-cache, no-store, must-revalidate'
        } 
      });
    }

    if (url.pathname === '/api/settings' && request.method === 'GET') {
      return new Response(JSON.stringify(settings), { headers: { 'Content-Type': 'application/json' } });
    }

    if (url.pathname === '/api/settings' && request.method === 'POST') {
      const newSettings = await request.json();
      await env.PROXY_IP_KV.put('app_settings', JSON.stringify({ ...settings, ...newSettings }));
      return new Response(JSON.stringify({ success: true }));
    }

    if (url.pathname === '/api/update') {
      await env.PROXY_IP_KV.put('update_progress', JSON.stringify({ status: 'starting' }));
      ctx.waitUntil(this.updateIPs(env));
      return new Response(JSON.stringify({ success: true }));
    }

    if (url.pathname === '/api/progress') {
      const data = await env.PROXY_IP_KV.get('update_progress');
      return new Response(data || '{"status":"idle"}', { 
        headers: { 
          'Content-Type': 'application/json',
          'Cache-Control': 'no-cache, no-store, must-revalidate'
        } 
      });
    }

    if (url.pathname === '/api/logout') {
      return new Response(JSON.stringify({ success: true }), {
        headers: { 'Set-Cookie': 'auth=; Path=/; Max-Age=0' }
      });
    }

    // Dashboard
    return new Response(this.getDashboardHTML(), { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
  },

  async getSettings(env) {
    const raw = await env.PROXY_IP_KV.get('app_settings');
    const defaults = {
      password: 'admin',
      domains: [
        'sig.proxyip.cmliussss.net', 'sg.proxyip.cmliussss.net', 'jp.proxyip.cmliussss.net',
        'proxyip.jp.cmliussss.net', 'proxyip.sg.cmliussss.net', 'jp.cmliussss.net'
      ]
    };
    return raw ? JSON.parse(raw) : defaults;
  },

  async updateIPs(env) {
    const settings = await this.getSettings(env);
    const domains = settings.domains;

    const progress = {
      status: 'dns', // 'starting', 'dns', 'test', 'completed'
      domainTotal: domains.length,
      dnsRequests: 0,
      dnsResolved: 0,
      ipTotal: 0,
      ipTested: 0,
      ipValid: 0,
    };
    let lastWriteTime = 0;
    const saveProgress = async (force = false) => {
      const now = Date.now();
      if (!force && now - lastWriteTime < 1000) return;
      lastWriteTime = now;
      try {
        await env.PROXY_IP_KV.put('update_progress', JSON.stringify(progress));
      } catch(e) {}
    };
    await saveProgress(true);

    // Helper for concurrency control
    const pool = async (items, task, limit = 10) => {
      const results = [];
      const executing = [];
      for (const item of items) {
        const p = task(item).then(res => {
          executing.splice(executing.indexOf(p), 1);
          return res;
        });
        executing.push(p);
        results.push(p);
        if (executing.length >= limit) await Promise.race(executing);
      }
      return Promise.all(results);
    };

    // 1. Parallel DNS Resolution (15 threads)
    let ipMap = new Map(); // ip -> isProxy
    
    // Multiple DoH endpoints and EDNS subnets (to discover IPs from different regions)
    const dnsRequests = [];
    const DoH = [
      'https://dns.google/resolve',
      'https://cloudflare-dns.com/dns-query',
      'https://doh.pub/dns-query',
      'https://dns.alidns.com/resolve',
      'https://1.1.1.1/dns-query'
    ];
    const subnets = ['', '1.1.1.0/24', '8.8.8.0/24', '114.114.114.0/24', '168.126.63.0/24', '202.14.67.0/24'];
    
    for (const domain of domains) {
      if (!domain.trim()) continue;
      const isProxyDomain = domain.toLowerCase().includes('proxyip') || domain.toLowerCase().includes('cmliussss');
      for (const endpoint of DoH) {
        const isGoogle = endpoint.includes('dns.google');
        for (const subnet of subnets) {
          if (subnet && !isGoogle) continue; 
          const url = isGoogle 
            ? \`\${endpoint}?name=\${domain.trim()}&type=A&edns_client_subnet=\${subnet}\`
            : \`\${endpoint}?name=\${domain.trim()}&type=A\`;
          
          dnsRequests.push({ url, isProxyDomain });
        }
        // Random padding for google
        if (isGoogle) {
          dnsRequests.push({ url: \`\${endpoint}?name=\${domain.trim()}&type=A&random_padding=\${Math.random()}\`, isProxyDomain });
        }
      }
    }

    progress.dnsRequests = dnsRequests.length;
    await saveProgress(true);

    await pool(dnsRequests, async (req) => {
      try {
        const res = await fetch(req.url, { headers: { 'Accept': 'application/dns-json' }, signal: AbortSignal.timeout(5000) });
        const data = await res.json();
        if (data.Answer) {
          data.Answer.forEach(r => {
            if (r.type === 1) { // A record
              const current = ipMap.get(r.data) || false;
              ipMap.set(r.data, current || req.isProxyDomain);
            }
          });
        }
      } catch (e) {}
      progress.dnsResolved++;
      saveProgress();
    }, 20);

    const ipArray = Array.from(ipMap.keys());
    progress.ipTotal = ipArray.length;
    progress.status = 'test';
    await saveProgress(true);
    
    const batchResults = [];
    
    // 2. Parallel ISP & Latency Testing (GeoJS + CF Trace)
    // Run all IPs through the pool with concurrency 20
    const chunkResults = await pool(ipArray, async (ip) => {
        const updateProgress = (res) => {
          progress.ipTested++;
          if (res) progress.ipValid++;
          saveProgress();
          return res;
        };

        const start = Date.now();
        let latency = -1;
        let isValid = false;
        let socket = null;
        try {
          socket = connect({ hostname: ip, port: 443 });
          
          await Promise.race([
            socket.opened.catch(() => null),
            new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 3000))
          ]);
          
          const writer = socket.writable.getWriter();
          const reader = socket.readable.getReader();
          
          // TLS Client Hello (matches cfcpi)
          const hexStr = '16030107a30100079f0303af1f4d78be2002cf63e8c727224cf1ee4a8ac89a0ad04bc54cbed5cd7c830880203d8326ae1d1d076ec749df65de6d21dec7371c589056c0a548e31624e121001e0020baba130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010007361a1a0000000a000c000acaca11ec001d00170018fe0d00ba0000010001fc00206a2fb0535a0a5e565c8a61dcb381bab5636f1502bbd09fe491c66a2d175095370090dd4d770fc5e14f4a0e13cfd919a532d04c62eb4a53f67b1375bf237538cea180470d942bdde74611afe80d70ad25afb1d5f02b2b4eed784bc2420c759a742885f6ca982b25d0fdd7d8f618b7f7bc10172f61d446d8f8a6766f3587abbae805b8ef40fcb819194ac49e91c6c3762775f8dc269b82a21ddccc9f6f43be62323147b411475e47ea2c4efe52ef2cef5c7b32000d00120010040308040401050308050501080606010010000e000c02683208687474702f312e31000b0002010000050005010000000044cd00050003026832001b00030200020017000000230000002d000201010012000000000010000e00000b636861746770742e636f6dff01000100002b0007061a1a03040303003304ef04edcaca00010011ec04c05eac5510812e46c13826d28279b13ce62b6464e01ae1bb6d49640e57fb3191c656c4b0167c246930699d4f467c19d60dacaa86933a49e5c97390c3249db33c1aa59f47205701419461569cb01a22b4378f5f3bb21d952700f250a6156841f2cc952c75517a481112653400913f9ab58982a3f2d0010aba5ae99a2d69f6617a4220cd616de58ccbf5d10c5c68150152b60e2797521573b10413cb7a3aab25409d426a5b64a9f3134e01dc0dd0fc1a650c7aafec00ca4b4dddb64c402252c1c69ca347bb7e49b52b214a7768657a808419173bcbea8aa5a8721f17c82bc6636189b9ee7921faa76103695a638585fe678bcbb8725831900f808863a74c52a1b2caf61f1dec4a9016261c96720c221f45546ce0e93af3276dd090572db778a865a07189ae4f1a64c6dbaa25a5b71316025bd13a6012994257929d199a7d90a59285c75bd4727a8c93484465d62379cd110170073aad2a3fd947087634574315c09a7ccb60c301d59a7c37a330253a994a6857b8556ce0ac3cda4c6fe3855502f344c0c8160313a3732bce289b6bda207301e7b318277331578f370ccbcd3730890b552373afeb162c0cb59790f79559123b2d437308061608a704626233d9f73d18826e27f1c00157b792460eda9b35d48b4515a17c6125bdb96b114503c99e7043b112a398888318b956a012797c8a039a51147b8a58071793c14a3611fb0424e865f48a61cac7c43088c634161cea089921d229e1a370effc5eff2215197541394854a201a6ebf74942226573bb95710454bd27a52d444690837d04611b676269873c50c3406a79077e6606478a841f96f7b076a2230fd34f3eea301b77bf00750c28357a9df5b04f192b9c0bbf4f71891f1842482856b021280143ae74356c5e6a8e3273893086a90daa7a92426d8c370a45e3906994b8fa7a57d66b503745521e40948e83641de2a751b4a836da54f2da413074c3d856c954250b5c8332f1761e616437e527c0840bc57d522529b9259ccac34d7a3888f0aade0a66c392458cc1a698443052413217d29fbb9a1124797638d76100f82807934d58f30fcff33197fc171cfa3b0daa7f729591b1d7389ad476fde2328af74effd946265b3b81fa33066923db476f71babac30b590e05a7ba2b22f86925abca7ef8058c2481278dd9a240c8816bba6b5e6603e30670dffa7e6e3b995b0b18ec404614198a43a07897d84b439878d179c7d6895ac3f42ecb7998d4491060d2b8a5316110830c3f20a3d9a488a85976545917124c1eb6eb7314ea9696712b7bcab1cfd2b66e5a85106b2f651ab4b8a145e18ac41f39a394da9f327c5c92d4a297a0c94d1b8dcc3b111a700ac8d81c45f983ca029fd2887ad4113c7a23badf807c6d0068b4fa7148402aae15cc55971b57669a4840a22301caaec392a6ea6d46dab63890594d41545ebc2267297e3f4146073814bb3239b3e566684293b9732894193e71f3b388228641bb8be6f5847abb9072d269cb40b353b6aa3259ccb7e438d6a37ffa8cc1b7e4911575c41501321769900d19792aa3cfbe58b0aaf91c91d3b63900697279ad6c1aa44897a07d937e0d5826c24439420ca5d8a63630655ce9161e58d286fc885fcd9b19d096080225d16c89939a24aa1e98632d497b5604073b13f65bdfddc1de4b40d2a829b0521010c5f0f241b1ccc759049579db79983434fac2748829b33f001d0020a8e86c9d3958e0257c867e59c8082238a1ea0a9f2cac9e41f9b3cb0294f34b484a4a000100002900eb00c600c0afc8dade37ae62fa550c8aa50660d8e73585636748040b8e01d67161878276b1ec1ee2aff7614889bb6a36d2bdf9ca097ff6d7bf05c4de1d65c2b8db641f1c8dfbd59c9f7e0fed0b8e0394567eda55173d198e9ca40883b291ab4cada1a91ca8306ca1c37e047ebfe12b95164219b06a24711c2182f5e37374d43c668d45a3ca05eda90e90e510e628b4cfa7ae880502dae9a70a8eced26ad4b3c2f05d77f136cfaa622e40eb084dd3eb52e23a9aeff6ae9018100af38acfd1f6ce5d8c53c4a61c547258002120fe93e5c7a5c9c1a04bf06858c4dd52b01875844e15582dd566d03f41133183a0';
          const arr = new Uint8Array(hexStr.length / 2);
          for (let i = 0; i < hexStr.length; i += 2) arr[i / 2] = parseInt(hexStr.substring(i, i + 2), 16);
          writer.write(arr).catch(() => null); // Do not await to prevent stalling, catch to prevent unhandled rejection
          
          const res = await Promise.race([
            reader.read().catch(() => null),
            new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 3000))
          ]);
          
          if (res && res.value && res.value[0] === 0x16) {
             latency = Date.now() - start;
             isValid = true;
          }
        } catch (e) {
        } finally {
          try { if (socket) socket.close(); } catch(e) {}
        }

        
        if (!isValid) return updateProgress(null);

        let info = null;
        try {
          const infoRes = await fetch(\`https://get.geojs.io/v1/ip/geo/\${ip}.json\`, { signal: AbortSignal.timeout(3000) });
          if (infoRes.ok) info = await infoRes.json();
          else {
            const fbRes = await fetch(\`http://ip-api.com/json/\${ip}\`, { signal: AbortSignal.timeout(3000) });
            if (fbRes.ok) info = await fbRes.json();
          }
        } catch (e) {
          try {
            const fbRes = await fetch(\`http://ip-api.com/json/\${ip}\`, { signal: AbortSignal.timeout(3000) });
            if (fbRes.ok) info = await fbRes.json();
          } catch(e2) {}
        }

        if (!info) {
          info = { country_code: '未知', organization: '', organization_name: '' };        const org = (info.organization_name || info.as || info.asn || '').toLowerCase();
        const isp = (info.organization || info.isp || '').toLowerCase();
        const combined = `${org} ${isp}`;
        let provider = '未知服务商';
        const isProxy = ipMap.get(ip) || false;
        
        const mapping = { 
          'HK': '香港', 'SG': '新加坡', 'JP': '日本', 'US': '美国', 'NL': '荷兰', 'DE': '德国', 
          'MY': '马来西亚', 'KR': '韩国', 'TW': '台湾', 'GB': '英国', 'FR': '法国', 'CA': '加拿大', 
          'IN': '印度', 'AU': '澳大利亚', 'TH': '泰国', 'PH': '菲律宾', 'VN': '越南', 'ID': '印尼',
          'BR': '巴西', 'RU': '俄罗斯', 'IT': '意大利', 'ES': '西班牙', 'AE': '阿联酋', 'TR': '土耳其',
          'MO': '澳门', 'CH': '瑞士', 'SE': '瑞典', 'NO': '挪威', 'FI': '�        // --- 核心厂商筛选逻辑 ---
        if (combined.includes('alibaba') || combined.includes('alipay') || combined.includes('as37963') || combined.includes('as45102')) provider = '阿里云';
        else if (combined.includes('tencent') || combined.includes('as132203')) provider = '腾讯云';
        else if (combined.includes('huawei') || combined.includes('as136907')) provider = '华为云';
        else if (combined.includes('amazon') || combined.includes('aws') || combined.includes('as16509') || combined.includes('as14618')) provider = 'AWS';
        else if (combined.includes('google') || combined.includes('gcp') || combined.includes('as15169')) provider = '谷歌云';
        else if (combined.includes('oracle') || combined.includes('as31898')) provider = 'Oracle';
        else if (combined.includes('linode') || combined.includes('akamai') || combined.includes('as15830')) provider = 'Linode/Akamai';
        else if (combined.includes('digitalocean') || combined.includes('as14061')) provider = 'DigitalOcean';
        else if (combined.includes('microsoft') || combined.includes('azure') || combined.includes('as8075')) provider = 'Azure';
        else if (combined.includes('vultr') || combined.includes('choopa') || combined.includes('as20473')) provider = 'Vultr';

        // --- 严格过滤：非知名厂商 IP 直接丢弃 ---
        if (provider === '未知服务商') return updateProgress(null);

        // --- 反代有效性检测 & 归属地修正 ---
        let proxyValid = false;
        try {
          const trace = await fetch(`http://${ip}/cdn-cgi/trace`, { 
             headers: { 'Host': 'www.cloudflare.com' },
             signal: AbortSignal.timeout(1500) 
          }).then(r => r.text());
          
          if (trace.includes('colo=')) {
            proxyValid = true;
            const coloMatch = trace.match(/colo=([A-Z]{3})/);
            if (coloMatch) {
              const coloMap = {
                'HKG': '香港', 'SIN': '新加坡', 'NRT': '日本', 'HND': '日本', 'KIX': '日本',
                'SJC': '美国', 'LAX': '美国', 'SEA': '美国', 'EWR': '美国', 'FRA': '德国',
                'LHR': '英国', 'ICN': '韩国', 'TPE': '台湾', 'BKK': '泰国', 'MNL': '菲律宾',
                'KUL': '马来西亚', 'SNA': '美国', 'ORD': '美国', 'DFW': '美国', 'IAD': '美国',
                'AMS': '荷兰', 'CDG': '法国', 'SYD': '澳大利亚', 'MEL': '澳大利亚', 'BOM': '印度', 'DEL': '印度'
              };
              if (coloMap[coloMatch[1]]) countryName = coloMap[coloMatch[1]];
            }
          }
        } catch(e) {}

        // 如果开启了严格的反代验证，则丢弃失败的节点。这里为了稳定性暂时保留厂商节点，但在 UI 标记。
        return updateProgress({ 
          ip, 
          country: countryName, 
          provider: provider + (proxyValid ? "" : " (无效反代)"), 
          latency, 
          isProxy: proxyValid, 
          updateAt: new Date().toISOString() 
        });
      }, 15);

      batchResults.push(...chunkResults.filter(r => r !== null));��利亚', 'BOM': '印度', 'DEL': '印度'
               };
               if (coloMap[colo]) countryName = coloMap[colo];
             }
           } catch(e) {}
        }

        return updateProgress({ 
          ip, 
          country: countryName, 
          provider, 
          latency, 
          isProxy, 
          updateAt: new Date().toISOString() 
        });
      }, 15);

      batchResults.push(...chunkResults.filter(r => r !== null));

    // IP Cleaning: Deduplicate
    const uniqueMap = new Map();
    batchResults.forEach(item => {
      uniqueMap.set(item.ip, item);
    });

    const finalResults = Array.from(uniqueMap.values())
      .filter(r => r.latency < 380) // 丢弃延迟大于 380ms 的
      .sort((a, b) => a.latency - b.latency) // 按延迟从小到大排序
      .slice(0, 30); // 仅保留前 30 个

    progress.status = 'saving';
    await saveProgress(true);

    await env.PROXY_IP_KV.put('latest_ips_json', JSON.stringify(finalResults));

    progress.status = 'completed';
    await saveProgress(true);
  },

  getLoginHTML() {
    return \`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Login</title><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-gray-950 flex items-center justify-center min-h-screen text-white font-sans">
      <div class="bg-gray-900 p-8 rounded-2xl border border-gray-800 shadow-2xl w-full max-w-md">
        <h1 class="text-2xl font-bold mb-6 text-center text-orange-500">开心指南 登录</h1>
        <input type="password" id="pw" class="w-full bg-gray-800 border-none rounded-lg p-3 mb-4 outline-none focus:ring-2 focus:ring-orange-500" placeholder="请输入密码">
        <button onclick="login()" class="w-full bg-orange-500 py-3 rounded-lg font-bold hover:bg-orange-600 transition">进入控制台</button>
        <p id="err" class="text-red-400 text-xs mt-3 text-center"></p>
      </div>
      <script>
        async function login() {
          const res = await fetch('/api/login', { method: 'POST', body: JSON.stringify({ password: pw.value }) });
          if(res.ok) location.reload();
          else err.innerText = '密码验证失败';
        }
      </script>
    </body></html>\`;
  },

  getDashboardHTML() {
    return \`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>开心指南</title><script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap'); 
        body { font-family: 'Inter', sans-serif; }
        select option { background-color: #111827; color: white; }
    </style></head>
    <body class="bg-gray-950 text-gray-100 min-h-screen">
      <div class="max-w-6xl mx-auto p-4 md:p-8">
        <header class="flex justify-between items-center mb-10">
          <div><h1 class="text-3xl font-bold text-orange-500">开心指南</h1><p class="text-gray-400 text-xs mt-1 underline decoration-gray-700 underline-offset-4">智能云厂商节点监控系统</p></div>
          <div class="flex gap-3">
             <button onclick="showSettings()" class="bg-gray-800 hover:bg-gray-700 px-4 py-2 rounded-lg text-sm border border-gray-700 transition">⚙️ 设置</button>
             <button onclick="logout()" class="bg-red-500/10 hover:bg-red-500/20 text-red-400 px-4 py-2 rounded-lg text-sm border border-red-500/30 transition">退出</button>
          </div>
        </header>

        <div id="settingsBox" class="hidden fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
          <div class="bg-gray-900 border border-gray-800 p-6 rounded-2xl w-full max-w-lg shadow-2xl">
            <h2 class="text-xl font-bold mb-6 text-white border-b border-gray-800 pb-2">系统设置</h2>
            <div class="mb-4 text-sm"><label class="text-gray-400 block mb-1">扫描域名 (每行一个)</label>
            <textarea id="domainList" class="w-full bg-gray-800 h-32 rounded-lg p-2 outline-none focus:ring-1 focus:ring-orange-500"></textarea></div>
            <div class="mb-6 text-sm"><label class="text-gray-400 block mb-1">管理密码</label>
            <input type="password" id="newPw" class="w-full bg-gray-800 rounded-lg p-2 outline-none focus:ring-1 focus:ring-orange-500" placeholder="保持原密码请留空"></div>
            <div class="flex gap-2"><button onclick="saveSettings()" class="flex-1 bg-orange-500 py-2 rounded-lg font-bold">保存配置</button>
            <button onclick="hideSettings()" class="flex-1 bg-gray-800 py-2 rounded-lg">取消</button></div>
          </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
          <div class="bg-gray-900/50 p-4 rounded-xl border border-gray-800">
            <label class="block text-[10px] text-gray-500 mb-1 font-bold">国家地区</label>
            <select id="countryF" onchange="render()" class="w-full bg-gray-900 text-white border-none p-0 text-sm focus:ring-0 outline-none"><option value="">全部</option></select>
          </div>
          <div class="bg-gray-900/50 p-4 rounded-xl border border-gray-800">
            <label class="block text-[10px] text-gray-500 mb-1 font-bold">厂商筛选</label>
            <select id="providerF" onchange="render()" class="w-full bg-gray-900 text-white border-none p-0 text-sm focus:ring-0 outline-none">
              <option value="">加载中...</option>
            </select>
          </div>
          <div class="bg-gray-900/50 p-4 rounded-xl border border-gray-800">
            <label class="block text-[10px] text-gray-500 mb-1 font-bold">代理类型</label>
            <select id="cfF" onchange="render()" class="w-full bg-gray-900 text-white border-none p-0 text-sm focus:ring-0 outline-none"><option value="">全部</option><option value="true">反代节点</option><option value="false">直连节点</option></select>
          </div>
          <div class="bg-gray-900/50 p-4 rounded-xl border border-gray-800">
            <label class="block text-[10px] text-gray-500 mb-1 font-bold">排序</label>
            <select id="sortO" onchange="render()" class="w-full bg-gray-800 text-white border-none p-0 text-sm focus:ring-0 outline-none"><option value="latency">延迟 (低->高)</option><option value="newest">更新时间</option></select>
          </div>
        </div>

        <div class="bg-gray-900 rounded-2xl border border-gray-800 overflow-hidden mb-8"><div class="overflow-x-auto"><table class="w-full text-left">
          <tr class="bg-gray-800/30 text-[10px] uppercase text-gray-500 font-bold"><th class="px-6 py-4">IP & Info (点击 IP 复制)</th><th class="px-6 py-4">Country</th><th class="px-6 py-4">ISP</th><th class="px-6 py-4">Delay</th><th class="px-6 py-4">Update</th></tr>
          <tbody id="tb" class="divide-y divide-gray-800"></tbody></table></div></div>
        
        <div class="flex flex-col md:flex-row justify-between items-center bg-gray-900 rounded-xl p-6 border border-gray-800 gap-4">
          <span id="st" class="text-sm text-gray-500 font-mono">Loading...</span>
          <div class="flex gap-3">
             <button onclick="runUpdate(this)" class="bg-gray-800 px-6 py-2 rounded-lg text-sm text-white font-semibold">立即刷新测速</button>
             <button onclick="copyAll()" class="bg-orange-500 px-6 py-2 rounded-lg text-sm text-white font-bold shadow-lg shadow-orange-500/20">复制 IP 列表</button>
          </div>
        </div>
      </div>
      <script>
        let raw = []; let set = {};
        async function load() {
          raw = await fetch('/api/ips').then(r => r.json());
          set = await fetch('/api/settings').then(r => r.json());
          
          const countries = [...new Set(raw.map(i => i.country))].sort();
          countryF.innerHTML = '<option value="">全部国家</option>' + countries.map(c => \\\`<option value="\\\${c}">\\\${c}</option>\\\`).join('');
          
          const providers = [...new Set(raw.map(i => i.provider))].sort();
          providerF.innerHTML = '<option value="">全部厂商</option>' + providers.map(p => \\\`<option value="\\\${p}">\\\${p}</option>\\\`).join('');
          
          render();
        }
        function render() {
          const c = countryF.value; const p = providerF.value; const cf = cfF.value; const s = sortO.value;
          let filter = raw.filter(i => (!c || i.country === c) && (!p || i.provider === p) && (cf === "" || (i.isProxy ?? false).toString() === cf));
          if(s === 'latency') filter.sort((a,b) => a.latency - b.latency); else filter.sort((a,b) => new Date(b.updateAt) - new Date(a.updateAt));
          tb.innerHTML = filter.map(i => \\\`
            <tr class="hover:bg-gray-800/20"><td class="px-6 py-4 cursor-pointer" onclick="copyText('\\\${i.ip}')">
            <div class="font-mono text-sm font-bold text-white">\\\${i.ip}</div>
            <div class="text-[10px] \\\${i.isProxy ? 'text-blue-400' : 'text-gray-400'}">\\\${i.isProxy ? '反代节点' : '直连节点'}</div></td>
            <td class="px-6 py-4 text-sm font-semibold">\\\${i.country}</td><td class="px-6 py-4 text-xs font-semibold text-orange-400">\\\${i.provider}</td>
            <td class="px-6 py-4"><span class="text-xs font-bold \\\${i.latency < 200 ? 'text-green-400' : 'text-yellow-500'}">\\\${i.latency}ms</span></td>
            <td class="px-6 py-4 text-[10px] text-gray-500 font-mono">\\\${i.updateAt.split('T')[1].split('.')[0]}</td></tr>
          \\\`).join('');
          st.innerText = \\\`FIND: \\\${filter.length} / TOTAL: \\\${raw.length}\\\`;
          window.cur = filter;
        }
        function showSettings() { domainList.value = set.domains.join('\\\\n'); settingsBox.classList.remove('hidden'); }
        function hideSettings() { settingsBox.classList.add('hidden'); }
        async function saveSettings() {
          const d = domainList.value.split('\\\\n').filter(l => l.trim());
          const payload = { domains: d }; if(newPw.value) payload.password = newPw.value;
          await fetch('/api/settings', { method: 'POST', body: JSON.stringify(payload) });
          location.reload();
        }
        async function runUpdate(btn) {
          const og = btn.innerText;
          btn.disabled = true; 
          btn.innerText = '正在启动测速...';
          
          try {
            await fetch('/api/update');
            let checks = 0;
            
            const it = setInterval(async () => {
              try {
                const p = await fetch('/api/progress').then(r => r.json());
                
                if (p.status === 'starting' || p.status === 'dns') {
                  btn.innerText = '正在解析 DNS... (' + (p.dnsResolved || 0) + '/' + (p.dnsRequests || 0) + ')';
                } else if (p.status === 'test') {
                  const pct = p.ipTotal ? Math.floor((p.ipTested || 0) / p.ipTotal * 100) : 0;
                  btn.innerText = '正在进行 TCP 测速: ' + pct + '% (' + (p.ipTested || 0) + '/' + (p.ipTotal || 0) + ')';
                } else if (p.status === 'saving') {
                  btn.innerText = '保存结果中...';
                } else if (p.status === 'completed') {
                  clearInterval(it);
                  btn.innerText = '测速完成！';
                  location.reload(); // 立即刷新页面
                  return;
                }
                
                if(++checks > 300) { 
                  clearInterval(it); 
                  btn.disabled = false;
                  btn.innerText = og; 
                  alert('后台测速超时，请稍后手动刷新页面查看最新结果'); 
                }
              } catch(e) {}
            }, 1000);
          } catch(e) {
            btn.disabled = false;
            btn.innerText = og;
            alert('请求失败，请检查网络');
          }
        }
        async function logout() { await fetch('/api/logout'); location.reload(); }
        function copyText(val) {
          navigator.clipboard.writeText(val).then(() => {
            const toast = document.createElement('div');
            toast.className = 'fixed bottom-10 left-1/2 -translate-x-1/2 bg-gray-800 text-white px-4 py-2 rounded-full text-xs shadow-2xl border border-gray-700 animate-bounce';
            toast.innerText = '已复制 IP: ' + val;
            document.body.appendChild(toast);
            setTimeout(() => toast.remove(), 2000);
          });
        }
        function copyAll() { 
          const t = window.cur.map(i => \\\`\\\${i.ip}#\\\${i.country}_\\\${i.provider}_[\\\${i.latency}ms]\\\`).join('\\\\n'); 
          navigator.clipboard.writeText(t).then(() => alert('Copied!'));
        }
        load();
      </script>
    </body></html>\`;
  }
};
`;

const WRANGLER_CODE = `name = "proxyip-tracker"
main = "src/worker.js"
compatibility_date = "2024-04-20"

# Trigger every hour (cron schedule)
[triggers]
crons = ["0 * * * *"]

# KV Namespace Binding
# IMPORTANT: Run \`npx wrangler kv:namespace create PROXY_IP_KV\` first,
# then replace the ID below with the one provided in your terminal.
[[kv_namespaces]]
binding = "PROXY_IP_KV"
id = "YOUR_KV_NAMESPACE_ID_HERE"
`;

function CodeBlock({ code, language, title }: { code: string; language: string; title: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-xl my-6">
      <div className="flex items-center justify-between px-6 py-3 border-b border-slate-100 bg-slate-50">
        <div className="flex gap-2 items-center">
          <FileCode size={16} className="text-slate-400" />
          <span className="text-sm font-bold text-slate-700 uppercase tracking-widest">{title}</span>
        </div>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1.5 px-3 py-1.5 transition-colors rounded-lg text-xs font-semibold hover:bg-slate-200 text-slate-600 bg-white border border-slate-200 shadow-sm"
        >
          {copied ? <Check size={14} className="text-green-600" /> : <Copy size={14} />}
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <div className="p-6 overflow-x-auto bg-slate-50/50">
        <pre className="text-sm font-mono leading-relaxed text-slate-700">
          <code>{code}</code>
        </pre>
      </div>
    </div>
  );
}

export default function App() {
  const [activeTab, setActiveTab] = useState<"deploy_api" | "code" | "deploy_cli">("deploy_api");

  const [accountId, setAccountId] = useState("");
  const [apiToken, setApiToken] = useState("");
  const [isDeploying, setIsDeploying] = useState(false);
  const [deployStatus, setDeployStatus] = useState<{tag: 'idle'|'success'|'error', msg?: string, url?: string}>({tag: 'idle'});

  const handleAutoDeploy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!accountId || !apiToken) return;

    setIsDeploying(true);
    setDeployStatus({ tag: 'idle' });

    try {
      const res = await fetch('/api/deploy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ accountId, apiToken, workerCode: WORKER_CODE })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setDeployStatus({ tag: 'success', url: data.url, msg: "部署成功！您的站点已经上线运行。如果您是首次部署，配置可能需要十几秒生效。" });
      } else {
        setDeployStatus({ tag: 'error', msg: data.error || "部署过程发生错误" });
      }
    } catch (err: any) {
      setDeployStatus({ tag: 'error', msg: err?.message || "网络请求失败" });
    }
    setIsDeploying(false);
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 font-sans selection:bg-slate-200">
      <div className="max-w-4xl mx-auto px-6 py-12 flex flex-col">
        
        {/* Header */}
        <motion.div 
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex justify-between items-end mb-12 border-b border-slate-200 pb-8"
        >
          <div>
            <h1 className="text-4xl font-light tracking-tight text-slate-800 mb-2 flex items-center gap-3">
              Cloudflare Worker ProxyIP Scanner
            </h1>
            <p className="text-slate-500 uppercase tracking-widest text-xs font-semibold max-w-2xl">
              自动解析域名 • 归属地判定 • KV永久存储
            </p>
          </div>
        </motion.div>

        {/* Custom Tabs */}
        <div className="flex flex-wrap gap-4 mb-8">
          <button
            onClick={() => setActiveTab("deploy_api")}
            className={`px-6 py-3 rounded-xl text-sm font-bold uppercase tracking-wider transition-all flex items-center gap-2 ${
              activeTab === "deploy_api" 
                ? "bg-slate-800 text-white shadow-xl" 
                : "bg-white border border-slate-200 text-slate-600 hover:text-slate-900 hover:bg-slate-50 shadow-sm"
            }`}
          >
            <Rocket size={16} /> 一键部署 (Auto Deploy)
          </button>
          <button
            onClick={() => setActiveTab("code")}
            className={`px-6 py-3 rounded-xl text-sm font-bold uppercase tracking-wider transition-all flex items-center gap-2 ${
              activeTab === "code" 
                ? "bg-slate-800 text-white shadow-xl" 
                : "bg-white border border-slate-200 text-slate-600 hover:text-slate-900 hover:bg-slate-50 shadow-sm"
            }`}
          >
            <FileCode size={16} /> 核心代码 (Files)
          </button>
          <button
            onClick={() => setActiveTab("deploy_cli")}
            className={`px-6 py-3 rounded-xl text-sm font-bold uppercase tracking-wider transition-all flex items-center gap-2 ${
              activeTab === "deploy_cli" 
                ? "bg-slate-800 text-white shadow-xl" 
                : "bg-white border border-slate-200 text-slate-600 hover:text-slate-900 hover:bg-slate-50 shadow-sm"
            }`}
          >
            <Terminal size={16} /> 本地部署指南 (CLI)
          </button>
        </div>

        {/* Tab Content */}
        {activeTab === "deploy_api" && (
          <motion.div
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.2 }}
            className="space-y-6"
          >
            <div className="bg-[#0f111a] border border-gray-800 rounded-xl p-8 shadow-xl">
              <h3 className="text-xl font-bold text-white mb-2 underline decoration-orange-500/50 underline-offset-4">自动连线 Cloudflare</h3>
              <p className="text-sm text-gray-400 mb-6">
                提供您的 Cloudflare 账户信息，本应用会自动为您：创建 KV 存储空间、上传 Worker 脚本代码、配置 Cron 重复任务定时器，并直接发布上线！
                <span className="block mt-2 text-xs text-orange-400/80 bg-orange-400/5 p-2 rounded border border-orange-400/20 italic">
                  💡 推荐：在 AI Studio 的 "Settings -&gt; Secrets" 中添加 CLOUDFLARE_ACCOUNT_ID 和 CLOUDFLARE_API_TOKEN 变量，之后可实现“一键静默部署”，无需重复输入。
                </span>
              </p>

              <form onSubmit={handleAutoDeploy} className="space-y-5">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1.5">
                    Account ID <span className="text-gray-500 font-normal">(账户 ID，若已设置 Secret 可留空)</span>
                  </label>
                  <input 
                    type="text" 
                    value={accountId}
                    onChange={(e) => setAccountId(e.target.value)}
                    placeholder="e.g. 1234567890abcdef1234567890abcdef"
                    className="w-full bg-[#161925] border border-gray-700 rounded-lg px-4 py-2.5 text-gray-200 focus:outline-none focus:ring-2 focus:ring-[#f6821f]/50 focus:border-[#f6821f] transition-all"
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1.5">
                    API Token / Global API Key <span className="text-gray-500 font-normal">(API 令牌，若已设置 Secret 可留空)</span>
                  </label>
                  <input 
                    type="password" 
                    value={apiToken}
                    onChange={(e) => setApiToken(e.target.value)}
                    placeholder="e.g. abcdefghijklmnopqrstuvwxyz1234567890"
                    className="w-full bg-[#161925] border border-gray-700 rounded-lg px-4 py-2.5 text-gray-200 focus:outline-none focus:ring-2 focus:ring-[#f6821f]/50 focus:border-[#f6821f] transition-all"
                  />
                </div>

                <button 
                  type="submit" 
                  disabled={isDeploying}
                  className="mt-4 w-full bg-[#f6821f] hover:bg-[#d66a12] disabled:bg-gray-700 disabled:text-gray-400 text-white font-bold py-3 px-4 rounded-lg flex items-center justify-center gap-2 transition-colors duration-200 shadow-lg shadow-[#f6821f]/20"
                >
                  {isDeploying ? (
                    <><Loader2 className="animate-spin" size={18} /> 正在部署中，请耐心等待自动化流程执行完...</>
                  ) : (
                    <><Rocket size={18} /> 立即一键自动部署</>
                  )}
                </button>
              </form>

              {deployStatus.tag !== 'idle' && (
                <div className={`mt-6 p-4 rounded-lg flex items-start gap-3 border ${
                  deployStatus.tag === 'success' 
                    ? 'bg-green-500/10 border-green-500/30 text-green-400' 
                    : 'bg-red-500/10 border-red-500/30 text-red-400'
                }`}>
                  {deployStatus.tag === 'success' ? <CheckCircle2 className="shrink-0 mt-0.5" size={18} /> : <AlertCircle className="shrink-0 mt-0.5" size={18} />}
                  <div className="flex-1">
                    <p className="font-semibold text-sm leading-snug">{deployStatus.msg}</p>
                    {deployStatus.tag === 'success' && deployStatus.url && (
                      <div className="mt-3">
                        <a 
                          href={deployStatus.url} 
                          target="_blank" 
                          rel="noreferrer"
                          className="inline-flex items-center gap-1.5 text-sm font-medium bg-green-500/20 hover:bg-green-500/30 text-green-300 px-3 py-1.5 rounded-md transition-colors"
                        >
                          访问我的 Worker 站点 <ExternalLink size={14} />
                        </a>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
            <p className="text-sm text-gray-500 text-center flex items-center justify-center gap-2">
              安全提示: 您的 API 密钥只会安全地通过此应用提供的后端服务发送给 Cloudflare 一次，绝不会被保存或用于其他用途。
            </p>
          </motion.div>
        )}
        {activeTab === "code" && (
          <motion.div
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.2 }}
          >
            <p className="text-gray-400 flex items-center gap-2">
              <CheckCircle2 size={16} className="text-green-500" />
              将以下代码保存到您的 Cloudflare Worker 项目根目录中：
            </p>
            <CodeBlock code={WORKER_CODE} language="javascript" title="src/worker.js" />
            <CodeBlock code={WRANGLER_CODE} language="toml" title="wrangler.toml" />
          </motion.div>
        )}

        {activeTab === "deploy_cli" && (
          <motion.div
            initial={{ opacity: 0, x: 10 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.2 }}
            className="space-y-8"
          >
            <div className="bg-[#0f111a] border border-gray-800 rounded-xl p-6">
              <h3 className="text-xl font-bold text-white mb-6">如何部署到 Cloudflare</h3>
              
              <ol className="space-y-6 text-gray-300 list-none">
                <li className="relative pl-8">
                  <span className="absolute left-0 top-0 inline-flex items-center justify-center w-5 h-5 rounded-full bg-[#f6821f]/20 text-[#f6821f] text-xs font-bold ring-2 ring-[#f6821f]/30">1</span>
                  <div className="font-semibold text-white mb-1">初始化项目</div>
                  <p className="text-sm text-gray-400 mb-2">创建一个新的文件夹并初始化 Worker 项目：</p>
                  <pre className="bg-black/50 p-3 rounded-lg border border-gray-800 font-mono text-sm">
                    npx wrangler init proxyip-tracker -y{`\\n`}
                    cd proxyip-tracker
                  </pre>
                </li>

                <li className="relative pl-8">
                  <span className="absolute left-0 top-0 inline-flex items-center justify-center w-5 h-5 rounded-full bg-[#f6821f]/20 text-[#f6821f] text-xs font-bold ring-2 ring-[#f6821f]/30">2</span>
                  <div className="font-semibold text-white mb-1">创建 KV 存储空间</div>
                  <p className="text-sm text-gray-400 mb-2">运行以下命令创建一个新的 KV 空间（用于存储整理好的 IP 列表）：</p>
                  <pre className="bg-black/50 p-3 rounded-lg border border-gray-800 font-mono text-sm">
                    npx wrangler kv:namespace create PROXY_IP_KV
                  </pre>
                  <p className="text-sm text-yellow-500/80 mt-2">
                    * 运行后终端会输出一个 `id`。复制这个 ID，替换到 `wrangler.toml` 中的 `YOUR_KV_NAMESPACE_ID_HERE` 处。
                  </p>
                </li>

                <li className="relative pl-8">
                  <span className="absolute left-0 top-0 inline-flex items-center justify-center w-5 h-5 rounded-full bg-[#f6821f]/20 text-[#f6821f] text-xs font-bold ring-2 ring-[#f6821f]/30">3</span>
                  <div className="font-semibold text-white mb-1">复制核心代码</div>
                  <p className="text-sm text-gray-400">将上方 <span className="text-white">代码片段</span> 标签页中的 `src/worker.js` 和 `wrangler.toml` 文件覆盖到你本地项目里对应的同名文件中。</p>
                </li>

                <li className="relative pl-8">
                  <span className="absolute left-0 top-0 inline-flex items-center justify-center w-5 h-5 rounded-full bg-[#f6821f]/20 text-[#f6821f] text-xs font-bold ring-2 ring-[#f6821f]/30">4</span>
                  <div className="font-semibold text-white mb-1">部署上线</div>
                  <p className="text-sm text-gray-400 mb-2">一键发布你的 Worker：</p>
                  <pre className="bg-black/50 p-3 rounded-lg border border-gray-800 font-mono text-sm">
                    npx wrangler deploy
                  </pre>
                </li>

                <li className="relative pl-8">
                  <span className="absolute left-0 top-0 inline-flex items-center justify-center w-5 h-5 rounded-full bg-green-500/20 text-green-500 text-xs font-bold ring-2 ring-green-500/30">!</span>
                  <div className="font-semibold text-white mb-1">开始使用与测试</div>
                  <p className="text-sm text-gray-400 mb-2">部署完成后：</p>
                  <ul className="list-disc leading-relaxed text-sm text-gray-400 pl-4 space-y-1 marker:text-gray-600">
                    <li>定时任务 (<strong>Cron</strong>) 会每小时自动执行，抓取和分类最新的 IP。</li>
                    <li>你可以直接访问 Worker 提供的部署域名（如 <code className="bg-gray-800 px-1 rounded">https://proxyip-tracker.your-subdomain.workers.dev</code>）来查看当前的 IP 数据。</li>
                    <li>如果你想<strong>立即触发更新测试</strong>，只需访问： <code className="bg-gray-800 px-1 rounded text-green-400">https://...workers.dev/update</code>。</li>
                  </ul>
                </li>
              </ol>
            </div>
          </motion.div>
        )}

      </div>
    </div>
  );
}
