import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  app.post('/api/deploy', async (req, res) => {
    const { accountId: reqAccountId, apiToken: reqApiToken, workerCode } = req.body;
    
    // Use UI input if provided, otherwise fallback to AI Studio Secrets (env variables)
    const accountId = reqAccountId || process.env.CLOUDFLARE_ACCOUNT_ID;
    const apiToken = reqApiToken || process.env.CLOUDFLARE_API_TOKEN;
    
    if (!accountId || !apiToken || !workerCode) {
      return res.status(400).json({ error: "Missing Cloudflare Credentials. Please provide Account ID and API Token in the UI, or set CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN in AI Studio Secrets." });
    }

    const headers = { 'Authorization': `Bearer ${apiToken}` };

    try {
      // 1. Get or Create KV Namespace
      const kvName = 'PROXY_IP_KV';
      let kvId = '';
      const kvListRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/storage/kv/namespaces`, { headers });
      const kvList = await kvListRes.json();
      if (!kvList.success) throw new Error('Failed to fetch KV namespaces: ' + JSON.stringify(kvList.errors));
      
      const existingKv = kvList.result.find((k: any) => k.title === kvName);
      if (existingKv) {
        kvId = existingKv.id;
      } else {
        const kvCreateRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/storage/kv/namespaces`, {
          method: 'POST',
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: JSON.stringify({ title: kvName })
        });
        const kvCreate = await kvCreateRes.json();
        if (!kvCreate.success) throw new Error('Failed to create KV: ' + JSON.stringify(kvCreate.errors));
        kvId = kvCreate.result.id;
      }

      // 2. Upload Worker script
      const form = new FormData();
      const metadata = {
        main_module: 'worker.js',
        bindings: [
          {
            name: 'PROXY_IP_KV',
            type: 'kv_namespace',
            namespace_id: kvId
          }
        ],
        compatibility_date: '2024-04-20'
      };
      form.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }), 'metadata.json');
      form.append('worker.js', new Blob([workerCode], { type: 'application/javascript+module' }), 'worker.js');

      const uploadRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/proxyip-tracker`, {
        method: 'PUT',
        headers,
        body: form as any
      });
      const uploadData = await uploadRes.json();
      if (!uploadData.success) throw new Error('Failed to upload worker: ' + JSON.stringify(uploadData.errors));

      // 3. Set Crons
      const cronRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/proxyip-tracker/schedules`, {
        method: 'PUT',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify([{ cron: '0 * * * *' }])
      });
      const cronData = await cronRes.json();
      if (!cronData.success) throw new Error('Failed to set crons: ' + JSON.stringify(cronData.errors));

      // 4. Enable Subdomain
      await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/proxyip-tracker/subdomain`, {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: true })
      });

      // Fetch subdomain name
      const accSubRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/subdomain`, { headers });
      const accSubData = await accSubRes.json();
      let siteUrl = accSubData.success && accSubData.result ? `https://proxyip-tracker.${accSubData.result.subdomain}.workers.dev` : 'Please check your Cloudflare Dashboard';

      res.json({ success: true, url: siteUrl });
    } catch (e: any) {
      console.error(e);
      res.status(500).json({ error: e.message });
    }
  });

  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
