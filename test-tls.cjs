const tls = require('tls');
const start = performance.now();
const socket = tls.connect({
  host: '1.1.1.1', // example IP
  port: 443,
  servername: 'www.cloudflare.com',
  rejectUnauthorized: false
}, () => {
  console.log(performance.now() - start);
  socket.destroy();
});
socket.on('error', console.error);
