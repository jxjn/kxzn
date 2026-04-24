const https = require('https');
https.get('https://get.geojs.io/v1/ip/geo/8.8.8.8.json', (res) => {
  let data = '';
  res.on('data', chunk => data += chunk);
  res.on('end', () => console.log(data));
});
