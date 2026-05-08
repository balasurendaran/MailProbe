const dns = require('dns');
const dnsPromises = dns.promises;

async function test() {
  try {
    console.log('Setting DNS servers to 8.8.8.8...');
    dns.setServers(['8.8.8.8', '1.1.1.1']);
    
    console.log('Resolving MX for gmail.com...');
    const records = await dnsPromises.resolveMx('gmail.com');
    console.log('Success:', records);
  } catch (err) {
    console.error('Failed:', err);
  }
}

test();
