import { auditResolvedDeliveryTarget, validateDeliveryUrl } from '../src/index.mjs';

const url = 'https://hooks.example.com/inbound';
console.log(validateDeliveryUrl(url));
console.log(auditResolvedDeliveryTarget(url, ['93.184.216.34']));
console.log(validateDeliveryUrl('https://169.254.169.254/latest/meta-data/'));
