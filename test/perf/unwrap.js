import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  insecureSkipTLSVerify: true,
  vus: 20,          // number of virtual users
  duration: '30s',  // total test duration
};

console.log('Reading attestation and wrapping key from files');
const attestation = open('../attestation-samples/snp.json').trim();
const wrappingKey = open('../data-samples/publicWrapKey.pem').trim();

export const kid = "18";
console.log('Using kid:', kid);

export default function () {
  // Replace with actual values as needed
  const url = 'https://depa-inferencing-kms.centralindia.cloudapp.azure.com/app/unwrapKey';
  const payload = JSON.stringify({
    attestation: attestation,
    wrappingKey: wrappingKey,
    wrappedKid: kid
  });

  const params = {
    headers: {
      'Content-Type': 'application/json',
      // Add authentication headers if required
    },
  };

  const res = http.post(url, payload, params);

  check(res, {
    'status is 200': (r) => r.status === 200,
    // Add more checks as needed, e.g., response structure
  });

  sleep(1); // each user waits 1 second between requests
}

