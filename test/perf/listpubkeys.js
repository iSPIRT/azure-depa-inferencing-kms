import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  insecureSkipTLSVerify: true,
  vus: 20,          // number of virtual users
  duration: '30s',  // total test duration
};

export default function () {
  const res = http.get('https://depa-inferencing-kms.centralindia.cloudapp.azure.com/app/listpubkeys');
  
  check(res, {
    'status is 200': (r) => r.status === 200,
  });
  
  sleep(1); // each user waits 1 second between requests
}