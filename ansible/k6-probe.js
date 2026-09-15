import http from 'k6/http';
import { check } from 'k6';

export const options = {
  scenarios: {
    probe_200tps: {
      executor: 'constant-arrival-rate',
      rate: 200,
      timeUnit: '1s',
      duration: '45s',
      preAllocatedVUs: 50,
      maxVUs: 150,
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.02'],   // error rate < 2%
    http_req_duration: ['p(95)<100'], // 95% requests < 100ms
  },
};

const VM1_BASE = 'http://192.168.122.236:8010';
const VM2_BASE = 'http://192.168.122.237:8010';

const SOAP_BODY = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><soapenv:Header><wsse:Security><wsse:UsernameToken><wsse:Username>k6_probe_user</wsse:Username></wsse:UsernameToken></wsse:Security></soapenv:Header><soapenv:Body><probeRequest/></soapenv:Body></soapenv:Envelope>';

export default function () {
  // Round-robin or distribute between endpoints across VM1 and VM2
  const rand = Math.random();

  if (rand < 0.35) {
    // 1. VM1 WsseService entry call (proxies to VM2 with traceparent & WSSE header)
    const res = http.post(
      `${VM1_BASE}/api/order`,
      JSON.stringify({ item: 'probe_test', ts: Date.now() }),
      {
        headers: {
          'Content-Type': 'application/json',
          'X-WSSE': 'Username="k6_client"',
        },
      }
    );
    check(res, {
      'VM1 order 200 OK': (r) => r.status === 200,
    });
  } else if (rand < 0.60) {
    // 2. VM1 SOAP XML call with WSSE UsernameToken
    const res = http.post(`${VM1_BASE}/soap/ws`, SOAP_BODY, {
      headers: {
        'Content-Type': 'text/xml',
      },
    });
    check(res, {
      'VM1 SOAP 200 OK': (r) => r.status === 200,
    });
  } else if (rand < 0.85) {
    // 3. VM2 direct call with Basic Auth
    const res = http.get(`${VM2_BASE}/api/users?status=200`, {
      headers: {
        Authorization: 'Basic YWRtaW46c2VjcmV0MTIz', // admin:secret123
      },
    });
    check(res, {
      'VM2 users 200 OK': (r) => r.status === 200,
    });
  } else {
    // 4. Healthz endpoint
    const target = rand < 0.92 ? `${VM1_BASE}/healthz` : `${VM2_BASE}/healthz`;
    const res = http.get(target);
    check(res, {
      'healthz 200 OK': (r) => r.status === 200,
    });
  }
}
