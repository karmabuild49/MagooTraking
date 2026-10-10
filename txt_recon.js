#!/usr/bin/env node
'use strict';

const dns = require('node:dns').promises;
const fs = require('node:fs');

const TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'CAA', 'SOA'];
const SUBDOMAINS = ['www', 'mail', 'ftp', 'api', 'dev', 'staging', 'test',
  'blog', 'shop', 'admin', 'portal', 'support', 'status', 'cdn', 'assets'];

function usage() {
  console.log('Usage: node txt_recon.js <domain> [--out FILE] [--help]');
}

async function query(name, type) {
  try {
    let records;
    switch (type) {
      case 'A': records = await dns.resolve4(name); break;
      case 'AAAA': records = await dns.resolve6(name); break;
      case 'MX': records = await dns.resolveMx(name); break;
      case 'NS': records = await dns.resolveNs(name); break;
      case 'TXT': records = await dns.resolveTxt(name); break;
      case 'CNAME': records = await dns.resolveCname(name); break;
      case 'CAA': records = await dns.resolveCaa(name); break;
      case 'SOA': records = await dns.resolveSoa(name); break;
    }
    return { status: 'ok', records };
  } catch (e) {
    return { status: 'error', code: e.code || 'UNKNOWN', message: e.message, records: [] };
  }
}

function txtAnalysis(records) {
  const values = records.flat().map(String);
  return {
    spf: values.filter(v => /^v=spf1/i.test(v)),
    dmarc: values.filter(v => /^v=dmarc1/i.test(v)),
    verification: values.filter(v => /google-site-verification|facebook-domain-verification|MS=|apple-domain-verification/i.test(v)),
    other: values.filter(v => !/^v=spf1/i.test(v) && !/^v=dmarc1/i.test(v))
  };
}

async function main() {
  const args = process.argv.slice(2);
  if (!args.length || args.includes('--help') || args.includes('-h')) {
    usage();
    process.exitCode = args.length ? 0 : 1;
    return;
  }
  const domain = args[0].trim().toLowerCase().replace(/\.$/, '');
  if (!domain || domain.includes('://') || /[\s/]/.test(domain)) {
    throw new Error('Use a domain only, for example example.com');
  }
  let out = null;
  for (let i = 1; i < args.length; i++) {
    if (args[i] === '--out') {
      out = args[++i];
      if (!out) throw new Error('--out requires a filename');
    } else throw new Error('Unknown option: ' + args[i]);
  }

  const names = [...new Set([domain, ...SUBDOMAINS.map(s => s + '.' + domain), '_dmarc.' + domain])];
  const results = [];
  for (const name of names) {
    const records = {};
    for (const type of TYPES) records[type] = await query(name, type);
    results.push({ name, records });
  }
  const root = results.find(r => r.name === domain);
  const dmarc = results.find(r => r.name === '_dmarc.' + domain);
  const report = {
    tool: 'MagooTracking DNS Recon',
    version: '1.0.0',
    scannedAt: new Date().toISOString(),
    domain,
    summary: {
      namesQueried: results.length,
      successfulQueries: results.reduce((n, r) => n + Object.values(r.records).filter(x => x.status === 'ok').length, 0)
    },
    txtAnalysis: {
      root: txtAnalysis(root.records.TXT.records),
      dmarc: txtAnalysis(dmarc.records.TXT.records)
    },
    results
  };
  const json = JSON.stringify(report, null, 2);
  if (out) {
    fs.writeFileSync(out, json + '\n', 'utf8');
    console.log('JSON report written to ' + out);
  }
  console.log(json);
}

main().catch(e => {
  console.error('Error: ' + e.message);
  process.exitCode = 1;
});
