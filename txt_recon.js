#!/usr/bin/env node
"use strict";

/**
 * txt_recon.js v2.0
 * Public DNS reconnaissance with JSON output.
 * Requires Node.js and dig (Termux: pkg install dnsutils).
 *
 * Usage:
 * node txt_recon.js example.com
 * node txt_recon.js example.com --out report.json
 * node txt_recon.js --help
 */

const { spawn } = require("node:child_process");
const fs = require("node:fs/promises");
const path = require("node:path");

const VERSION = "2.0.0";
const TIMEOUT = 5000;

const SELECTORS = [
  "selector1", "selector2", "google", "default", "dkim",
  "mail", "s1", "s2", "k1", "m1", "smtp", "mandrill",
  "protonmail", "zoho"
];

function usage() {
  console.log(`
txt_recon.js v${VERSION}

Usage:
  node txt_recon.js <domain> [--out file.json] [--timeout ms]
  node txt_recon.js --help

Options:
  --out FILE       Save report to a JSON file
  --timeout MS     Timeout per DNS query (250-60000 ms)
  --no-color       Disable terminal colors
  --help           Show this help
`);
}

function parseArgs(argv) {
  const args = {
    domain: null,
    out: null,
    timeout: TIMEOUT,
    help: false
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];

    if (arg === "--help" || arg === "-h") {
      args.help = true;
    } else if (arg === "--no-color") {
      process.env.NO_COLOR = "1";
    } else if (arg === "--out") {
      if (!argv[i + 1]) throw new Error("--out requires a filename");
      args.out = argv[++i];
    } else if (arg === "--timeout") {
      const n = Number(argv[++i]);
      if (!Number.isInteger(n) || n < 250 || n > 60000) {
        throw new Error("--timeout must be 250-60000 ms");
      }
      args.timeout = n;
    } else if (arg.startsWith("-")) {
      throw new Error(`Unknown option: ${arg}`);
    } else if (!args.domain) {
      args.domain = arg;
    } else {
      throw new Error(`Unexpected argument: ${arg}`);
    }
  }

  return args;
}

function normalizeDomain(input) {
  let domain = String(input || "").trim().toLowerCase();

  domain = domain
    .replace(/^https?:\/\//, "")
    .split("/")[0]
    .replace(/:\d+$/, "")
    .replace(/\.$/, "");

  let hostname;
  try {
    hostname = new URL(`http://${domain}`).hostname.toLowerCase();
  } catch {
    throw new Error("Invalid domain name");
  }

  if (
    !hostname ||
    hostname.length > 253 ||
    !hostname.split(".").every(label =>
      label.length >= 1 &&
      label.length <= 63 &&
      /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
    )
  ) {
    throw new Error("Enter a valid domain, e.g. example.com");
  }

  return hostname;
}

function classifyTxt(value) {
  const v = String(value || "").trim();
  const findings = [];

  const add = (type, summary, confidence = "high", details = null) => {
    findings.push({ type, summary, confidence, details });
  };

  if (/^v=spf1(?:\s|$)/i.test(v)) {
    const includes = [...v.matchAll(/\binclude:([^\s]+)/ig)]
      .map(m => m[1]);

    let policy = "No explicit all mechanism";
    if (/(?:^|\s)-all(?:\s|$)/i.test(v)) policy = "hard-fail (-all)";
    else if (/(?:^|\s)~all(?:\s|$)/i.test(v)) policy = "soft-fail (~all)";
    else if (/(?:^|\s)\?all(?:\s|$)/i.test(v)) policy = "neutral (?all)";
    else if (/(?:^|\s)\+all(?:\s|$)/i.test(v)) policy = "pass-all (+all; risky)";

    add("SPF", "Email sender authorization policy.", "high", {
      includes,
      policy
    });
  }

  if (/^v=dmarc1(?:;|$)/i.test(v)) {
    const get = key =>
      (v.match(new RegExp(`(?:^|;)\\\\s*${key}=([^;]+)`, "i")) || [])[1] || null;

    add("DMARC", "Email authentication and reporting policy.", "high", {
      policy: get("p"),
      rua: get("rua"),
      ruf: get("ruf")
    });
  }

  const patterns = [
    [/^google-site-verification=/i, "Google verification"],
    [/^facebook-domain-verification=/i, "Meta/Facebook domain verification"],
    [/^ms=ms/i, "Microsoft domain verification"],
    [/^apple-domain=/i, "Apple domain verification"],
    [/^atlassian-domain-verification=/i, "Atlassian verification"],
    [/^adobe-idp-site-verification=/i, "Adobe verification"],
    [/^stripe-verification=/i, "Stripe verification"],
    [/^onetrust-domain-verification=/i, "OneTrust verification"]
  ];

  for (const [pattern, type] of patterns) {
    if (pattern.test(v)) {
      add(
        type,
        "Recognized service verification record. The TXT value alone does not identify the current account owner."
      );
    }
  }

  if (/^v=spf1/i.test(v) && /\+all(?:\s|$)/i.test(v)) {
    add(
      "SPF warning",
      "The +all mechanism authorizes any sender; the domain administrator should review this policy."
    );
  }

  if (/^v=dkim1(?:;|$)/i.test(v) ||
      (/\bp=/i.test(v) && /(?:^|;)\s*k=rsa/i.test(v))) {
    add("Possible DKIM record", "Possible DKIM public-key record.", "medium");
  }

  return findings;
}

function runDig(name, type, timeoutMs) {
  return new Promise(resolve => {
    const started = Date.now();
    let stdout = "";
    let stderr = "";
    let settled = false;
    let timer;

    const finish = result => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);

      resolve({
        name,
        type,
        elapsed_ms: Date.now() - started,
        ...result
      });
    };

    const proc = spawn("dig", [
      "+time=3",
      "+tries=1",
      "+noall",
      "+answer",
      name,
      type
    ], { stdio: ["ignore", "pipe", "pipe"] });

    timer = setTimeout(() => {
      proc.kill("SIGKILL");
      finish({
        ok: false,
        records: [],
        error: `Timed out after ${timeoutMs} ms`
      });
    }, timeoutMs);

    proc.stdout.on("data", chunk => {
      stdout += chunk.toString();
    });

    proc.stderr.on("data", chunk => {
      stderr += chunk.toString();
    });

    proc.on("error", err => {
      finish({
        ok: false,
        records: [],
        error: err.code === "ENOENT"
          ? "dig not found; install dnsutils"
          : err.message
      });
    });

    proc.on("close", code => {
      finish({
        ok: code === 0,
        records: stdout.trim()
          ? stdout.trim().split(/\r?\n/).filter(Boolean)
          : [],
        error: code === 0
          ? null
          : (stderr.trim() || `dig exited with code ${code}`)
      });
    });
  });
}

function buildQueries(domain) {
  const queries = [];

  for (const type of ["TXT", "A", "AAAA", "MX", "NS", "SOA", "CAA"]) {
    queries.push({ name: domain, type });
  }

  for (const name of [
    `_dmarc.${domain}`,
    `_mta-sts.${domain}`,
    `_smtp._tls.${domain}`
  ]) {
    queries.push({ name, type: "TXT" });
  }

  for (const name of [`www.${domain}`, `autodiscover.${domain}`]) {
    queries.push({ name, type: "CNAME" });
  }

  for (const selector of SELECTORS) {
    queries.push({
      name: `${selector}._domainkey.${domain}`,
      type: "TXT"
    });
  }

  for (const sub of [
    "www", "mail", "smtp", "api", "static",
    "assets", "cdn", "links", "uploads"
  ]) {
    queries.push({ name: `${sub}.${domain}`, type: "TXT" });
  }

  return queries;
}

function extractTxtRecords(results) {
  const output = [];

  for (const result of results) {
    if (result.type !== "TXT" || !result.ok) continue;

    for (const raw of result.records) {
      const match = raw.match(/\sTXT\s+(.*)$/i);
      if (!match) continue;

      // Join the quoted chunks of a single DNS TXT answer.
      const value = [...match[1].matchAll(/"((?:\\.|[^"])*)"/g)]
        .map(m => m[1])
        .join("");

      output.push({
        name: result.name,
        value,
        raw,
        classifications: classifyTxt(value),
        exact_search_urls: {
          Google: `https://www.google.com/search?q=${encodeURIComponent(`"${value}"`)}`,
          Bing: `https://www.bing.com/search?q=${encodeURIComponent(`"${value}"`)}`,
          DuckDuckGo: `https://duckduckgo.com/?q=${encodeURIComponent(`"${value}"`)}`
        }
      });
    }
  }

  return output;
}

async function main() { 
function extractSocialProfiles(html, domain) {
  const profiles = new Map();

  const patterns = [
    ["Instagram", /https?:\/\/(?:www\.)?instagram\.com\/[A-Za-z0-9._]+\/?/gi],
    ["Facebook", /https?:\/\/(?:www\.)?facebook\.com\/[A-Za-z0-9._-]+\/?/gi],
    ["X", /https?:\/\/(?:www\.)?(?:x|twitter)\.com\/[A-Za-z0-9_]+\/?/gi],
    ["TikTok", /https?:\/\/(?:www\.)?tiktok\.com\/@[A-Za-z0-9._]+\/?/gi],
    ["YouTube", /https?:\/\/(?:www\.)?youtube\.com\/@[A-Za-z0-9._-]+\/?/gi],
    ["Threads", /https?:\/\/(?:www\.)?threads\.net\/@[A-Za-z0-9._]+\/?/gi],
    ["Truth Social", /https?:\/\/(?:www\.)?truthsocial\.com\/@[A-Za-z0-9._]+\/?/gi],
    ["LinkedIn", /https?:\/\/(?:www\.)?linkedin\.com\/(?:company|in)\/[A-Za-z0-9._-]+\/?/gi]
  ];

  for (const [platform, pattern] of patterns) {
    for (const match of html.matchAll(pattern)) {
      try {
        const url = new URL(match[0]);
        const pathname = url.pathname.replace(/\/+$/, "");
        const first = pathname.split("/").filter(Boolean)[0];

        if (!first) continue;


        const username = platform === "YouTube" ||
          platform === "TikTok" ||
          platform === "Threads" ||
          platform === "Truth Social"
          ? first
          : platform === "LinkedIn"
            ? pathname.split("/").filter(Boolean)[1] || null
            : `@${first}`;

        const key = `${platform}:${url.hostname}${pathname}`;

        profiles.set(key, {
          platform,
          url: url.href,
          username_candidate: username,
          source: `Public HTML links on ${domain}`,
          identity_verified: false,
          public_display_name: null,
          public_bio: null,
          public_location: null,
          location_source: null,
          notes: [
            "Username is extracted from the URL and is not independently verified.",
            "No location is inferred from posts, photos, IP addresses, or followers."
          ]
        });
      } catch {
        // Skip malformed URLs.
      }
    }
  }

  return [...profiles.values()];
}

async function inspectPublicWebsite(domain) {
  const result = {
    checked: false,
    url: `https://${domain}`,
    title: null,
    description: null,
    social_profiles: [],
    error: null
  };

  try {
    const response = await fetch(result.url, {
      redirect: "follow",
      signal: AbortSignal.timeout(10000),
      headers: {
        "user-agent": "txt-recon/3.1 public metadata checker"
      }
    });

    if (!response.ok) {
      result.error = `Website returned HTTP ${response.status}`;
      return result;
    }

    const type = response.headers.get("content-type") || "";
    if (!type.includes("text/html")) {
      result.error = "Website did not return HTML";
      return result;
    }

    const html = (await response.text()).slice(0, 1500000);
    result.checked = true;

    function getMeta(key) {
      const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const patterns = [
        new RegExp(
          `<meta\\b[^>]*\\bproperty=["']${escaped}["'][^>]*\\bcontent=["']([^"']*)["']`,
          "i"
        ),
        new RegExp(
          `<meta\\b[^>]*\\bname=["']${escaped}["'][^>]*\\bcontent=["']([^"']*)["']`,
          "i"
        )
      ];

      for (const pattern of patterns) {
        const match = html.match(pattern);
        if (match) return match[1]
          .replace(/&amp;/g, "&")
          .replace(/&quot;/g, '"')
          .replace(/&#39;/g, "'")
          .replace(/&lt;/g, "<")
          .replace(/&gt;/g, ">");
      }

      return null;
    }

    const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);

    result.title = getMeta("og:title") ||
      (titleMatch ? titleMatch[1].trim() : null);

    result.description = getMeta("og:description") ||
      getMeta("description");

    result.social_profiles = extractSocialProfiles(html, domain);
  } catch (error) {
    result.error = error.message;
  }

  return result;
}

  const args = parseArgs(process.argv.slice(2));

  if (args.help) {
    usage();
    return;
  }

  if (!args.domain) {
    usage();
    process.exitCode = 1;
    return;
  }

  const domain = normalizeDomain(args.domain);
  const queries = buildQueries(domain);
  const results = [];

  console.log(`\n=== TXT Recon v${VERSION} ===`);
  console.log(`Target: ${domain}`);
  console.log("Scope: public DNS records only\n");

  // Keep DNS query concurrency low.
  for (let i = 0; i < queries.length; i += 5) {
    const batch = queries.slice(i, i + 5);
    const batchResults = await Promise.all(
      batch.map(q => runDig(q.name, q.type, args.timeout))
    );
    results.push(...batchResults);
  }

  const txtRecords = extractTxtRecords(results);
  const website = await inspectPublicWebsite(domain);
  const report = {
    tool: {
      name: "txt_recon",
      version: VERSION
    },
    generated_at: new Date().toISOString(),
    target: domain, website,
    social_profiles: website.social_profiles,
    scope: "Public DNS lookups only.",
    summary: {
      dns_queries: results.length,
      successful_queries: results.filter(r => r.ok).length,
      failed_queries: results.filter(r => !r.ok).length,
      txt_records_found: txtRecords.length,
      classified_txt_records: txtRecords.filter(
        r => r.classifications.length > 0
      ).length
    },
    txt_records: txtRecords,
    dns_results: results,
    references: {
      certificate_transparency: `https://crt.sh/?q=${encodeURIComponent(domain)}`,
      google_dns: `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=TXT`,
      security_txt: `https://${domain}/.well-known/security.txt`
    },
    notes: [
      "Verification tokens are not passwords.",
      "DNS alone does not establish who currently owns a service account.",
      "DNS answers may vary due to caching and propagation.",
      "Only assess domains you own or are authorized to test."
    ]
  };

  console.log("TXT findings:");

  if (txtRecords.length === 0) {
    console.log("No TXT answers returned for the queried names.");
  }

  for (const record of txtRecords) {
    console.log(`\n${record.name}`);
    console.log(`  ${record.value}`);

    if (record.classifications.length === 0) {
      console.log("  [Unclassified] No known pattern matched.");
    }

    for (const finding of record.classifications) {
      console.log(`  [${finding.type}] ${finding.summary}`);

      if (finding.details) {
        console.log(`  Details: ${JSON.stringify(finding.details)}`);
      }
    }
  }

  console.log(
    `\nDNS queries: ${report.summary.successful_queries}/${results.length} successful`
  );

  const json = JSON.stringify(report, null, 2);

  if (args.out) {
    const outputPath = path.resolve(args.out);
    await fs.writeFile(outputPath, json + "\n", {
      mode: 0o600
    });
    console.log(`JSON saved: ${outputPath}`);
  } else {
    console.log("\n--- JSON REPORT ---");
    console.log(json);
  }
}

main().catch(error => {
  console.error(`Error: ${error.message}`);
  process.exitCode = 1;
});
