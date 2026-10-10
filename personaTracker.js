/**
 * PersonTracker.js — Node.js OSINT script: search a person across ~60
 * platforms by username, social link, or email; collect everything
 * publicly available; and store JSON + Markdown reports.
 *
 * [!] LEGAL & ETHICAL USE ONLY - check your own accounts, authorized
 *     pentests, brand protection, or with the person's consent.
 *     Do not use it to stalk, harass, or doxx anyone.
 *
 * SETUP (nothing to install — zero dependencies):
 *   1. Save as person-tracker.js
 *   2. Requires Node.js >= 18 (has global fetch). Check:  node -v
 *   3. Optional but recommended: create package.json first:
 *        npm init -y
 *      then set "type": "commonjs" (default) — the script uses require().
 *
 * MODES:
 *   node person-tracker.js <username>                    full sweep + enrich + store
 *   node person-tracker.js --full <username>             ALSO chase every discovered alias
 *   node person-tracker.js --url <profile-url>           start from a social link
 *   node person-tracker.js --full --url <profile-url>    social link + alias chasing
 *   node person-tracker.js --multi <url|user> <url|user> ...  combined report for many links
 *   node person-tracker.js --links <profile-url>         only harvest links from a page
 *   node person-tracker.js --site github <user>          single platform check + detail
 *   node person-tracker.js --email <email>               email-based lookups (gravatar)
 *   node person-tracker.js --list                        list all supported platforms
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ------------------------------------------------------------------
// Platform registry (~60 platforms)
// {} is replaced with the username. group is used for reporting.
// ------------------------------------------------------------------
const PLATFORMS = {
  // --- dev / tech ---
  github:         { url: 'https://github.com/{}',                 group: 'dev' },
  gitlab:         { url: 'https://gitlab.com/{}',                 group: 'dev' },
  bitbucket:      { url: 'https://bitbucket.org/{}',              group: 'dev' },
  codeberg:       { url: 'https://codeberg.org/{}',               group: 'dev' },
  sourceforge:    { url: 'https://sourceforge.net/u/{}',          group: 'dev' },
  npm:            { url: 'https://www.npmjs.com/~{}',             group: 'dev' },
  pypi:           { url: 'https://pypi.org/user/{}',              group: 'dev' },
  crates:         { url: 'https://crates.io/users/{}',            group: 'dev' },
  docker:         { url: 'https://hub.docker.com/u/{}',           group: 'dev' },
  hackerrank:     { url: 'https://www.hackerrank.com/{}',         group: 'dev' },
  replit:         { url: 'https://replit.com/@{}',                group: 'dev' },
  leetcode:       { url: 'https://leetcode.com/{}',               group: 'dev' },
  codepen:        { url: 'https://codepen.io/{}',                 group: 'dev' },
  devto:          { url: 'https://dev.to/{}',                    group: 'dev' },
  hackernews:     { url: 'https://news.ycombinator.com/user?id={}', group: 'dev' },
  keybase:        { url: 'https://keybase.io/{}',                group: 'dev' },
  greasyfork:     { url: 'https://greasyfork.org/users/{}',       group: 'dev' },
  gumroad:        { url: 'https://{}.gumroad.com/',               group: 'dev' },

  // --- social ---
  reddit:         { url: 'https://www.reddit.com/user/{}',        group: 'social' },
  twitter:        { url: 'https://twitter.com/{}',                group: 'social', note: 'login-walled' },
  x:              { url: 'https://x.com/{}',                      group: 'social', note: 'login-walled' },
  threads:        { url: 'https://www.threads.net/@{}',           group: 'social', note: 'login-walled' },
  instagram:      { url: 'https://www.instagram.com/{}',         group: 'social', note: 'often login-walled' },
  facebook:       { url: 'https://www.facebook.com/{}',           group: 'social', note: 'login-walled' },
  vk:             { url: 'https://vk.com/{}',                     group: 'social' },
  mastodon:       { url: 'https://mastodon.social/@{}',          group: 'social', note: 'instance-specific' },
  bluesky:        { group: 'social', method: 'bluesky' },
  mewe:           { url: 'https://mewe.com/i/{}',                 group: 'social' },
  minds:          { url: 'https://www.minds.com/{}',              group: 'social' },
  gab:            { url: 'https://gab.com/{}',                    group: 'social' },
  truthsocial:    { url: 'https://truthsocial.com/@{}',          group: 'social' },
  telegram:       { url: 'https://t.me/{}',                      group: 'social' },
  snapchat:       { url: 'https://www.snapchat.com/add/{}',      group: 'social' },

  // --- content / creative ---
  youtube:        { url: 'https://www.youtube.com/@{}',          group: 'content' },
  vimeo:          { url: 'https://vimeo.com/{}',                 group: 'content' },
  dailymotion:    { url: 'https://www.dailymotion.com/{}',       group: 'content' },
  rumble:         { url: 'https://rumble.com/user/{}',           group: 'content' },
  odysee:         { url: 'https://odysee.com/@{}',              group: 'content' },
  medium:         { url: 'https://medium.com/@{}',               group: 'content' },
  substack:       { url: 'https://{}.substack.com/',             group: 'content' },
  wordpress:      { url: 'https://{}.wordpress.com/',            group: 'content' },
  blogspot:       { url: 'https://{}.blogspot.com/',             group: 'content' },
  tumblr:         { url: 'https://www.tumblr.com/{}',            group: 'content' },
  quora:          { url: 'https://www.quora.com/profile/{}',     group: 'content' },
  wattpad:        { url: 'https://www.wattpad.com/user/{}',       group: 'content' },
  goodreads:      { url: 'https://www.goodreads.com/{}',         group: 'content' },
  letterboxd:     { url: 'https://letterboxd.com/{}',           group: 'content' },
  trakt:          { url: 'https://trakt.tv/users/{}',            group: 'content' },
  myanimelist:    { url: 'https://myanimelist.net/profile/{}',   group: 'content' },
  pastebin:       { url: 'https://pastebin.com/u/{}',            group: 'content' },
  slideshare:     { url: 'https://www.slideshare.net/{}',        group: 'content' },
  scribd:         { url: 'https://www.scribd.com/{}',             group: 'content' },
  speakerdeck:    { url: 'https://speakerdeck.com/{}',           group: 'content' },

  // --- art / design / photo ---
  behance:        { url: 'https://www.behance.net/{}',           group: 'art' },
  dribbble:       { url: 'https://dribbble.com/{}',             group: 'art' },
  artstation:     { url: 'https://www.artstation.com/{}',       group: 'art' },
  deviantart:     { url: 'https://{}.deviantart.com',           group: 'art' },
  flickr:         { url: 'https://www.flickr.com/people/{}',     group: 'art' },
  '500px':        { url: 'https://500px.com/p/{}',              group: 'art' },
  unsplash:       { url: 'https://unsplash.com/@{}',             group: 'art' },
  vsco:           { url: 'https://vsco.co/{}',                   group: 'art' },
  imgur:          { url: 'https://imgur.com/user/{}',           group: 'art' },
  pinterest:      { url: 'https://www.pinterest.com/{}',        group: 'art' },
  etsy:           { url: 'https://www.etsy.com/shop/{}',          group: 'art' },
  redbubble:      { url: 'https://www.redbubble.com/people/{}',  group: 'art' },
  inprnt:         { url: 'https://www.inprnt.com/profile/{}',    group: 'art' },

  // --- music / audio ---
  soundcloud:     { url: 'https://soundcloud.com/{}',            group: 'music' },
  spotify:        { url: 'https://open.spotify.com/user/{}',      group: 'music' },
  bandcamp:       { url: 'https://{}.bandcamp.com/',             group: 'music' },
  audiomack:      { url: 'https://audiomack.com/{}',             group: 'music' },
  mixcloud:       { url: 'https://www.mixcloud.com/{}',          group: 'music' },
  lastfm:         { url: 'https://www.last.fm/user/{}',          group: 'music' },
  genius:         { url: 'https://genius.com/{}',                group: 'music' },
  reverbnation:   { url: 'https://www.reverbnation.com/{}',      group: 'music' },

  // --- gaming ---
  steam:          { url: 'https://steamcommunity.com/id/{}',     group: 'gaming' },
  roblox:         { url: 'https://www.roblox.com/users/profile?username={}', group: 'gaming' },
  minecraft:      { group: 'gaming', method: 'minecraft' },
  chess:          { group: 'gaming', method: 'chesscom' },
  lichess:        { group: 'gaming', method: 'lichess' },
  osu:            { url: 'https://osu.ppy.sh/users/{}',         group: 'gaming' },
  speedrun:       { url: 'https://www.speedrun.com/users/{}',    group: 'gaming' },
  itch:           { url: 'https://{}.itch.io/',                 group: 'gaming' },
  gamejolt:       { url: 'https://gamejolt.com/@{}',            group: 'gaming' },

  // --- business / pro ---
  linkedin:       { url: 'https://www.linkedin.com/in/{}',        group: 'pro', note: 'login-walled' },
  wellfound:      { url: 'https://wellfound.com/u/{}',            group: 'pro' },
  producthunt:    { url: 'https://www.producthunt.com/@{}',      group: 'pro' },
  indiehackers:   { url: 'https://www.indiehackers.com/{}',      group: 'pro' },
  aboutme:        { url: 'https://about.me/{}',                  group: 'pro' },
  linktree:       { url: 'https://linktr.ee/{}',               group: 'pro' },
  gravatar:       { group: 'pro', method: 'gravatar' },
};

const GROUP_LABELS = [
  ['dev', 'Dev / Tech'], ['social', 'Social'], ['content', 'Content / Writing'],
  ['art', 'Art / Design / Photo'], ['music', 'Music / Audio'],
  ['gaming', 'Gaming'], ['pro', 'Business / Pro'],
];

const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';
const UA_API = 'PersonTracker/1.0 (OSINT research tool)'; // friendlier for public APIs

// ------------------------------------------------------------------
// HTTP helpers
// ------------------------------------------------------------------
function timeoutSignal(ms) {
  try { return AbortSignal.timeout(ms); } catch (e) { return undefined; }
}

async function fetchSafe(url, opts = {}) {
  try {
    const res = await fetch(url, {
      redirect: 'follow',
      signal: timeoutSignal(10000),
      headers: { 'user-agent': UA, accept: 'text/html,application/json' },
      ...opts,
    });
    return res;
  } catch (e) {
    return { ok: false, status: 0, error: String(e), text: async () => '', json: async () => null };
  }
}

async function fetchApi(url) {
  return fetchSafe(url, { headers: { 'user-agent': UA_API, accept: 'application/json' } });
}

function classify(res) {
  if (res.status === 200) return 'FOUND';
  if ([403, 429, 503].includes(res.status) || res.status === 0) return 'UNKNOWN';
  return 'NOT_FOUND';
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

// ------------------------------------------------------------------
// ASCII art theme
// ------------------------------------------------------------------
const ASCII = {
  banner: [
    '=======================================================================',
    '   ____  _   _  ____ _   _  _____ ____    _____ ____  ',
    '  |  _ \\| | | |/ ___| | | |/ _ \\|  _ \\  |_   _|  _ \\ ',
    '  | |_) | | | | |   | |_| | | | | |_) |   | | | |_) |',
    '  |  __/| |_| | |___|  _  | |_| |  __/    | | |  __/ ',
    '  |_|    \\___/ \\____|_| |_|\\___/|_|       |_| |_|    ',
    '',
    '  * trace a person across ~60 platforms, gather public intel *',
    '=======================================================================',
  ].join('\n'),
  found:    (n) => `  [+] HIT  - matched ${n} platform${n === 1 ? '' : 's'}`,
  miss:     (n) => `  [-] MISS - ${n} platform${n === 1 ? '' : 's'} returned nothing`,
  unknown:  (n) => `  [?] LIM  - ${n} platform${n === 1 ? '' : 's'} rate-limited / login-walled`,
  reportHeader: (query) => [
    '  +-------------------------------------------------------------+',
    `  |  PERSON TRACKER :: TARGET "${String(query).slice(0, 32).padEnd(32)}"|`,
    '  +-------------------------------------------------------------+',
  ].join('\n'),
  progress: (name, result, status) => {
    const icon = result === 'FOUND' ? '[+]' : result === 'UNKNOWN' ? '[?]' : '[-]';
    return `  ${icon} ${name.padEnd(14)} ${result.padEnd(10)} ${status}`;
  },
  divider: '  ' + '-'.repeat(60),
  trackIcon: '*',
};

function printBanner() {
  console.log('\n' + ASCII.banner + '\n');
  console.log(ASCII.divider);
  console.log('  ' + ASCII.trackIcon + '  T R A C K I N G   P R O F I L E   T R A C E S');
  console.log(ASCII.divider + '\n');
}

// ------------------------------------------------------------------
// Probes — one unified entry point used by every mode
// ------------------------------------------------------------------
async function probePlatform(name, username) {
  const cfg = PLATFORMS[name];
  if (!cfg) return null;
  try {
    switch (cfg.method) {
      case 'gravatar':  return await probeGravatar(username);
      case 'bluesky':   return await probeBluesky(username);
      case 'minecraft': return await probeMinecraft(username);
      case 'chesscom':  return await probeChesscom(username);
      case 'lichess':   return await probeLichess(username);
      default:          return await probeStatus(name, cfg, username);
    }
  } catch (e) {
    return { platform: name, url: cfg.url ? cfg.url.replace('{}', username) : null,
      status: 0, result: 'UNKNOWN', group: cfg.group, error: String(e) };
  }
}

async function probeStatus(name, cfg, username) {
  const url = cfg.url.replace('{}', encodeURIComponent(username));
  const res = await fetchSafe(url);
  return { platform: name, url, status: res.status, result: classify(res), group: cfg.group, note: cfg.note };
}

async function probeGravatar(emailOrName) {
  const hash = crypto.createHash('sha256').update(String(emailOrName).trim().toLowerCase()).digest('hex');
  const res = await fetchApi(`https://gravatar.com/${hash}.json`);
  let data = null;
  if (res.ok) {
    const j = await res.json().catch(() => null);
    const e = j && j.entry && j.entry[0];
    if (e) data = {
      username: e.preferredUsername, display: e.displayName, about: e.aboutMe,
      accounts: (e.accounts || []).map(a => ({ platform: a.shortname, url: a.url })),
    };
  }
  return {
    platform: 'gravatar', url: `https://gravatar.com/${hash}`,
    status: res.status, result: data ? 'FOUND' : classify(res),
    group: 'pro', data, note: 'hash-based — matches by email',
  };
}

async function probeBluesky(username) {
  const res = await fetchApi(`https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=${encodeURIComponent(username)}`);
  let data = null;
  if (res.ok) {
    const j = await res.json().catch(() => null);
    if (j && j.did) data = {
      did: j.did, handle: j.handle, display: j.displayName, bio: j.description,
      followers: j.followersCount, posts: j.postsCount, created_at: j.createdAt, avatar: j.avatar,
    };
  }
  return {
    platform: 'bluesky', url: `https://bsky.app/profile/${username}`,
    status: res.status, result: data ? 'FOUND' : classify(res), group: 'social', data,
  };
}

async function probeMinecraft(username) {
  const res = await fetchApi(`https://api.mojang.com/users/profiles/minecraft/${encodeURIComponent(username)}`);
  let data = null;
  if (res.ok) data = await res.json().catch(() => null);
  return {
    platform: 'minecraft', url: `https://namemc.com/profile/${username}`,
    status: res.status, result: data ? 'FOUND' : classify(res),
    group: 'gaming', data: data ? { uuid: data.id } : null,
  };
}

async function probeChesscom(username) {
  const res = await fetchApi(`https://api.chess.com/pub/player/${encodeURIComponent(username)}`);
  let data = null;
  if (res.ok) {
    const j = await res.json().catch(() => null);
    if (j && j.username) data = {
      username: j.username, name: j.name || null, country: j.country || null,
      joined: j.joined ? new Date(j.joined * 1000).toISOString() : null, location: j.location || null,
    };
  }
  return {
    platform: 'chess', url: `https://www.chess.com/member/${username}`,
    status: res.status, result: data ? 'FOUND' : classify(res), group: 'gaming', data,
  };
}

async function probeLichess(username) {
  const res = await fetchApi(`https://lichess.org/api/user/${encodeURIComponent(username)}`);
  let data = null;
  if (res.ok) {
    const j = await res.json().catch(() => null);
    if (j && j.id) data = {
      username: j.username,
      created_at: j.createdAt ? new Date(j.createdAt).toISOString() : null,
      bio: (j.profile && j.profile.bio) || null,
      country: (j.profile && j.profile.country) || null,
    };
  }
  return {
    platform: 'lichess', url: `https://lichess.org/@/${username}`,
    status: res.status, result: data ? 'FOUND' : classify(res), group: 'gaming', data,
  };
}

// ------------------------------------------------------------------
// Enrichers (public APIs — pull real profile data)
// ------------------------------------------------------------------
async function enrichGithub(username) {
  const res = await fetchApi(`https://api.github.com/users/${encodeURIComponent(username)}`);
  if (!res.ok) return null;
  const u = await res.json().catch(() => null);
  if (!u) return null;
  return {
    platform: 'github', url: u.html_url, result: 'FOUND',
    data: {
      name: u.name || null, login: u.login, bio: u.bio || null, company: u.company || null,
      location: u.location || null, email: u.email || null, blog: u.blog || null,
      twitter: u.twitter_username || null, followers: u.followers,
      public_repos: u.public_repos, created_at: u.created_at, avatar: u.avatar_url,
    },
  };
}

async function enrichReddit(username) {
  const res = await fetchApi(`https://www.reddit.com/user/${encodeURIComponent(username)}/about.json`);
  if (!res.ok) return null;
  const d = ((await res.json().catch(() => null)) || {}).data;
  if (!d) return null;
  return {
    platform: 'reddit', url: `https://www.reddit.com/user/${username}`, result: 'FOUND',
    data: {
      name: (d.subreddit && d.subreddit.title) || null,
      bio: (d.subreddit && d.subreddit.public_description) || null,
      created_at: d.created_utc ? new Date(d.created_utc * 1000).toISOString() : null,
      karma: d.total_karma, verified: !!d.verified, is_mod: !!d.is_mod,
    },
  };
}

async function enrichGitlab(username) {
  const res = await fetchApi(`https://gitlab.com/api/v4/users?username=${encodeURIComponent(username)}`);
  if (!res.ok) return null;
  const arr = await res.json().catch(() => null);
  const u = arr && arr[0];
  if (!u) return null;
  return {
    platform: 'gitlab', url: u.web_url, result: 'FOUND',
    data: {
      name: u.name || null, username: u.username, bio: u.bio || null,
      location: u.location || null, state: u.state, created_at: u.created_at, avatar: u.avatar_url || null,
    },
  };
}

async function enrichLinktree(username) {
  const res = await fetchSafe(`https://linktr.ee/${encodeURIComponent(username)}`);
  if (!res.ok) return null;
  const html = await res.text();
  let name = null, bio = null, links = [];
  const m = html.match(/__NEXT_DATA__[^>]*>([\s\S]*?)<\/script>/);
  if (m) {
    try {
      const j = JSON.parse(m[1]);
      const p = (j.props && j.props.pageProps) || {};
      const acc = p.account || {};
      name = acc.title || null;
      bio = acc.description || null;
      (acc.links || []).forEach(l => l.url && links.push(l.url));
      (acc.socialLinks || []).forEach(l => l.url && links.push(l.url));
    } catch (e) { /* fall through to regex */ }
  }
  if (!links.length) {
    for (const mm of html.matchAll(/href="(https?:\/\/[^"]+)"/g)) links.push(mm[1]);
  }
  return {
    platform: 'linktree', url: `https://linktr.ee/${username}`, result: 'FOUND',
    data: { name, bio, links: [...new Set(links)].filter(u => !/linktr\.ee/.test(u)).slice(0, 50) },
  };
}

async function enrichMastodon(username) {
  const res = await fetchApi(`https://mastodon.social/api/v1/accounts/lookup?acct=${encodeURIComponent(username)}`);
  if (!res.ok) return null;
  const j = await res.json().catch(() => null);
  if (!j || !j.id) return null;
  return {
    platform: 'mastodon', url: j.url, result: 'FOUND',
    data: {
      display: j.display_name || null, username: j.username,
      bio: (j.note || '').replace(/<[^>]+>/g, '') || null,
      followers: j.followers_count, posts: j.statuses_count,
      created_at: j.created_at, avatar: j.avatar || null,
    },
  };
}

async function enrichBluesky(username) {
  const r = await probeBluesky(username);
  return r.result === 'FOUND' ? r : null;
}

async function enrichAnyProfilePage(username, platform) {
  // Generic: fetch the FOUND profile page and extract title/meta/og-tags + outbound social links
  const cfg = PLATFORMS[platform];
  if (!cfg || !cfg.url) return null;
  const url = cfg.url.replace('{}', encodeURIComponent(username));
  const res = await fetchSafe(url);
  if (!res.ok) return null;
  const html = await res.text();
  const get = re => { const m = html.match(re); return m ? m[1].trim().slice(0, 300) : null; };
  const socialLinks = [...new Set(
    [...html.matchAll(/href="(https?:\/\/[^"]*(?:twitter\.com|x\.com|instagram\.com|t\.me|facebook\.com|linkedin\.com|youtube\.com|github\.com|tiktok\.com|threads\.net)[^"]*)"/gi)]
      .map(m => m[1])
  )].slice(0, 30);
  return {
    platform, url, result: 'FOUND',
    data: {
      page_title: get(/<title[^>]*>([^<]+)<\/title>/i),
      og_title: get(/property="og:title"\s+content="([^"]+)"/i),
      og_description: get(/property="og:description"\s+content="([^"]+)"/i),
      description: get(/<meta\s+name="description"\s+content="([^"]+)"/i),
      og_image: get(/property="og:image"\s+content="([^"]+)"/i),
      social_links: socialLinks,
    },
  };
}

const ENRICHERS = {
  github: enrichGithub,
  gitlab: enrichGitlab,
  reddit: enrichReddit,
  linktree: enrichLinktree,
  mastodon: enrichMastodon,
  bluesky: enrichBluesky,
};

async function enrich(username, foundPlatforms) {
  const tasks = [];
  for (const p of foundPlatforms) {
    if (ENRICHERS[p]) tasks.push(Promise.resolve(ENRICHERS[p](username)).catch(() => null));
    else if (PLATFORMS[p] && PLATFORMS[p].url) tasks.push(enrichAnyProfilePage(username, p).catch(() => null));
  }
  const settled = await Promise.allSettled(tasks);
  return settled.map(s => (s.status === 'fulfilled' && s.value) || null).filter(Boolean);
}

// ------------------------------------------------------------------
// URL handling — extract username + platform from a social link
// ------------------------------------------------------------------
const URL_PATTERNS = [
  ['github',        /github\.com\/([A-Za-z0-9-]+)/],
  ['gitlab',        /gitlab\.com\/([A-Za-z0-9._-]+)/],
  ['reddit',        /reddit\.com\/(?:user|u)\/([A-Za-z0-9_-]+)/],
  ['instagram',     /instagram\.com\/([A-Za-z0-9._]+)/],
  ['tiktok',        /tiktok\.com\/@([A-Za-z0-9._]+)/],
  ['twitter',       /(?:twitter|x)\.com\/([A-Za-z0-9_]+)/],
  ['x',             /(?:twitter|x)\.com\/([A-Za-z0-9_]+)/],
  ['youtube',       /youtube\.com\/@([A-Za-z0-9._-]+)/],
  ['twitch',        /twitch\.tv\/([A-Za-z0-9_]+)/],
  ['telegram',      /t\.me\/([A-Za-z0-9_]+)/],
  ['steam',         /steamcommunity\.com\/id\/([A-Za-z0-9_-]+)/],
  ['soundcloud',    /soundcloud\.com\/([A-Za-z0-9_-]+)/],
  ['medium',        /medium\.com\/@([A-Za-z0-9_-]+)/],
  ['devto',         /dev\.to\/([A-Za-z0-9_]+)/],
  ['linkedin',      /linkedin\.com\/in\/([A-Za-z0-9-]+)/],
  ['pinterest',     /pinterest\.com\/([A-Za-z0-9_]+)/],
  ['behance',       /behance\.net\/([A-Za-z0-9_]+)/],
  ['dribbble',      /dribbble\.com\/([A-Za-z0-9_]+)/],
  ['mastodon',      /mastodon\.(?:social|online|world)\/@([A-Za-z0-9_]+)/],
  ['bluesky',       /bsky\.app\/profile\/([A-Za-z0-9._-]+)/],
  ['substack',      /([A-Za-z0-9-]+)\.substack\.com/],
  ['linktree',      /linktr\.ee\/([A-Za-z0-9._-]+)/],
  ['wordpress',     /([A-Za-z0-9-]+)\.wordpress\.com/],
  ['blogspot',      /([A-Za-z0-9-]+)\.blogspot\.com/],
  ['bandcamp',      /([A-Za-z0-9-]+)\.bandcamp\.com/],
  ['itch',          /([A-Za-z0-9-]+)\.itch\.io/],
  ['gumroad',       /([A-Za-z0-9-]+)\.gumroad\.com/],
  ['aboutme',       /about\.me\/([A-Za-z0-9._-]+)/],
  ['spotify',       /open\.spotify\.com\/user\/([A-Za-z0-9_]+)/],
  ['deviantart',    /([A-Za-z0-9-]+)\.deviantart\.com/],
];

function extractFromUrl(inputUrl) {
  for (const [platform, re] of URL_PATTERNS) {
    const m = String(inputUrl).match(re);
    if (m) return { platform, username: m[1] };
  }
  return null;
}

// ------------------------------------------------------------------
// Scrape a page for ALL outbound social links (cross-platform discovery)
// ------------------------------------------------------------------
async function harvestLinks(pageUrl) {
  const res = await fetchSafe(pageUrl);
  if (!res.ok) return { page: pageUrl, error: `HTTP ${res.status}`, social_links: [], all_links: [] };
  const html = await res.text();
  const allLinks = [...new Set(
    [...html.matchAll(/href="(https?:\/\/[^"]+)"/g)]
      .map(m => m[1])
      .filter(u => !/\.(css|js|png|jpe?g|svg|ico|woff2?)(\?|$)/i.test(u))
  )];

  const socialFound = [];
  const seen = new Set();
  for (const link of allLinks) {
    const hit = extractFromUrl(link);
    if (hit && !seen.has(hit.platform + hit.username)) {
      seen.add(hit.platform + hit.username);
      socialFound.push({ platform: hit.platform, url: link, username: hit.username });
    }
  }
  const get = re => { const m = html.match(re); return m ? m[1].trim() : null; };
  return {
    page: pageUrl,
    title: get(/<title[^>]*>([^<]+)<\/title>/i),
    og_description: get(/property="og:description"\s+content="([^"]+)"/i),
    social_links: socialFound,
    all_links: allLinks.slice(0, 200),
  };
}

// ------------------------------------------------------------------
// Runner — sweep platforms with concurrency + polite pacing
// ------------------------------------------------------------------
async function sweep(username, { concurrency = 8, platforms = Object.keys(PLATFORMS), delayMs = 250 } = {}) {
  const results = [];
  let i = 0;
  async function worker() {
    while (i < platforms.length) {
      const name = platforms[i++];
      const r = await probePlatform(name, username);
      if (r) {
        results.push(r);
        console.log(ASCII.progress(name, r.result, r.status));
      }
      if (delayMs) await sleep(delayMs);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, platforms.length) }, worker));
  return results.sort((a, b) => a.platform.localeCompare(b.platform));
}

// ------------------------------------------------------------------
// Full investigation pipeline (with optional alias chasing)
// ------------------------------------------------------------------
async function investigate(username, { sourceUrl = null, fullMode = false, aliasLimit = 5 } = {}) {
  console.log('\n' + ASCII.reportHeader(username));
  console.log(`\n[1/4] Sweeping "${username}" across ${Object.keys(PLATFORMS).length} platforms...\n`);
  const results = await sweep(username);
  const enriched = [];
  const harvestedAliases = [];   // [{platform, username, url}]
  const harvestedPages = [];     // raw harvests from profile pages

  let found = results.filter(r => r.result === 'FOUND');
  const missCount = results.filter(r => r.result === 'NOT_FOUND').length;
  const unknownCount = results.filter(r => r.result === 'UNKNOWN').length;
  console.log(ASCII.divider);
  console.log(ASCII.found(found.length));
  console.log(ASCII.miss(missCount));
  console.log(ASCII.unknown(unknownCount));
  console.log(ASCII.divider);
  console.log(`\n[+] Found on ${found.length} platforms: ${found.map(m => m.platform).join(', ') || '(none)'}`);

  // --- enrich ---
  console.log('\n[2/4] Enriching profiles (public APIs + page scraping)...');
  (await enrich(username, found.map(r => r.platform))).forEach(e => enriched.push(e));
  console.log(`   Enriched ${enriched.length} profiles.`);

  // --- harvest links from hub profiles ---
  console.log('\n[3/4] Harvesting outbound links from hub profiles (linktree, about.me, github)...');
  const hubTargets = ['linktree', 'aboutme', 'gumroad', 'github', 'mastodon']
    .filter(p => results.find(r => r.platform === p && r.result === 'FOUND'));

  for (const p of hubTargets.slice(0, 3)) {
    const e = enriched.find(x => x.platform === p);
    const url = (e && e.url) || PLATFORMS[p].url.replace('{}', encodeURIComponent(username));
    console.log(`   Harvesting ${p}: ${url}`);
    const h = await harvestLinks(url).catch(err => ({ page: url, error: String(err), social_links: [] }));
    if (h && !h.error && h.social_links.length) {
      harvestedPages.push(h);
      h.social_links.forEach(s => harvestedAliases.push(s));
      console.log(`   -> ${h.social_links.length} social links: ${h.social_links.map(s => s.platform).join(', ')}`);
    }
  }

  // --- alias chasing (fullMode) ---
  if (fullMode && harvestedAliases.length) {
    console.log(`\n[4/4] Full mode: chasing up to ${aliasLimit} discovered aliases across ALL platforms...`);
    const seenAliases = new Set([username.toLowerCase()]);
    let chased = 0;
    for (const alias of harvestedAliases) {
      if (chased >= aliasLimit) break;
      const a = alias.username;
      if (!a || seenAliases.has(a.toLowerCase()) || !PLATFORMS[alias.platform]) continue;
      seenAliases.add(a.toLowerCase());
      chased++;
      console.log(`\n   >> Alias "@${a}" (from ${alias.platform}) - full sweep...`);
      const aliasResults = await sweep(a, { delayMs: 150 });
      aliasResults.forEach(r => { r.alias_of = username; r.username = a; results.push(r); });
      const aliasFound = aliasResults.filter(r => r.result === 'FOUND');
      const aliasEnriched = await enrich(a, aliasFound.map(r => r.platform));
      aliasEnriched.forEach(e => { e.alias_of = username; e.username = a; enriched.push(e); });
      console.log(`   -> found on ${aliasFound.length} platforms`);
    }
  } else if (!fullMode) {
    console.log('\n[i] Tip: run with --full to also chase every discovered alias across all platforms.');
  }

  return {
    query: username,
    source_url: sourceUrl,
    results,
    enriched,
    link_harvest: harvestedPages,
    discovered_aliases: harvestedAliases,
  };
}

// ------------------------------------------------------------------
// Storage
// ------------------------------------------------------------------
function sanitizeQuery(q) { return String(q).replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 60); }

function store(report) {
  const dir = path.join(process.cwd(), 'output');
  fs.mkdirSync(dir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const base = `person-${sanitizeQuery(report.query)}-${stamp}`;

  // de-duplicate matches per platform+username
  const seen = new Set();
  const matches = report.results.filter(r => {
    if (r.result !== 'FOUND') return false;
    const key = r.platform + '|' + (r.username || report.query);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const out = {
    query: report.query,
    source_url: report.source_url || null,
    generated_at: new Date().toISOString(),
    summary: {
      total_checks: report.results.length,
      found: matches.length,
      unknown: report.results.filter(r => r.result === 'UNKNOWN').length,
      aliases_discovered: (report.discovered_aliases || []).length,
    },
    matches,
    unknown: report.results.filter(r => r.result === 'UNKNOWN'),
    enriched_profiles: report.enriched,
    discovered_aliases: report.discovered_aliases || [],
    link_harvest: report.link_harvest || [],
    all_checks: report.results,
  };

  fs.writeFileSync(path.join(dir, base + '.json'), JSON.stringify(out, null, 2));

  // Markdown report
  const md = [];
  md.push('```');
  md.push('  +---------------------------------------------------------------+');
  md.push(`  |  PERSON TRACKER :: TARGET "${sanitizeQuery(report.query).slice(0, 30).padEnd(30)}"  |`);
  md.push('  +---------------------------------------------------------------+');
  md.push('        \\   ^__^');
  md.push('         \\  (oo)\\_______');
  md.push('            (__)\\       )\\/\\');
  md.push('                ||----w |');
  md.push('                ||     ||    ~ trace complete ~');
  md.push('```');
  md.push(`# Person Report: ${report.query}`);
  md.push(`\n_Generated: ${out.generated_at}_`);
  if (report.source_url) md.push(`\n_Source link: ${report.source_url}_`);
  md.push(`\n**Found on ${out.summary.found} platforms** (${out.summary.unknown} unknown/limited, ${out.summary.aliases_discovered} aliases discovered)\n`);

  md.push('\n## Matches\n');
  md.push('| Platform | Username | URL | Status |');
  md.push('|---|---|---|---|');
  matches.forEach(m => md.push(`| ${m.platform} | ${m.username || report.query} | ${m.url || ''} | ${m.status} |`));

  md.push('\n## By category\n');
  for (const [grp, label] of GROUP_LABELS) {
    const g = matches.filter(m => m.group === grp);
    if (g.length) md.push(`- **${label}**: ${g.map(m => m.platform + (m.username && m.username !== report.query ? ` (@${m.username})` : '')).join(', ')}`);
  }

  if (report.discovered_aliases && report.discovered_aliases.length) {
    md.push('\n## Discovered aliases / cross-links\n');
    report.discovered_aliases.forEach(a => md.push(`- ${a.platform}: @${a.username} — ${a.url}`));
  }

  if (report.enriched.length) {
    md.push('\n## Profile details\n');
    report.enriched.forEach(e => {
      md.push(`### ${e.platform}${e.username && e.username !== report.query ? ` (@${e.username})` : ''}`);
      md.push(`URL: ${e.url}\n`);
      Object.entries(e.data || {}).forEach(([k, v]) => {
        if (v == null || v === '' || (Array.isArray(v) && !v.length)) return;
        if (Array.isArray(v)) {
          md.push(`- **${k}**:`);
          v.forEach(item => md.push(`  - ${typeof item === 'object' ? JSON.stringify(item) : item}`));
        } else {
          md.push(`- **${k}**: ${v}`);
        }
      });
      md.push('');
    });
  }

  if (out.unknown.length) {
    md.push('\n## Unknown (rate-limited / login-walled — check manually)\n');
    out.unknown.forEach(m => md.push(`- ${m.platform} (${m.status})${m.note ? ' — ' + m.note : ''}`));
  }

  fs.writeFileSync(path.join(dir, base + '.md'), md.join('\n'));
  console.log('\n' + [
    '  +-----------------------------------------------------------+',
    '  |               T R A C E   C O M P L E T E                |',
    '  +-----------------------------------------------------------+',
    `  |  target:        ${String(report.query).slice(0, 37).padEnd(37)}|`,
    `  |  hits:          ${String(out.summary.found).padEnd(37)}|`,
    `  |  limited:       ${String(out.summary.unknown).padEnd(37)}|`,
    `  |  aliases found: ${String(out.summary.aliases_discovered).padEnd(37)}|`,
    '  +-----------------------------------------------------------+',
    `  |  saved: output/${base.slice(0, 42).padEnd(42)}|`,
    '  +-----------------------------------------------------------+',
  ].join('\n'));
  return out;
}

// ------------------------------------------------------------------
// Combined report for multiple links/usernames (--multi)
// ------------------------------------------------------------------
async function multi(targets) {
  printBanner();
  console.log(`\n[#] Combined investigation of ${targets.length} targets...\n`);
  const reports = [];
  const allAliases = new Map(); // lowercase username -> username

  for (let i = 0; i < targets.length; i++) {
    const t = targets[i];
    let username = t, sourceUrl = null;
    if (/^https?:\/\//i.test(t)) {
      const hit = extractFromUrl(t);
      if (!hit) { console.log(`[!] Skipping unrecognised URL: ${t}`); continue; }
      username = hit.username;
      sourceUrl = t;
      console.log(`[+] [${i + 1}/${targets.length}] ${hit.platform} profile detected: @${username}`);
    } else {
      console.log(`>> [${i + 1}/${targets.length}] username: ${username}`);
    }
    const rep = await investigate(username, { sourceUrl, fullMode: true });
    reports.push(rep);

    allAliases.set(username.toLowerCase(), username);
    (rep.discovered_aliases || []).forEach(a => {
      if (!allAliases.has(a.username.toLowerCase())) allAliases.set(a.username.toLowerCase(), a.username);
    });
    await sleep(1000); // politeness between targets
  }

  // ---- combined report ----
  const dir = path.join(process.cwd(), 'output');
  fs.mkdirSync(dir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const base = `person-combined-${stamp}`;

  // unique matches across all targets, per platform+username
  const seen = new Set();
  const allMatches = [];
  for (const rep of reports) {
    for (const r of rep.results) {
      if (r.result !== 'FOUND') continue;
      const key = r.platform + '|' + (r.username || rep.query);
      if (seen.has(key)) continue;
      seen.add(key);
      allMatches.push({ ...r, target: rep.query });
    }
  }
  const allEnriched = reports.flatMap(r => r.enriched);

  const combined = {
    mode: 'multi-target combined report',
    targets: reports.map(r => ({ query: r.query, source_url: r.source_url })),
    generated_at: new Date().toISOString(),
    identity_map: [...allAliases.values()],
    summary: {
      targets: reports.length,
      total_unique_matches: allMatches.length,
      aliases: allAliases.size,
    },
    matches: allMatches,
    enriched_profiles: allEnriched,
    per_target: reports.map(r => ({ query: r.query, found: r.results.filter(x => x.result === 'FOUND').length })),
  };
  fs.writeFileSync(path.join(dir, base + '.json'), JSON.stringify(combined, null, 2));

  const md = [];
  md.push(`# Combined Person Report`);
  md.push(`\n_Generated: ${combined.generated_at}_`);
  md.push(`\n**Targets:** ${combined.targets.map(t => t.query).join(', ')}`);
  md.push(`\n**Likely identity aliases:** ${combined.identity_map.join(', ')}`);
  md.push(`\n**Total unique matches: ${combined.summary.total_unique_matches}**\n`);
  md.push('\n## All matches\n');
  md.push('| Platform | Username | URL | Target |');
  md.push('|---|---|---|---|');
  allMatches.forEach(m => md.push(`| ${m.platform} | ${m.username || m.target} | ${m.url || ''} | ${m.target} |`));
  if (allEnriched.length) {
    md.push('\n## Profile details\n');
    allEnriched.forEach(e => {
      md.push(`### ${e.platform} (@${e.username || '—'})`);
      Object.entries(e.data || {}).forEach(([k, v]) => {
        if (v == null || v === '' || (Array.isArray(v) && !v.length)) return;
        md.push(Array.isArray(v) ? `- **${k}**: ${v.map(String).join(', ')}` : `- **${k}**: ${v}`);
      });
      md.push('');
    });
  }
  fs.writeFileSync(path.join(dir, base + '.md'), md.join('\n'));

  console.log(`\n[+] Combined report saved: output/${base}.json and output/${base}.md`);
  console.log(`\n=== COMBINED SUMMARY ===`);
  console.log(`Targets:            ${combined.summary.targets}`);
  console.log(`Identity aliases:   ${combined.identity_map.join(', ')}`);
  console.log(`Unique matches:     ${combined.summary.total_unique_matches}`);
}

// ------------------------------------------------------------------
// CLI
// ------------------------------------------------------------------
async function main() {
  const args = process.argv.slice(2);

  if (!args.length) {
    printBanner();
    console.log(`OSINT across ${Object.keys(PLATFORMS).length} platforms (zero deps, Node >= 18)

  ::::::::::::::::::::  M O D E S  ::::::::::::::::::::

    <username>                        full sweep + enrich + store
    --full    <username>              ALSO chase every discovered alias
    --url     <profile-url>           start from a social link
    --full --url <profile-url>        social link + alias chasing
    --multi   <url|user> <url|user>   combined report for many links
    --links   <profile-url>           only harvest links from a page
    --site    github <user>           single platform check + detail
    --email   <email>                 email-based lookups (gravatar)
    --list                           list all supported platforms

  Output: output/person-<query>-<timestamp>.json + .md
  [!] Legal & ethical use only - public data, consent, self-checks.`);
    process.exit(1);
  }

  // --list
  if (args[0] === '--list') {
    printBanner();
    console.log(`Supported platforms (${Object.keys(PLATFORMS).length}):\n`);
    for (const [grp, label] of GROUP_LABELS) {
      const ps = Object.entries(PLATFORMS).filter(([, c]) => c.group === grp).map(([n]) => n);
      if (ps.length) console.log(`  ${label}: ${ps.join(', ')}`);
    }
    return;
  }

  // --links <url>: harvest only
  if (args[0] === '--links' && args[1]) {
    const h = await harvestLinks(args[1]);
    console.log(JSON.stringify(h, null, 2));
    return;
  }

  // --site <platform> <username>
  if (args[0] === '--site' && args.length >= 3) {
    const [, name, username] = args;
    if (!PLATFORMS[name]) { console.error(`Unknown platform: ${name}. Use --list.`); process.exit(1); }
    const r = await probePlatform(name, username);
    console.log(JSON.stringify(r, null, 2));
    if (r && r.result === 'FOUND' && ENRICHERS[name]) {
      const e = await ENRICHERS[name](username).catch(() => null);
      if (e) console.log(JSON.stringify(e, null, 2));
    }
    return;
  }

  // --email <email>
  if (args[0] === '--email' && args[1]) {
    const email = args[1];
    const results = [await probeGravatar(email)];
    const enriched = results.filter(r => r.data);
    store({ query: email, results, enriched, discovered_aliases: [], link_harvest: [] });
    return;
  }

  // --multi <targets...>
  if (args[0] === '--multi' && args.length >= 2) {
    await multi(args.slice(1));
    return;
  }

  // --full and/or --url
  const fullMode = args.includes('--full');
  const urlIdx = args.indexOf('--url');

  if (urlIdx >= 0 && args[urlIdx + 1]) {
    const inputUrl = args[urlIdx + 1];
    const hit = extractFromUrl(inputUrl);
    if (!hit) { console.error('Could not recognise any platform in that URL.'); process.exit(1); }
    console.log(`[+] Detected ${hit.platform} profile: @${hit.username}`);
    const rep = await investigate(hit.username, { sourceUrl: inputUrl, fullMode });
    store(rep);
    return;
  }

  const username = args.find(a => !a.startsWith('--'));
  if (!username) { console.error('No username given.'); process.exit(1); }
  const rep = await investigate(username, { fullMode });
  store(rep);
}

main().catch(e => {
  console.error('Failed:', e && e.stack ? e.stack.split('\n').slice(0, 3).join('\n') : e);
  process.exit(1);
});
