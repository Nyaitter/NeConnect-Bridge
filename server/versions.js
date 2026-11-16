'use strict';

const fs = require('fs');
const path = require('path');

const RELEASE_PATTERN = /^NeConnectBridge-(.+)\.exe$/i;

function compareVersions(a, b) {
  const left = a.split(/[.+-]/);
  const right = b.split(/[.+-]/);
  const length = Math.max(left.length, right.length);
  for (let i = 0; i < length; i += 1) {
    const l = left[i] === undefined ? 0 : Number(left[i]);
    const r = right[i] === undefined ? 0 : Number(right[i]);
    const lNum = Number.isFinite(l);
    const rNum = Number.isFinite(r);
    if (lNum && rNum) {
      if (l !== r) return r - l;
      continue;
    }
    if (lNum !== rNum) return lNum ? -1 : 1;
    const diff = String(right[i]).localeCompare(String(left[i]));
    if (diff !== 0) return diff;
  }
  return 0;
}

class ReleaseStore {
  constructor({ releasesDir, fallbackExe, fallbackVersion }) {
    this.releasesDir = releasesDir;
    this.fallbackExe = fallbackExe;
    this.fallbackVersion = fallbackVersion || '1.0.0';
  }

  list() {
    const found = [];
    let names = [];
    try {
      names = fs.readdirSync(this.releasesDir);
    } catch {
      names = [];
    }
    for (const name of names) {
      const match = RELEASE_PATTERN.exec(name);
      if (!match) continue;
      const file = path.join(this.releasesDir, name);
      let stat;
      try {
        stat = fs.statSync(file);
      } catch {
        continue;
      }
      if (!stat.isFile()) continue;
      found.push({
        version: match[1],
        file,
        size: stat.size,
        released_at: new Date(stat.mtimeMs).toISOString(),
      });
    }
    if (found.length === 0 && this.fallbackExe) {
      try {
        const stat = fs.statSync(this.fallbackExe);
        if (stat.isFile()) {
          found.push({
            version: this.fallbackVersion,
            file: this.fallbackExe,
            size: stat.size,
            released_at: new Date(stat.mtimeMs).toISOString(),
          });
        }
      } catch {
        // no fallback file
      }
    }
    return found.sort((a, b) => compareVersions(a.version, b.version));
  }

  latest() {
    const all = this.list();
    return all.length > 0 ? all[0] : null;
  }

  resolve(version) {
    const all = this.list();
    if (!version) return all.length > 0 ? all[0] : null;
    return all.find((item) => item.version === version) || null;
  }
}

module.exports = { ReleaseStore };
