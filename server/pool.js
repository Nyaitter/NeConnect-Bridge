'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

class BridgePool {
  constructor(file, maxClients) {
    this.file = file;
    this.maxClients = maxClients;
    this.entries = [];
    this.load();
  }

  load() {
    let raw;
    try {
      raw = fs.readFileSync(this.file, 'utf8');
    } catch {
      this.entries = [];
      return;
    }
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      this.entries = [];
      return;
    }
    this.entries = Array.isArray(parsed) ? parsed.map((entry) => this.normalize(entry)) : [];
  }

  normalize(entry) {
    const clients = {};
    if (entry && entry.clients && typeof entry.clients === 'object') {
      for (const key of Object.keys(entry.clients)) clients[key] = true;
    }
    return {
      url: entry.url,
      owner_id: entry.owner_id || 0,
      owner_handle: entry.owner_handle || '',
      owner_name: entry.owner_name || '',
      clients,
      added_at: entry.added_at || Math.floor(Date.now() / 1000),
    };
  }

  save() {
    const body = JSON.stringify(this.entries, null, 2);
    fs.writeFileSync(this.file, body, { mode: 0o600 });
  }

  countClients(entry) {
    return Object.keys(entry.clients).length;
  }

  pick(cid) {
    const eligible = this.entries.filter(
      (entry) => this.countClients(entry) < this.maxClients && !entry.clients[cid],
    );
    if (eligible.length === 0) return null;
    const chosen = eligible[crypto.randomInt(eligible.length)];
    chosen.clients[cid] = true;
    this.save();
    return chosen.url;
  }

  find(url) {
    return this.entries.find((entry) => entry.url === url);
  }

  add({ url, ownerId = 0, ownerHandle = '', ownerName = '' }) {
    const existing = this.find(url);
    if (existing) return { entry: existing, duplicate: true };
    const entry = {
      url,
      owner_id: ownerId,
      owner_handle: ownerHandle,
      owner_name: ownerName,
      clients: {},
      added_at: Math.floor(Date.now() / 1000),
    };
    this.entries.push(entry);
    this.save();
    return { entry, duplicate: false };
  }

  remove(url) {
    const before = this.entries.length;
    this.entries = this.entries.filter((entry) => entry.url !== url);
    if (this.entries.length === before) return false;
    this.save();
    return true;
  }

  removeOwned(url, ownerId) {
    const before = this.entries.length;
    this.entries = this.entries.filter((entry) => !(entry.url === url && entry.owner_id === ownerId));
    if (this.entries.length === before) return false;
    this.save();
    return true;
  }

  reset(url) {
    const targets = url ? this.entries.filter((entry) => entry.url === url) : this.entries;
    for (const entry of targets) entry.clients = {};
    this.save();
    return targets.length;
  }

  setMax(value) {
    this.maxClients = value;
  }

  list() {
    return this.entries.map((entry) => ({
      url: entry.url,
      used: this.countClients(entry),
      max: this.maxClients,
      owner_handle: entry.owner_handle,
      added_at: entry.added_at,
    }));
  }
}

module.exports = { BridgePool };
