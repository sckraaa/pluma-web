// Tests of the choice of a path to the server (pathChoice.ts of ci/patch.py, W-087), run by
// ci/patch_test.py with Node.js, which strips the types: PATH_CHOICE names the file to test.
import assert from 'node:assert/strict';
import {test} from 'node:test';

const m = await import(process.env.PATH_CHOICE);

const nonce = Uint8Array.from({length: 16}, (_, i) => i);
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const BRIEF = {
  v: 1, country: 'RU', gate_down: 65536, rank_down: 196608, up: 20480,
  stall_ms: 1500, deadline_ms: 6000, suspect_ms: 4000, reprobe_s: 21600,
  rank_min_interval_s: 1800, min_dwell_s: 600, switch_ratio: 0.7, switch_ratio_now: 0.25,
  edge_probe_if_direct_ms: 1500, bad_ttl_s: 86400, failed_ttl_s: 300,
  race_stagger_ms: 800, confirm_s: 60
};
const SETTINGS = m.parseProbeConfig(BRIEF).settings;
const SERVER = 'wss://web.pluma.example/apiws';
const RU = 'wss://ru.edge.example/apiws';
const GCORE = 'wss://g1.cdn.example/apiws';

// pluma.probeData as the gateway makes it (pkg/mtserver/handshake/probe.go, ProbeData), in an
// unencrypted message.
function probeData(seq, total, pad, n = nonce) {
  const prefix = pad < 254 ? 1 : 4;
  const length = 4 + 16 + 4 + 4 + 8 + ((prefix + pad + 3) & ~3);
  const out = new Uint8Array(20 + length);
  const view = new DataView(out.buffer);
  view.setUint32(8, 0x12345679, true);
  view.setUint32(16, length, true);
  view.setUint32(20, 0x6ab3780b, true);
  out.set(n, 24);
  view.setInt32(40, seq, true);
  view.setInt32(44, total, true);
  view.setUint32(48, 1763500000, true);
  if(prefix === 1) {
    out[56] = pad;
  } else {
    out.set([254, pad & 0xff, (pad >> 8) & 0xff, pad >> 16], 56);
  }
  return out;
}

// The pluma.probeData of an answer to down bytes.
function answerTo(down) {
  const d = m.clampDown(down);
  const total = Math.ceil(d / 16384);
  return Array.from({length: total}, (_, seq) => probeData(seq, total, seq < total - 1 ? 16384 : d - 16384 * (total - 1)));
}

function abridged(packet) {
  const words = packet.length / 4;
  const head = words < 127 ? [words] : [0x7f, words & 0xff, (words >> 8) & 0xff, words >> 16];
  return Uint8Array.from([...head, ...packet]);
}

test('pluma_probe: the brief values', () => {
  const {settings, country} = m.parseProbeConfig(BRIEF);
  assert.equal(country, 'RU');
  for(const key of Object.keys(BRIEF)) {
    if(key !== 'v' && key !== 'country') assert.equal(settings[key], BRIEF[key], key);
  }
  assert.deepEqual(m.parseProbeConfig({v: 1}).settings, {...m.PROBE_DEFAULTS});
  assert.deepEqual({...m.PROBE_DEFAULTS}, SETTINGS);
});

test('pluma_probe: a field out of range or of the wrong kind takes its default', () => {
  for(const [key, value] of [
    ['gate_down', 1000], ['gate_down', 600000], ['gate_down', 65536.5], ['gate_down', '65536'],
    ['up', -1], ['up', 70000], ['stall_ms', 100], ['reprobe_s', Infinity], ['confirm_s', NaN],
    ['switch_ratio', 1], ['switch_ratio_now', 0.01], ['race_stagger_ms', null]
  ]) {
    const {settings} = m.parseProbeConfig({...BRIEF, [key]: value});
    assert.equal(settings[key], m.PROBE_DEFAULTS[key], `${key} ${value}`);
  }
  const {settings} = m.parseProbeConfig({...BRIEF, gate_down: 32768, switch_ratio: 0.8, up: 0, race_stagger_ms: 0});
  assert.equal(settings.gate_down, 32768);
  assert.equal(settings.switch_ratio, 0.8);
  assert.equal(settings.up, 0);
  assert.equal(settings.race_stagger_ms, 0);
});

test('pluma_probe: pairs that contradict each other go back to the defaults', () => {
  let {settings} = m.parseProbeConfig({...BRIEF, stall_ms: 5000, deadline_ms: 5000});
  assert.equal(settings.stall_ms, 1500);
  assert.equal(settings.deadline_ms, 6000);
  ({settings} = m.parseProbeConfig({...BRIEF, switch_ratio: 0.5, switch_ratio_now: 0.6}));
  assert.equal(settings.switch_ratio, 0.7);
  assert.equal(settings.switch_ratio_now, 0.25);
});

test('pluma_probe: the country and the version', () => {
  assert.equal(m.parseProbeConfig({...BRIEF, country: ''}).country, '');
  assert.equal(m.parseProbeConfig({...BRIEF, country: 'ru'}).country, '');
  assert.equal(m.parseProbeConfig({...BRIEF, country: 'RUS'}).country, '');
  assert.equal(m.parseProbeConfig({...BRIEF, country: 7}).country, '');
  for(const value of [undefined, null, 1, 'x', [], {...BRIEF, v: 2}, {...BRIEF, v: '1'}]) {
    assert.equal(m.parseProbeConfig(value), undefined, JSON.stringify(value));
  }
});

test('pluma_edge: the build\'s edges the server lists, and the order', () => {
  const built = [GCORE, RU];
  assert.deepEqual(m.parseEdgeConfig({v: 1, ws: [RU, 'wss://other.example/apiws', RU, 5], order: ['edge', 'direct'], sticky_s: 1800}, built),
    {edgesFirst: true, edges: [RU]});
  assert.deepEqual(m.parseEdgeConfig({v: 1, ws: [GCORE, RU], order: ['direct', 'edge']}, built), {edgesFirst: false, edges: [GCORE, RU]});
  assert.deepEqual(m.parseEdgeConfig({v: 1, ws: [], order: ['direct']}, built), {edgesFirst: false, edges: []});
  for(const value of [undefined, {v: 2, ws: [], order: []}, {v: 1, ws: 'x', order: []}, {v: 1, ws: []}]) {
    assert.equal(m.parseEdgeConfig(value, built), undefined);
  }
});

test('pluma.probe: the vectors of the contract', () => {
  assert.equal(hex(m.probeRequest(nonce, 65536, new Uint8Array(0))),
    '306d315c000102030405060708090a0b0c0d0e0f0000010000000000');
  const pad = new Uint8Array(20480).fill(7);
  const big = m.probeRequest(nonce, 65536, pad);
  // 4 + 16 + 4 and the pad: its 4 bytes of length and 20480 of data.
  assert.equal(big.length, 20508);
  assert.equal(hex(big.subarray(20, 28)), '00000100fe005000');
  assert.equal(big[28], 7);
  assert.equal(big[big.length - 1], 7);
  // A pad of 1 byte: its length, the byte and two zeros.
  assert.equal(hex(m.probeRequest(nonce, 16384, Uint8Array.of(9)).subarray(24)), '01090000');
  assert.equal(hex(m.reqPqMulti(nonce)), 'f18e7ebe000102030405060708090a0b0c0d0e0f');
});

test('an unencrypted message: auth_key_id 0, a msg_id of the time, the length', () => {
  const now = 1763500000123;
  const message = m.plainMessage(Uint8Array.of(1, 2, 3, 4), now);
  const view = new DataView(message.buffer);
  assert.equal(message.length, 24);
  assert.equal(hex(message.subarray(0, 8)), '0000000000000000');
  assert.equal(view.getUint32(12, true), 1763500000);
  const fraction = view.getUint32(8, true);
  assert.equal(fraction % 4, 0);
  assert.ok(Math.abs(fraction / 2 ** 32 - 0.123) < 1e-6);
  assert.equal(view.getUint32(16, true), 4);
  assert.equal(hex(message.subarray(20)), '01020304');
});

test('the abridged stream, however it is cut', () => {
  const small = probeData(0, 1, 16);
  const large = answerTo(16384)[0];
  assert.equal(large.length, 16444);
  const stream = Uint8Array.from([...abridged(small), ...abridged(large), ...abridged(small)]);
  for(const step of [1, 3, 7, 1000, stream.length]) {
    const reader = new m.AbridgedReader();
    const packets = [];
    for(let i = 0; i < stream.length; i += step) {
      packets.push(...reader.push(stream.subarray(i, i + step)));
    }
    assert.deepEqual(packets.map((p) => p.length), [small.length, large.length, small.length], `step ${step}`);
    assert.equal(hex(packets[1]), hex(large));
  }
  assert.throws(() => new m.AbridgedReader().push(Uint8Array.of(0x80, 0, 0, 0)));
});

test('resPQ and the unencrypted envelope', () => {
  const resPQ = new Uint8Array(20 + 4 + 16 + 16);
  new DataView(resPQ.buffer).setUint32(16, 36, true);
  resPQ.set([0x63, 0x24, 0x16, 0x05], 20);
  resPQ.set(nonce, 24);
  const data = m.plainData(resPQ);
  assert.equal(data.length, 36);
  assert.ok(m.isResPQ(data, nonce));
  assert.ok(!m.isResPQ(data, new Uint8Array(16)));
  const encrypted = resPQ.slice();
  encrypted[3] = 1;
  assert.equal(m.plainData(encrypted), undefined);
  const long = resPQ.slice();
  new DataView(long.buffer).setUint32(16, 37, true);
  assert.equal(m.plainData(long), undefined);
  assert.equal(m.plainData(new Uint8Array(19)), undefined);
});

test('the answer: every message in order, the pads adding up', () => {
  for(const [down, sizes] of [[65536, [16384, 16384, 16384, 16384]], [20000, [16384, 3616]], [1000, [16384]], [600000, null]]) {
    const answer = new m.ProbeAnswer(down);
    const messages = answerTo(down);
    if(sizes) assert.deepEqual(messages.map((p) => m.parseProbeData(m.plainData(p), nonce).pad), sizes);
    const progress = messages.map((p) => answer.add(m.parseProbeData(m.plainData(p), nonce)));
    assert.deepEqual(progress, [...Array(messages.length - 1).fill('more'), 'done'], `down ${down}`);
    assert.equal(answer.received, m.clampDown(down));
  }

  const parse = (p, n = nonce) => m.parseProbeData(m.plainData(p), n);
  assert.equal(parse(probeData(0, 2, 16384), new Uint8Array(16)), 'pluma.probeData of another probe');
  let answer = new m.ProbeAnswer(65536);
  assert.match(answer.add(parse(probeData(1, 4, 16384))), /^pluma.probeData 1 of 4 after 0/);
  answer = new m.ProbeAnswer(65536);
  assert.equal(answer.add(parse(probeData(0, 4, 16384))), 'more');
  assert.match(answer.add(parse(probeData(1, 5, 16384))), /^pluma.probeData 1 of 5/);
  answer = new m.ProbeAnswer(65536);
  assert.equal(answer.add(parse(probeData(0, 2, 16384))), 'more');
  assert.equal(answer.add(parse(probeData(1, 2, 16384))), '32768 bytes of 65536');
  const truncated = probeData(0, 1, 16384).slice(0, 100);
  new DataView(truncated.buffer).setUint32(16, 80, true);
  assert.equal(parse(truncated), 'pad past the message');
  const other = probeData(0, 1, 16);
  other[20] ^= 1;
  assert.equal(parse(other), 'not pluma.probeData');
});

test('the meter: frozen, slow, failed and the speed', () => {
  // Nothing at all by the deadline: failed; never frozen without a byte.
  let meter = new m.ProbeMeter(1500);
  meter.wait(0, 0, 6000, false);
  assert.equal(meter.check(5999), undefined);
  assert.equal(meter.check(6000), 'failed');

  // The handshake, resPQ, then the answer stops: frozen 1.5 s after the last byte.
  meter = new m.ProbeMeter(1500);
  meter.wait(0, 0, 6000, false);
  meter.opened(100);
  meter.bytes(200, 80);
  meter.wait(210, 100, 6210, true);
  assert.equal(meter.check(1800), undefined);
  meter.bytes(400, 16448);
  assert.equal(meter.check(1899), undefined);
  assert.equal(meter.check(1900), 'frozen');

  // The request plus the round trip later than the last byte: the stall counts from it.
  meter = new m.ProbeMeter(1500);
  meter.wait(0, 0, 9000, false);
  meter.opened(0);
  meter.wait(1000, 800, 9000, true);
  assert.equal(meter.check(3299), undefined);
  assert.equal(meter.check(3300), 'frozen');

  // Bytes keep coming but not all by the deadline: slow.
  meter = new m.ProbeMeter(1500);
  meter.wait(0, 0, 6000, true);
  for(let t = 0; t <= 6000; t += 1000) {
    meter.bytes(t, 16448);
    if(t < 6000) assert.equal(meter.check(t + 999), undefined);
  }
  assert.equal(meter.check(6000), 'slow');
  // The speed: the bytes after the first read over the time from it to the last one.
  assert.equal(meter.bps(), 16448 * 6 / 6);
  assert.equal(meter.answerBytes, 16448 * 7);
  assert.equal(new m.ProbeMeter(1500).bps(), 0);
});

test('the score: the round trip and 256 KiB at the speed', () => {
  assert.equal(m.pathScore({outcome: 'ok', rtt: 50, bps: 262144, received: 0}), 1050);
  assert.equal(m.pathScore({outcome: 'slow', rtt: 50, bps: 131072, received: 0}), 2050);
  assert.equal(m.pathScore({outcome: 'ok', rtt: 50, bps: 0, received: 0}), Infinity);
  assert.equal(m.pathScore({outcome: 'frozen', rtt: 50, bps: 262144, received: 0}), Infinity);
  assert.ok(m.passed({outcome: 'slow'}) && !m.passed({outcome: 'unsupported'}));
});

const ok = (rtt, bps) => ({outcome: 'ok', rtt, bps, received: 65536});
const bad = (outcome) => ({outcome, rtt: 0, bps: 0, received: 0});

test('the memory: what is kept, what goes', () => {
  const now = 1_000_000_000;
  const net = {at: now - 5, paths: {}};
  m.recordProbe(net, RU, ok(40, 262144), now, SETTINGS);
  assert.equal(net.paths[RU].score, 1040);
  assert.equal(net.at, now);
  m.recordProbe(net, SERVER, bad('frozen'), now, SETTINGS);
  assert.equal(net.paths[SERVER].excludedUntil, now + 86400e3);
  assert.ok(m.isExcluded(net, SERVER, now + 86400e3 - 1));
  assert.ok(!m.isExcluded(net, SERVER, now + 86400e3));
  m.recordProbe(net, GCORE, bad('failed'), now, SETTINGS);
  assert.equal(net.paths[GCORE].excludedUntil, now + 300e3);
  m.recordProbe(net, GCORE, bad('unsupported'), now + 1, SETTINGS);
  assert.deepEqual(net.paths[GCORE].history, ['failed']);
  // A pass brings a path back and keeps the last four outcomes.
  m.recordProbe(net, SERVER, ok(10, 262144), now + 2, SETTINGS);
  assert.equal(net.paths[SERVER].excludedUntil, undefined);
  for(const outcome of ['failed', 'ok', 'ok', 'ok']) m.recordProbe(net, RU, outcome === 'ok' ? ok(40, 262144) : bad(outcome), now, SETTINGS);
  assert.deepEqual(net.paths[RU].history, ['failed', 'ok', 'ok', 'ok']);

  // Losses: two of the last four not ok double the score.
  assert.equal(m.effectiveScore({score: 100, history: ['ok', 'slow', 'ok', 'ok']}), 100);
  assert.equal(m.effectiveScore({score: 100, history: ['frozen', 'slow', 'ok', 'ok']}), 200);
  assert.equal(m.effectiveScore(undefined), Infinity);
  assert.equal(m.effectiveScore({history: ['ok']}), Infinity);
});

test('the memory as storage kept it', () => {
  const paths = [SERVER, RU];
  const kept = {
    v: 1, country: 'DE',
    networks: {
      DE: {at: 5, best: RU, ranked: 4, switched: 3, pending: {url: SERVER, at: 2},
        paths: {[RU]: {outcome: 'ok', at: 5, score: 900, history: ['ok', 'bogus', 'slow'], excludedUntil: 9},
          [GCORE]: {outcome: 'ok', at: 5, history: []}, [SERVER]: {outcome: 'weird', at: 5, history: []}}},
      RU: {at: 'x', paths: {}},
      xx: {at: 1, paths: {}},
      '': {at: 1, best: GCORE, paths: {}}
    }
  };
  const memory = m.readMemory(JSON.parse(JSON.stringify(kept)), paths);
  assert.deepEqual(memory, {
    v: 1, country: 'DE',
    networks: {
      DE: {at: 5, best: RU, ranked: 4, switched: 3, pending: {url: SERVER, at: 2},
        paths: {[RU]: {outcome: 'ok', at: 5, score: 900, history: ['ok', 'slow'], excludedUntil: 9}}},
      '': {at: 1, paths: {}}
    }
  });
  for(const value of [undefined, null, 'x', {v: 2, networks: {}}, {v: 1}]) {
    assert.deepEqual(m.readMemory(value, paths), {v: 1, networks: {}});
  }

  // At most 16 networks: the least recent go.
  const memory2 = {v: 1, networks: {}};
  for(let i = 0; i < 16; ++i) m.networkRecord(memory2, String.fromCharCode(65 + i) + 'A', 100 + i);
  m.networkRecord(memory2, 'ZZ', 1000);
  assert.equal(Object.keys(memory2.networks).length, 16);
  assert.ok(!('AA' in memory2.networks) && 'ZZ' in memory2.networks && 'BA' in memory2.networks);
  assert.ok(m.isFresh({at: 0}, 7 * 86400e3 - 1) && !m.isFresh({at: 0}, 7 * 86400e3) && !m.isFresh(undefined, 0));
});

test('the best of scored paths, ties to the country\'s order', () => {
  const order = m.preference(SERVER, [RU, GCORE], false);
  assert.deepEqual(order, [SERVER, RU, GCORE]);
  assert.deepEqual(m.preference(SERVER, [RU, GCORE], true), [RU, GCORE, SERVER]);
  assert.equal(m.pickBest([{url: RU, score: 100}, {url: SERVER, score: 300}], order), RU);
  // Within the tie ratio, the order wins.
  assert.equal(m.pickBest([{url: RU, score: 100}, {url: SERVER, score: 140}], order), SERVER);
  assert.equal(m.pickBest([{url: GCORE, score: 100}, {url: RU, score: 120}], order), RU);
  assert.equal(m.pickBest([{url: RU, score: Infinity}], order), undefined);
  assert.equal(m.pickBest([], order), undefined);
});

test('the race plan', () => {
  const none = () => false;
  assert.deepEqual(m.racePlan({candidates: [SERVER, RU, GCORE], current: SERVER, first: [SERVER], excluded: none}),
    {now: [SERVER], later: [RU, GCORE]});
  assert.deepEqual(m.racePlan({candidates: [RU, GCORE, SERVER], current: SERVER, first: [RU, GCORE], excluded: none}),
    {now: [RU, GCORE, SERVER], later: []});
  assert.deepEqual(m.racePlan({candidates: [SERVER, RU, GCORE], current: SERVER, best: GCORE, first: [SERVER], excluded: none}),
    {now: [SERVER, GCORE], later: [RU]});
  // A path out of races stays out while others are left; all out, all race.
  assert.deepEqual(m.racePlan({candidates: [SERVER, RU, GCORE], current: SERVER, first: [SERVER], excluded: (url) => url === SERVER}),
    {now: [RU, GCORE], later: []});
  assert.deepEqual(m.racePlan({candidates: [SERVER, RU], current: SERVER, first: [SERVER], excluded: () => true}),
    {now: [SERVER], later: [RU]});
});

test('a ranking probes the other edges only where they are needed', () => {
  assert.ok(!m.rankEdgesToo(false, ok(40, 1048576), SETTINGS));
  assert.ok(m.rankEdgesToo(true, ok(40, 1048576), SETTINGS));
  assert.ok(m.rankEdgesToo(false, undefined, SETTINGS));
  assert.ok(m.rankEdgesToo(false, bad('frozen'), SETTINGS));
  // 256 KiB at 128 KiB/s is 2 s: poorer than edge_probe_if_direct_ms.
  assert.ok(m.rankEdgesToo(false, ok(40, 131072), SETTINGS));
});

test('the rules that switch', () => {
  const order = [SERVER, RU, GCORE];
  const now = 10_000_000;
  const decide = (net, results, at = now, current = RU) => {
    results.forEach((result, url) => m.recordProbe(net, url, result, at, SETTINGS));
    return m.decideRank({net, current, results, order, now: at, settings: SETTINGS});
  };

  // Four times better: at once.
  let net = {at: 0, paths: {}};
  assert.deepEqual(decide(net, new Map([[SERVER, ok(20, 1048576)], [RU, ok(200, 262144)]])),
    {kind: 'switch', url: SERVER, emergency: false});

  // Twice better: a second ranking within the window confirms.
  net = {at: 0, paths: {}};
  const twice = () => new Map([[SERVER, ok(20, 524288)], [RU, ok(40, 262144)]]);
  assert.deepEqual(decide(net, twice()), {kind: 'confirm', url: SERVER});
  assert.deepEqual(net.pending, {url: SERVER, at: now});
  assert.deepEqual(decide(net, twice(), now + 60e3), {kind: 'switch', url: SERVER, emergency: false});
  assert.equal(net.pending, undefined);
  // Too late a second win is a first one again.
  net = {at: 0, paths: {}};
  decide(net, twice());
  assert.deepEqual(decide(net, twice(), now + 121e3), {kind: 'confirm', url: SERVER});

  // Within switch_ratio: stay, and a pending win is forgotten.
  net = {at: 0, paths: {}, pending: {url: SERVER, at: now}};
  assert.deepEqual(decide(net, new Map([[SERVER, ok(20, 262144)], [RU, ok(40, 262144)]])), {kind: 'stay'});
  assert.equal(net.pending, undefined);

  // Not within min_dwell_s of the last switch.
  net = {at: 0, paths: {}, switched: now - 599e3};
  assert.deepEqual(decide(net, new Map([[SERVER, ok(20, 1048576)], [RU, ok(200, 262144)]])), {kind: 'stay'});

  // The current path failing: the best other at once, whatever the dwell; none, stay.
  net = {at: 0, paths: {}, switched: now};
  assert.deepEqual(decide(net, new Map([[SERVER, ok(200, 262144)], [RU, bad('frozen')], [GCORE, ok(20, 1048576)]])),
    {kind: 'switch', url: GCORE, emergency: true});
  net = {at: 0, paths: {}};
  assert.deepEqual(decide(net, new Map([[SERVER, bad('failed')], [RU, bad('frozen')]])), {kind: 'stay'});

  // An unsupported probe of the current path is no verdict on it.
  net = {at: 0, paths: {}};
  assert.deepEqual(decide(net, new Map([[SERVER, ok(200, 262144)], [RU, bad('unsupported')]])), {kind: 'stay'});

  // Losses double the score: a path that keeps failing loses its lead.
  net = {at: 0, paths: {[SERVER]: {outcome: 'ok', at: 0, history: ['frozen', 'failed', 'ok']}}};
  assert.deepEqual(decide(net, new Map([[SERVER, ok(20, 1048576)], [RU, ok(200, 524288)]])), {kind: 'stay'});
});
