import test from 'node:test';
import assert from 'node:assert/strict';
import { IPList } from '../src/IPList.js';

test('IPList basic add/contains/del', (t) => {
  const list = new IPList();
  const ip = { ipV4: '1.2.3.4' };

  // initially not contained
  assert.equal(list.contains(ip), false);

  // add with a ban duration and ensure a timestamp was set
  list.add(ip, 1000);
  const ts = list.getIpV4Timestamp('1.2.3.4');
  assert.equal(typeof ts, 'number');
  assert.ok(ts > 0, 'timestamp should be a positive number');
  assert.equal(list.contains(ip), true);

  // remove the IP and ensure it's gone
  list.del('1.2.3.4');
  assert.equal(list.contains(ip), false);
});
