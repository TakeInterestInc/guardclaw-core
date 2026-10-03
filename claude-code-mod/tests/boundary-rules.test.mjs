// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {checkCommand,degradedVerdict} from '../hooks/rules.ts';
// Pure predicates only. No command in this test is executed.
test('cwd and expansion-bearing mutations fail closed in both modes',()=>{
 for(const command of ['cd "$HOME" && rm -rf Documents','S="$HOME/go/bin/guardclaw-scan"; cp ./fake "$S"','cd "$HOME/.claude" && cp ./replacement.json settings.json','env -C /home/synthetic rm -rf Documents','env -C/home/synthetic rm -rf Documents','sudo -D/home/synthetic rm -rf Documents','chroot /home/synthetic rm -rf Documents','pushd /home/synthetic; rm -rf Documents','echo data > "$DEST"']) {
  assert.ok(checkCommand(command,'/project/plugin',[],'/home/synthetic',['/home/synthetic/go/bin/guardclaw-scan']));
  assert.ok(degradedVerdict(command,'/project/plugin',[],'/home/synthetic',['/home/synthetic/go/bin/guardclaw-scan']));
 }
});
test('ordinary documented agent workflows retain lexical behavior',()=>{
 for(const command of ['cd src && echo install','cd src && sed -n 1,10p README.md','sed -n "$RANGE" README.md','cd src && npm test','rm -rf ./build','cp ./input ./output','echo $(date)','npm test | tee test.log','go test ./... 2>&1 | tail',"find . -name '*.pyc' -delete"]) assert.equal(checkCommand(command),undefined);
});
