// Copyright 2026 TakeInterest Inc. SPDX-License-Identifier: Apache-2.0
// Pure local event proposal. No writer, sender, endpoint or persistent identifier.
export function setupEvent({enabled=false,version}={}){
 if(!enabled)return null;
 if(typeof version!=='string'||!/^\d+\.\d+\.\d+(?:-[a-z0-9.-]+)?$/.test(version))throw Error('Invalid public version.');
 return Object.freeze({schema:'guardclaw.usage.v1',event:'setup_succeeded',version});
}
