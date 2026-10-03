export const ACCESS_BYTES=128;
// Canonical tiny schema only; deliberately never echo credentials in errors.
export function parseLocalAccess(bytes){
 if(!(bytes instanceof Uint8Array)||bytes.byteLength>ACCESS_BYTES)throw Error('Invalid local access file.');
 const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);
 const match=/^\{"schemaVersion":1,"capability":"([a-f0-9]{64})"\}$/.exec(text);
 if(!match)throw Error('Invalid local access file.');
 return match[1];
}
