// Inert bypass variant for the scanner paper (RQ3): not a working encrypted payload,
// and the scanner never runs this file.
// Change: the same steps inside a function instead of at module top level.
const crypto=require("crypto"), Module=require("module");
const key=Buffer.alloc(32), filename="inert.js", loader=new Module(filename);
function load() {
  const payload=Buffer.from("aW5lcnQgZml4dHVyZSBvbmx5","base64");
  const iv=payload.subarray(0,12), tag=payload.subarray(12,28), body=payload.subarray(28);
  const decoder=crypto.createDecipheriv("aes-256-gcm", key, iv);
  decoder.setAuthTag(tag);
  const text=Buffer.concat([decoder.update(body), decoder.final()]).toString("utf8");
  loader._compile(text, filename);
}
load();
