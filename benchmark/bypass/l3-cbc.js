// Inert bypass variant for the scanner paper (RQ3): not a working encrypted payload,
// and the scanner never runs this file.
// Change: AES-CBC without an authentication tag.
const crypto=require("crypto"), Module=require("module");
const key=Buffer.alloc(32), filename="inert.js", loader=new Module(filename);
const payload=Buffer.from("aW5lcnQgZml4dHVyZSBvbmx5","base64");
const iv=payload.subarray(0,16), body=payload.subarray(16);
const decoder=crypto.createDecipheriv("aes-256-cbc", key, iv);
const text=Buffer.concat([decoder.update(body), decoder.final()]).toString("utf8");
loader._compile(text, filename);
