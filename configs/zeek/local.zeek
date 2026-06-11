# Thor Firewall — Zeek local config
@load base/frameworks/notice
@load base/frameworks/intel
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/ssh
@load base/protocols/smtp
@load base/protocols/ftp
@load policy/tuning/json-logs
@load policy/integration/collective-intel
@load policy/frameworks/intel/seen
@load policy/protocols/ssh/detect-bruteforcing
@load policy/protocols/http/detect-sqli
@load policy/frameworks/files/hash-all-files

redef LogAscii::use_json = T;
redef Intel::read_files += {
  "/usr/local/zeek/share/zeek/intel/intel.dat"
};
