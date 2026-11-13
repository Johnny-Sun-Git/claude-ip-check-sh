#!/usr/bin/env bash
# Claude / Net.Coffee IP diagnostic report
# Usage: bash claude-ip-check.sh [IP]
# Requires: bash, curl, python3. No Node.js/npm required.
set -Eeuo pipefail

VERSION="1.0.0"

for cmd in curl python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "错误：缺少依赖 $cmd" >&2
    echo "Debian/Ubuntu 安装：sudo apt-get update && sudo apt-get install -y curl python3" >&2
    exit 1
  fi
done

TARGET_IP="${1:-}"
if [[ -z "$TARGET_IP" ]]; then
  TARGET_IP="$(curl -4fsS --max-time 10 https://api.ipify.org || true)"
fi
if [[ -z "$TARGET_IP" ]]; then
  echo "无法获取 IPv4 出口 IP。请检查网络/代理，或手动指定：bash $0 <IP>" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
HTML_FILE="$TMP_DIR/netcoffee.html"

printf '正在查询 Net.Coffee：%s\n' "$TARGET_IP"
if ! curl -fsSL --max-time 25 -A 'Mozilla/5.0 (compatible; ClaudeIPCheck/1.0)' \
  "https://ip.net.coffee/ip/${TARGET_IP}" -o "$HTML_FILE"; then
  echo "警告：Net.Coffee 页面请求失败；仍将执行基础网络检测。" >&2
  : > "$HTML_FILE"
fi

TARGET_IP="$TARGET_IP" HTML_FILE="$HTML_FILE" python3 <<'PY'
import os, sys, re, json, socket, subprocess, datetime, ipaddress
from html.parser import HTMLParser

IP = os.environ.get('TARGET_IP', '')
HTML_FILE = os.environ.get('HTML_FILE', '')
VERSION = os.environ.get('VERSION', '1.0.1')
RESET='\033[0m'; BOLD='\033[1m'; DIM='\033[2m'
GREEN='\033[32m'; YELLOW='\033[33m'; RED='\033[31m'; CYAN='\033[36m'; BLUE='\033[34m'
if not sys.stdout.isatty() or os.environ.get('NO_COLOR'):
    RESET=BOLD=DIM=GREEN=YELLOW=RED=CYAN=BLUE=''

def safe_ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except Exception:
        return None

if not safe_ip(IP):
    print(f'错误：不是有效的 IPv4/IPv6 地址：{IP}', file=sys.stderr)
    sys.exit(2)

class SnapshotParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.depth=0
        self.in_snapshot=False
        self.capture=None
        self.buf=[]
        self.rows=[]
        self.row=None
        self.cell=None
        self.paragraphs=[]
        self.headings=[]
        self.all_text=[]
    def handle_starttag(self, tag, attrs):
        attrs=dict(attrs)
        if tag=='div' and attrs.get('id')=='ssr-snapshot' and not self.in_snapshot:
            self.in_snapshot=True; self.depth=1
            return
        if not self.in_snapshot: return
        if tag=='div': self.depth += 1
        if tag=='tr': self.row=[]
        if tag in ('td','th') and self.row is not None: self.cell=[]
        if tag in ('h1','h2','h3','p'):
            self.capture=tag; self.buf=[]
    def handle_endtag(self, tag):
        if not self.in_snapshot: return
        if tag in ('td','th') and self.cell is not None and self.row is not None:
            self.row.append(' '.join(' '.join(self.cell).split())); self.cell=None
        if tag=='tr' and self.row is not None:
            if self.row: self.rows.append(self.row)
            self.row=None
        if tag==self.capture:
            value=' '.join(' '.join(self.buf).split())
            if value:
                if tag=='p': self.paragraphs.append(value)
                elif tag in ('h1','h2','h3'): self.headings.append(value)
                self.all_text.append(value)
            self.capture=None; self.buf=[]
        if tag=='div':
            self.depth -= 1
            if self.depth <= 0:
                self.in_snapshot=False
    def handle_data(self, data):
        if not self.in_snapshot: return
        if self.cell is not None: self.cell.append(data)
        if self.capture: self.buf.append(data)

parser=SnapshotParser()
try:
    with open(HTML_FILE, encoding='utf-8', errors='replace') as f:
        parser.feed(f.read())
except OSError:
    pass

fields={}
for row in parser.rows:
    if len(row)>=2:
        fields[row[0].strip().rstrip(':')]=row[1].strip()

# IPv6 egress (may be unavailable on this VM or network).
def run_cmd(args, timeout=10):
    try:
        p=subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
        return p.stdout.strip() if p.returncode==0 else ''
    except Exception:
        return ''

ip6=run_cmd(['curl','-6','-fsS','--max-time','8','https://api64.ipify.org'], 10)
if not safe_ip(ip6): ip6=''

# DNS + HTTP/TLS timings. A normal GET is discarded; no account/API credentials are sent.
hosts=['claude.ai','console.anthropic.com','api.anthropic.com']
checks=[]
for host in hosts:
    try:
        infos=socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        addrs=[]
        for item in infos:
            addr=item[4][0]
            if addr not in addrs: addrs.append(addr)
        dns='、'.join(addrs[:4]) if addrs else '解析结果为空'
        dns_ok=True
    except Exception as e:
        dns='解析失败'; dns_ok=False
    fmt='%{http_code}|%{remote_ip}|%{time_namelookup}|%{time_connect}|%{time_appconnect}|%{time_starttransfer}|%{time_total}'
    raw=run_cmd(['curl','-4','-sS','-L','-o','/dev/null','--max-time','15','-w',fmt,'https://'+host], 17)
    parts=raw.split('|') if raw else []
    if len(parts)==7:
        code,remote,tdns,tconn,ttls,tttf,total=parts
        def ms(x):
            try: return round(float(x)*1000)
            except: return None
        checks.append({'host':host,'dns_ok':dns_ok,'dns':dns,'http':code,'remote_ip':remote,
                       'dns_ms':ms(tdns),'connect_ms':ms(tconn),'tls_ms':ms(ttls),
                       'ttfb_ms':ms(tttf),'total_ms':ms(total)})
    else:
        checks.append({'host':host,'dns_ok':dns_ok,'dns':dns,'http':'失败/超时','remote_ip':'-',
                       'dns_ms':None,'connect_ms':None,'tls_ms':None,'ttfb_ms':None,'total_ms':None})

# Output helpers
def line(): print(CYAN+'─'*76+RESET)
def show(label, value): print(f'  {DIM}{label:<17}{RESET} {value if value else YELLOW+"页面未提供"+RESET}')
def score_color(n): return GREEN if n>=80 else (YELLOW if n>=60 else RED)

print('\n'+BOLD+CYAN+'          CLAUDE IP / NETWORK DIAGNOSTIC'+RESET+DIM+f'  v{VERSION}'+RESET)
line()
print(f'  {BOLD}检测出口 IP{RESET}       {IP}')
print(f'  {BOLD}IPv6 出口{RESET}         {ip6 if ip6 else YELLOW+"不可用 / 未检测到"+RESET}')
proxy='已设置' if (os.getenv('HTTPS_PROXY') or os.getenv('https_proxy') or os.getenv('ALL_PROXY') or os.getenv('all_proxy')) else '未设置（或使用透明代理）'
print(f'  {BOLD}代理环境变量{RESET}     {proxy}')
line()
print(BOLD+'  NET.COFFEE 服务端快照'+RESET)
if fields:
    show('IP 地址', fields.get('IP 地址', IP))
    show('协议版本', fields.get('协议版本'))
    show('国家/地区', fields.get('国家/地区'))
    show('区域 / 城市', ' / '.join(x for x in [fields.get('区域'),fields.get('城市')] if x))
    show('运营商 / ASN', fields.get('运营商/ASN'))
    show('公司', fields.get('公司'))
    trust=fields.get('信任评分','')
    m=re.search(r'(\d+(?:\.\d+)?)\s*/\s*100',trust)
    if m:
        n=float(m.group(1)); blocks=max(0,min(20,round(n/5)))
        bar='█'*blocks+'░'*(20-blocks)
        print(f'  {DIM}{"信任评分":<17}{RESET} {score_color(n)}{BOLD}{n:g}/100{RESET}  {score_color(n)}[{bar}]{RESET}')
    else: show('信任评分',trust)
    print()
    # Print descriptive sections from the SSR snapshot.
    for p in parser.paragraphs:
        if any(k in p for k in ('可用','尝试','人类','机器','热度指数','所属前缀','直接上游','IDC','地图定位','Los Angeles')):
            print(f'  {p}')
else:
    print('  '+YELLOW+'未提取到 SSR 快照。可能是页面结构调整或请求失败。'+RESET)
    print('  '+DIM+'Net.Coffee 页面在浏览器中加载的动态检测不会自动包含在 curl 的 HTML 中。'+RESET)
line()
print(BOLD+'  CLAUDE / ANTHROPIC 连通性（IPv4）'+RESET)
print(f'  {"域名":<27} {"HTTP":<12} {"DNS":<9} {"TCP":<9} {"TLS":<9} {"TTFB":<9} {"总计":<9}')
for c in checks:
    def val(x): return (str(x)+'ms') if x is not None else '-'
    code=str(c['http'])
    status=GREEN+code+RESET if code.isdigit() and 200<=int(code)<400 else YELLOW+code+RESET
    print(f"  {c['host']:<27} {status:<20} {val(c['dns_ms']):<9} {val(c['connect_ms']):<9} {val(c['tls_ms']):<9} {val(c['ttfb_ms']):<9} {val(c['total_ms']):<9}")
    print(f"    {DIM}系统 DNS: {c['dns']}  |  curl 连接对端: {c['remote_ip']}{RESET}")
line()
print(BOLD+'  结论提示'+RESET)
print('  • 若运营商/公司标注为 Cloud、Hosting 或 IDC，通常属于机房网络，而非住宅宽带。')
print('  • HTTP 200/403/404 都只代表 HTTP 层收到了响应，不等于 Claude 账号可用。')
print('  • Net.Coffee 这里读取的是服务端 HTML 快照；风险、端口、黑名单、全球延迟等')
print('    动态字段若没有出现在 HTML 中，就不会被本脚本推断。')
print('  • 设置 HTTP(S)_PROXY 时，curl 的连接耗时/连接对端可能反映代理服务器；系统 DNS')
print('    查询结果则来自本机解析器，两者不一定相同。')
print('  • 第三方信任评分不是 Anthropic 官方风控分数，也不能预测封号概率。')
line()

report={
  'generated_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
  'source':'https://ip.net.coffee/ip/'+IP,
  'ipv4':IP,'ipv6':ip6 or None,'proxy_environment':'set' if proxy=='已设置' else 'not_detected',
  'netcoffee_snapshot':fields,'netcoffee_sections':parser.paragraphs,
  'connectivity':checks,
  'limitations':['HTML SSR snapshot only; JavaScript-loaded details are not included',
                 'Third-party scores are not Anthropic internal risk signals']
}
name='claude-ip-report-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'.json'
try:
    with open(name,'w',encoding='utf-8') as f: json.dump(report,f,ensure_ascii=False,indent=2)
    print(f'  JSON 报告已保存：{os.path.abspath(name)}')
except Exception as e:
    print(f'  {YELLOW}JSON 报告保存失败：{e}{RESET}')
print()
PY

