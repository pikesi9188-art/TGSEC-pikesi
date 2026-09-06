#!/usr/bin/env python3
"""Bypass OpenResty/Imunify360 JS anti-bot challenge for Plesk-hosted sites."""
import re
import urllib3
import argparse
urllib3.disable_warnings()

import requests

def extract_jsnum(js_expr: str) -> int:
    """Evaluate obfuscated JS number expressions like (+!+[]+!![]+!![]+[])."""
    parts = re.findall(r'\(([^()]+)\)', js_expr)
    digits = []
    for part in parts:
        trues = part.count('+!+[]') + part.count('!![]')
        val = trues
        is_str = part.rstrip().endswith('+[]') and not part.rstrip().endswith('+!+[]')
        if is_str:
            val -= 1
        digits.append((val, is_str))
    result = ""
    for val, is_str in digits:
        if result == "":
            if is_str:
                result = str(val)
            else:
                result = val
        else:
            if isinstance(result, int):
                if is_str:
                    result = str(result) + str(val)
                else:
                    result = result + val
            else:
                result = result + str(val)
    return int(result)


def bypass(target_url: str, verbose: bool = False):
    sess = requests.Session()
    sess.verify = False
    sess.headers['User-Agent'] = (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36'
    )

    r = sess.get(target_url, timeout=15)
    html = r.text

    if 'One moment, please' not in html and 'wsidchk' not in html:
        print('[*] No anti-bot challenge detected, page is accessible directly')
        return sess, r

    scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL)
    if len(scripts) < 2:
        print('[-] Could not find challenge script')
        return None, None

    js = scripts[1]
    if verbose:
        print('[*] Challenge script length:', len(js))

    verify_path = re.search(r"'(/z0f[a-f0-9]+)'", js)
    if not verify_path:
        print('[-] Could not find verification path')
        return None, None
    verify_path = verify_path.group(1)
    if verbose:
        print('[*] Verify path:', verify_path)

    id_parts = re.findall(r"'([a-f0-9]{10})'", js)
    if verbose:
        print('[*] ID parts:', id_parts)

    id_val_match = re.search(r"r\[.*?\]='([a-f0-9]+)'.*?r\[.*?\]=x\(0x9d\)\+'([a-f0-9]+)'", js)

    id_pieces = []
    for part in id_parts:
        if len(part) == 10:
            id_pieces.append(part)
    if len(id_pieces) >= 2:
        full_id = ''.join(id_pieces)
    else:
        full_id = ''.join(id_parts)

    ts_match = re.search(r"'(\d{10})'", js)
    ts = ts_match.group(1) if ts_match else None
    if verbose:
        print('[*] Timestamp:', ts)

    pdata_match = re.search(r"'(https?%3A%2F%2F[^']+)'", js)
    pdata = pdata_match.group(1) if pdata_match else ''
    if verbose:
        print('[*] pdata:', pdata)

    p_exprs = re.findall(r'=\+\(((?:\([^()]+\)\+?)+)\)', js)
    if verbose:
        print(f'[*] Found {len(p_exprs)} number expressions')

    nums = []
    for expr in p_exprs:
        try:
            n = extract_jsnum(expr)
            nums.append(n)
            if verbose:
                print(f'  num: {n}')
        except Exception as e:
            if verbose:
                print(f'  failed: {e}')

    if len(nums) >= 2:
        wsidchk = nums[0] + nums[1]
    else:
        print('[-] Could not compute wsidchk')
        return None, None

    if verbose:
        print(f'[*] wsidchk = {nums[0]} + {nums[1]} = {wsidchk}')

    from urllib.parse import urlparse
    parsed = urlparse(target_url)
    base = f'{parsed.scheme}://{parsed.netloc}'

    params = {
        'id': full_id,
        'ts': ts,
        'wsidchk': str(wsidchk),
        'pdata': pdata,
        'bv': '0',
    }

    verify_url = base + verify_path
    if verbose:
        print(f'[*] Verify URL: {verify_url}')
        print(f'[*] Params: {params}')

    r2 = sess.get(verify_url, params=params, timeout=15, allow_redirects=True)
    if verbose:
        print(f'[*] Verify response: {r2.status_code}')
        print(f'[*] Cookies: {dict(sess.cookies)}')
        print(f'[*] Response headers: {dict(r2.headers)}')

    r3 = sess.get(target_url, timeout=15)
    if 'One moment, please' in r3.text:
        print('[-] Anti-bot bypass failed, still getting challenge page')
        if verbose:
            print(f'[*] Final cookies: {dict(sess.cookies)}')
        return None, None
    else:
        print('[+] Anti-bot bypass successful!')
        return sess, r3


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('url', help='Target URL to bypass anti-bot')
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()

    sess, resp = bypass(args.url, args.verbose)
    if sess and resp:
        print(f'[+] Status: {resp.status_code}')
        print(f'[+] Content-Type: {resp.headers.get("content-type")}')
        print('[+] Body preview:')
        print(resp.text[:500])
