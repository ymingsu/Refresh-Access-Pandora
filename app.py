# -*- coding: utf-8 -*-

from flask import Flask, request, jsonify
import requests
import re
from certifi import where
from datetime import datetime as dt
import datetime
from pandora.openai.auth import Auth0
from os import getenv

app = Flask(__name__)

proxy = getenv('PROXY',None)


@app.route('/')
def hello():
    return "<p>Hello, World!</p>"

@app.route('/api/share', methods=['POST'])
def share_token():
    unique_name = getenv("UNIQUE_NAME",'my-share')
    register_url = 'https://ai.fakeopen.com/token/register'
    expires_in=0
    access_token_payload = request.get_json()
    access_token = access_token_payload['access_token']
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    payload = f'unique_name={unique_name}&access_token={access_token}&expires_in={expires_in}&show_userinfo=false'
    share_response = requests.post(register_url, headers=headers, data=payload)
    resp=share_response.json()
    token_info = {
            'share_token': 'None',
            'text':'None'
        }
    if share_response.status_code == 200:
        token_info['share_token'] = resp['token_key']
        return jsonify(token_info),200
    else:
        token_info['text'] = share_response.text
        return jsonify(token_info),share_response.status_code

@app.route('/api/pool', methods=['POST'])
def pool_token():
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    pool_url = 'https://ai.fakeopen.com/pool/update'
    share_tokens = request.json.get('share_tokens', [])
    if len(share_tokens)<2:
        return jsonify({'text': 'More share tokens needed.'}),500
    pool_token = request.json.get('pool_token', None)
    share_token_list_str = '%0A'.join([share_token for share_token in share_tokens])
    if not pool_token:
        pool_payload = f'share_tokens={share_token_list_str}&pool_token={pool_token}'
    else:
        pool_payload = f'share_tokens={share_token_list_str}'
    pool_response = requests.request('POST', pool_url, headers=headers, data=pool_payload)
    if pool_response.status_code == 200:
        return jsonify({'pool_token': pool_response.json()['pool_token']}),200
    return jsonify({'text': pool_response.text}),pool_response.status_code
@app.route('/api/login', methods=['POST'])
def login():
    access_token_payload = request.get_json()
    username = access_token_payload['username']
    password = access_token_payload['password']
    mfa = access_token_payload.get('mfa')
    # 生成 access_token 的操作
    return get_access_token(username,password,mfa)

def get_access_token(username,password,mfa):
    theauth = Auth0(username, password, proxy, False, mfa)
    token_info = {
            'access_token': 'None',
            'expires': 'None',
            'refresh_token': 'None',
            'text': 'None',
        }
    try:
        token_info['access_token'] = theauth.auth(False)# fakeopen
        token_info['refresh_token'] = theauth.get_refresh_token()
        token_info['expires'] = theauth.expires
    except Exception as e1:
        try:
            token_info['access_token'] = theauth.auth(True)# openai
            token_info['refresh_token'] = theauth.get_refresh_token()
            token_info['expires'] = theauth.expires
            token_info['text'] = str(e1).replace('\n', '').replace('\r', '').strip()
        except Exception as e2:
            token_info['text'] = str(e2).replace('\n', '').replace('\r', '').strip()
            # error_message = 'Invalid refresh token.'
            return jsonify(token_info), 500
    return jsonify(token_info), 200

@app.route('/api/revoke', methods=['POST'])
def revoke_refresh_token():
    user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) ' \
                          'Chrome/109.0.0.0 Safari/537.36'
    refresh_data = {
        "client_id": "pdlLIX2Y72MIl2rhLhTE9VV9bN905kBh",
        "refresh_token": refresh_token
        }
    url = 'https://auth0.openai.com/oauth/revoke'
    headers = {
            'User-Agent': user_agent,
        }
    session = requests.Session()
    
    req_kwargs = {
            'proxies': {
                'http': proxy,
                'https': proxy,
            } if proxy else None,
            'verify': where(),
            'timeout': 100,
        }
    resp = session.post(url, headers=headers, json=refresh_data, allow_redirects=False, **req_kwargs)
    return jsonify({'text': resp.text}), resp.status_code

@app.route('/api/refresh', methods=['POST'])
def refresh_token():
    # 获取 POST 请求的 JSON 数据
    refresh_token_payload = request.get_json()

    # 从 payload 中获取 refresh_token
    refresh_token = refresh_token_payload.get('refresh_token')

    # 在这里进行验证 refresh_token 的逻辑
    if not check_refresh_token(refresh_token):
        error_message = 'Invalid refresh token.'
        return jsonify({'text': error_message}), 500
    # 假设验证成功，生成新的 access_token
    return generate_access_token(refresh_token)
def check_refresh_token(refresh_token: str):
    regex =  r'[a-zA-Z0-9\-_]{45}'
    return re.fullmatch(regex, refresh_token)
def generate_access_token(refresh_token):
    # 在这里根据实际需求生成 access_token
    # 这里使用一个简单的示例，将固定的字符串作为 access_token
    # 假设生成失败时返回 None
    user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) ' \
                          'Chrome/109.0.0.0 Safari/537.36'
    refresh_data = {
        "redirect_uri": "com.openai.chat://auth0.openai.com/ios/com.openai.chat/callback",
        "grant_type": "refresh_token",
        "client_id": "pdlLIX2Y72MIl2rhLhTE9VV9bN905kBh",
        "refresh_token": refresh_token
        }
    url = 'https://auth0.openai.com/oauth/token'
    headers = {
            'User-Agent': user_agent,
        }
    session = requests.Session()
    
    req_kwargs = {
            'proxies': {
                'http': proxy,
                'https': proxy,
            } if proxy else None,
            'verify': where(),
            'timeout': 100,
        }
    resp = session.post(url, headers=headers, json=refresh_data, allow_redirects=False, **req_kwargs)
    return parse_access_token(resp)
def parse_access_token(resp):
    if resp.status_code == 200:
        json = resp.json()
        if 'access_token' not in json:
            error_message = 'Failed to get access token.'
            return jsonify({'text': error_message}), 500

        access_token = json['access_token']
        expires = dt.utcnow() + datetime.timedelta(seconds=json['expires_in']) - datetime.timedelta(minutes=5)
        data={
            'access_token': access_token,
            'expires' : expires,
        }
        return jsonify(data), 200
    else:
        # raise Exception(resp.text)
        return jsonify({'text': resp.text}), resp.status_code
