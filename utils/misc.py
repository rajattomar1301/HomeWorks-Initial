import random
import json
import requests
from datetime import datetime
from functools import wraps
from flask import request, session, redirect, url_for, flash, g
allowed_chars = "0123456789"

def generate_random_string(length=32, chars=allowed_chars):
    r = random.SystemRandom()
    return "".join([r.choice(chars) for i in range(length)])

def generate_confirmation_key():
    return generate_random_string(32)

def get_ip():
    return request.headers.get(config.proxied_ip_header, request.remote_addr)

