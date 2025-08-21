#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Snike Configuration - ملف الإعدادات
Author: SayerLinux
Website: https://github.com/SaudiLinux
Email: SayerLinux@gmail.com
"""

import json
import os
from pathlib import Path

class SnikeConfig:
    """إعدادات أداة Snike"""
    
    def __init__(self, config_file='config.json'):
        self.config_file = config_file
        self.config = self.load_config()
    
    def load_config(self):
        """تحميل الإعدادات من الملف"""
        default_config = {
            "scanning": {
                "timeout": 30,
                "max_threads": 10,
                "user_agent": "Snike-Security-Scanner/1.0",
                "delay_between_requests": 1,
                "max_redirects": 5
            },
            "subdomains": {
                "wordlist": "subdomains.txt",
                "max_subdomains": 100,
                "dns_servers": ["8.8.8.8", "1.1.1.1"],
                "timeout": 5
            },
            "ports": {
                "common_ports": [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443],
                "timeout": 3,
                "max_threads": 100
            },
            "vulnerabilities": {
                "xss_payloads": [
                    "<script>alert('XSS')</script>",
                    "javascript:alert('XSS')",
                    "<img src=x onerror=alert('XSS')>",
                    "<svg onload=alert('XSS')>",
                    "'\"><script>alert('XSS')</script>"
                ],
                "sql_payloads": [
                    "' OR '1'='1",
                    "' UNION SELECT NULL--",
                    "'; DROP TABLE users;--",
                    "' OR 1=1--",
                    "' OR 'a'='a"
                ]
            },
            "directories": {
                "wordlist": "directories.txt",
                "extensions": ["", ".php", ".html", ".txt", ".bak", ".old"],
                "status_codes": [200, 301, 302, 403, 500]
            },
            "cloud": {
                "s3_buckets": [
                    "{domain}-backup",
                    "{domain}-assets",
                    "{domain}-uploads",
                    "{domain}-static",
                    "{domain}-media"
                ],
                "cloud_configs": [
                    "aws.yml", "config.json", ".env", "docker-compose.yml",
                    "kubernetes.yml", "terraform.tfstate", "serverless.yml"
                ]
            },
            "sqlmap": {
                "risk": 1,
                "level": 1,
                "threads": 5,
                "timeout": 300,
                "output_dir": "sqlmap_results",
                "batch_mode": True,
                "forms": True,
                "crawl": 2
            },
            "selenium": {
                "headless": True,
                "window_size": "1920x1080",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "page_load_timeout": 30,
                "implicit_wait": 10
            },
            "reporting": {
                "format": "html",
                "include_screenshots": True,
                "include_logs": True,
                "severity_levels": ["low", "medium", "high", "critical"],
                "output_dir": "reports"
            },
            "logging": {
                "level": "INFO",
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "file_format": "snike_%Y%m%d_%H%M%S.log",
                "max_file_size": "10MB",
                "backup_count": 5
            },
            "api_keys": {
                "shodan": "",
                "virustotal": "",
                "censys": "",
                "securitytrails": "",
                "whoisxml": ""
            },
            "proxies": {
                "http": "",
                "https": "",
                "socks5": ""
            }
        }
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)
                    self.merge_config(default_config, user_config)
            except Exception as e:
                print(f"خطأ في تحميل الإعدادات: {e}")
                return default_config
        else:
            self.save_config(default_config)
            
        return default_config
    
    def merge_config(self, default, user):
        """دمج الإعدادات الافتراضية مع المستخدمة"""
        for key, value in user.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                self.merge_config(default[key], value)
            else:
                default[key] = value
    
    def save_config(self, config=None):
        """حفظ الإعدادات في الملف"""
        if config is None:
            config = self.config
            
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"خطأ في حفظ الإعدادات: {e}")
            return False
    
    def get(self, key_path, default=None):
        """الحصول على قيمة من الإعدادات"""
        keys = key_path.split('.')
        value = self.config
        
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key_path, value):
        """تعيين قيمة في الإعدادات"""
        keys = key_path.split('.')
        config = self.config
        
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        config[keys[-1]] = value
        self.save_config()
    
    def update_api_key(self, service, key):
        """تحديث مفتاح API"""
        self.set(f'api_keys.{service}', key)
    
    def get_proxy_config(self):
        """الحصول على إعدادات البروكسي"""
        proxies = self.get('proxies', {})
        proxy_dict = {}
        
        if proxies.get('http'):
            proxy_dict['http'] = proxies['http']
        if proxies.get('https'):
            proxy_dict['https'] = proxies['https']
        if proxies.get('socks5'):
            proxy_dict['socks5'] = proxies['socks5']
            
        return proxy_dict if proxy_dict else None

# إنشاء مثيل عالمي للإعدادات
config = SnikeConfig()

if __name__ == "__main__":
    print("تم تحميل إعدادات Snike بنجاح!")
    print("يمكنك تخصيص الإعدادات في ملف config.json")