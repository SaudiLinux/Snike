#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Snike - Advanced Security Testing Tool
Author: SayerLinux
Website: https://github.com/SaudiLinux
Email: SayerLinux@gmail.com
"""

import requests
import socket
import subprocess
import json
import os
import time
import logging
from datetime import datetime
from urllib.parse import urljoin, urlparse
import argparse
import threading
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
import sqlite3
import re
import uuid

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'

class SnikeLogger:
    def __init__(self):
        self.setup_logging()
    
    def setup_logging(self):
        if not os.path.exists('logs'):
            os.makedirs('logs')
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = f'logs/snike_{timestamp}.log'
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('Snike')

class AttackSurfaceManager:
    def __init__(self, target_url):
        self.target_url = target_url
        self.discovered_urls = set()
        self.vulnerabilities = []
        self.logger = SnikeLogger().logger
    
    def discover_subdomains(self):
        """اكتشاف النطاقات الفرعية"""
        self.logger.info("بدء اكتشاف النطاقات الفرعية...")
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging',
            'api', 'blog', 'shop', 'support', 'help', 'docs',
            'cdn', 'static', 'media', 'img', 'images', 'js', 'css'
        ]
        
        discovered = []
        base_domain = urlparse(self.target_url).netloc
        
        for sub in common_subdomains:
            subdomain = f"{sub}.{base_domain}"
            try:
                socket.gethostbyname(subdomain)
                discovered.append(subdomain)
                self.logger.info(f"تم العثور على النطاق الفرعي: {subdomain}")
            except socket.gaierror:
                pass
        
        return discovered
    
    def discover_hidden_directories(self):
        """اكتشاف الدلائل المخفية"""
        self.logger.info("بدء اكتشاف الدلائل المخفية...")
        common_dirs = [
            'admin', 'administrator', 'backup', 'config', 'logs', 'temp',
            'uploads', 'download', 'includes', 'lib', 'modules', 'plugins',
            'wp-admin', 'wp-content', 'wp-includes', '.git', '.env',
            'robots.txt', 'sitemap.xml', '.htaccess', 'phpinfo.php'
        ]
        
        discovered = []
        for directory in common_dirs:
            url = urljoin(self.target_url, directory)
            try:
                response = requests.get(url, timeout=5)
                if response.status_code != 404:
                    discovered.append(url)
                    self.logger.info(f"تم العثور على دليل: {url}")
            except:
                pass
        
        return discovered
    
    def port_scan(self):
        """مسح المنفذ"""
        self.logger.info("بدء مسح المنفذ...")
        target = urlparse(self.target_url).netloc.split(':')[0]
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
        
        open_ports = []
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
                self.logger.info(f"المنفذ {port} مفتوح")
            sock.close()
        
        return open_ports

class ZeroDayScanner:
    def __init__(self):
        self.logger = SnikeLogger().logger
    
    def scan_common_vulnerabilities(self, url):
        """مسح الثغرات الشائعة"""
        self.logger.info("بدء مسح الثغرات الصفرية...")
        vulnerabilities = []
        
        # اختبار XSS
        xss_payloads = [
            '<script>alert("XSS")</script>',
            'javascript:alert("XSS")',
            '<img src=x onerror=alert("XSS")>'
        ]
        
        for payload in xss_payloads:
            test_url = f"{url}?test={payload}"
            try:
                response = requests.get(test_url)
                if payload in response.text:
                    vulnerabilities.append({
                        'type': 'XSS',
                        'payload': payload,
                        'url': test_url
                    })
            except:
                pass
        
        # اختبار SQL Injection
        sql_payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users;--"
        ]
        
        for payload in sql_payloads:
            test_url = f"{url}?id={payload}"
            try:
                response = requests.get(test_url)
                if any(error in response.text.lower() for error in ['mysql', 'sql', 'syntax']):
                    vulnerabilities.append({
                        'type': 'SQL Injection',
                        'payload': payload,
                        'url': test_url
                    })
            except:
                pass
        
        return vulnerabilities

class CloudSecurityScanner:
    def __init__(self):
        self.logger = SnikeLogger().logger
    
    def scan_aws_s3_buckets(self, domain):
        """مسح حاويات AWS S3"""
        self.logger.info("بدء مسح حاويات AWS S3...")
        common_buckets = [
            f"{domain}-backup",
            f"{domain}-assets",
            f"{domain}-uploads",
            f"{domain}-static",
            f"{domain}-media"
        ]
        
        found_buckets = []
        for bucket in common_buckets:
            try:
                response = requests.get(f"https://{bucket}.s3.amazonaws.com")
                if response.status_code != 404:
                    found_buckets.append(f"{bucket}.s3.amazonaws.com")
            except:
                pass
        
        return found_buckets
    
    def scan_cloud_config(self, url):
        """مسح إعدادات السحابة"""
        cloud_configs = [
            'aws.yml', 'config.json', '.env', 'docker-compose.yml',
            'kubernetes.yml', 'terraform.tfstate'
        ]
        
        found_configs = []
        for config in cloud_configs:
            try:
                response = requests.get(urljoin(url, config))
                if response.status_code == 200:
                    found_configs.append(urljoin(url, config))
            except:
                pass
        
        return found_configs

class SQLMapScanner:
    def __init__(self):
        self.logger = SnikeLogger().logger
    
    def run_sqlmap_scan(self, url):
        """تشغيل SQLMap للمسح التلقائي"""
        self.logger.info("بدء مسح SQLMap...")
        
        try:
            cmd = [
                'sqlmap', '-u', url, '--batch', '--risk=1', '--level=1',
                '--output-dir=sqlmap_results', '--format=json'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if os.path.exists('sqlmap_results'):
                for file in os.listdir('sqlmap_results'):
                    if file.endswith('.json'):
                        with open(os.path.join('sqlmap_results', file), 'r') as f:
                            return json.load(f)
            
            return {'status': 'completed', 'findings': []}
            
        except subprocess.TimeoutExpired:
            self.logger.error("SQLMap timeout")
            return {'error': 'timeout'}
        except FileNotFoundError:
            self.logger.error("SQLMap not found. Please install sqlmap")
            return {'error': 'sqlmap_not_found'}

class HiddenLinksDiscoverer:
    def __init__(self):
        self.logger = SnikeLogger().logger
        self.driver = None
    
    def setup_driver(self):
        """إعداد متصفح Selenium"""
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        
        try:
            self.driver = webdriver.Chrome(options=chrome_options)
            return True
        except:
            self.logger.error("Failed to setup Chrome driver")
            return False
    
    def discover_hidden_links(self, url):
        """اكتشاف الروابط المخفية"""
        if not self.setup_driver():
            return []
        
        self.logger.info("بدء اكتشاف الروابط المخفية...")
        hidden_links = []
        
        try:
            self.driver.get(url)
            time.sleep(3)
            
            # العثور على جميع الروابط
            links = self.driver.find_elements(By.TAG_NAME, 'a')
            for link in links:
                href = link.get_attribute('href')
                if href and href not in hidden_links:
                    hidden_links.append(href)
            
            # العثور على الروابط في JavaScript
            scripts = self.driver.find_elements(By.TAG_NAME, 'script')
            for script in scripts:
                content = script.get_attribute('innerHTML')
                if content:
                    urls = re.findall(r'https?://[^\s"<>]+', content)
                    hidden_links.extend(urls)
            
            # لقطة شاشة
            screenshot_path = f"screenshots/screenshot_{uuid.uuid4().hex}.png"
            if not os.path.exists('screenshots'):
                os.makedirs('screenshots')
            self.driver.save_screenshot(screenshot_path)
            
            return list(set(hidden_links))
            
        except Exception as e:
            self.logger.error(f"Error discovering hidden links: {e}")
            return []
        finally:
            if self.driver:
                self.driver.quit()

class ReportGenerator:
    def __init__(self):
        self.logger = SnikeLogger().logger
    
    def generate_report(self, results):
        """توليد تقرير شامل"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"reports/security_report_{timestamp}.html"
        
        if not os.path.exists('reports'):
            os.makedirs('reports')
        
        html_content = f"""
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>تقرير أمني - Snike</title>
    <style>
        body {{ font-family: 'Arial', sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px; margin-bottom: 20px; }}
        .section {{ background: white; margin: 20px 0; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .vulnerability {{ background: #ffebee; border-left: 4px solid #f44336; padding: 15px; margin: 10px 0; }}
        .safe {{ background: #e8f5e8; border-left: 4px solid #4caf50; padding: 15px; margin: 10px 0; }}
        .info {{ background: #e3f2fd; border-left: 4px solid #2196f3; padding: 15px; margin: 10px 0; }}
        .log-entry {{ font-family: monospace; background: #f5f5f5; padding: 10px; margin: 5px 0; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>تقرير الأمان - Snike</h1>
        <p>أداة اختبار الأمان المتقدمة</p>
        <p>المبرمج: SayerLinux | الموقع: https://github.com/SaudiLinux</p>
    </div>
    
    <div class="section">
        <h2>ملخص النتائج</h2>
        <div class="info">
            <strong>التاريخ:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        </div>
    </div>
    
    <div class="section">
        <h2>النتائج التفصيلية</h2>
        <pre>{json.dumps(results, indent=2, ensure_ascii=False)}</pre>
    </div>
    
    <div class="section">
        <h2>التوصيات</h2>
        <ul>
            <li>تحديث جميع البرامج والمكتبات بانتظام</li>
            <li>استخدام مصادقة متعددة العوامل</li>
            <li>مراجعة إعدادات الأمان بشكل دوري</li>
            <li>تنفيذ سياسات كلمة المرور القوية</li>
            <li>مراقبة السجلات باستمرار</li>
        </ul>
    </div>
</body>
</html>
        """
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.info(f"تم إنشاء التقرير: {report_file}")
        return report_file

class Snike:
    def __init__(self):
        self.logger = SnikeLogger().logger
        self.results = {}
    
    def banner(self):
        """عرض الشعار"""
        banner_text = f"""
{Colors.CYAN}
███████╗███╗░░██╗██╗██████╗░░█████╗░███╗░░██╗
██╔════╝████╗░██║██║██╔══██╗██╔══██╗████╗░██║
█████╗░░██╔██╗██║██║██████╔╝███████║██╔██╗██║
██╔══╝░░██║╚████║██║██╔═══╝░██╔══██║██║╚████║
███████╗██║░╚███║██║██║░░░░░██║░░██║██║░╚███║
╚══════╝╚═╝░░╚══╝╚═╝╚═╝░░░░░╚═╝░░╚═╝╚═╝░░╚══╝
{Colors.YELLOW}
Advanced Security Testing Tool
Author: SayerLinux
Website: https://github.com/SaudiLinux
Email: SayerLinux@gmail.com
{Colors.RESET}
        """
        print(banner_text)
    
    def run_full_scan(self, target_url):
        """تشغيل مسح شامل"""
        self.logger.info(f"بدء المسح الكامل للهدف: {target_url}")
        
        # إعداد المجلدات
        for folder in ['logs', 'reports', 'screenshots', 'sqlmap_results']:
            if not os.path.exists(folder):
                os.makedirs(folder)
        
        # سطح الهجوم
        attack_surface = AttackSurfaceManager(target_url)
        self.results['subdomains'] = attack_surface.discover_subdomains()
        self.results['hidden_directories'] = attack_surface.discover_hidden_directories()
        self.results['open_ports'] = attack_surface.port_scan()
        
        # الثغرات الصفرية
        zero_day = ZeroDayScanner()
        self.results['vulnerabilities'] = zero_day.scan_common_vulnerabilities(target_url)
        
        # أمن السحابة
        cloud_scanner = CloudSecurityScanner()
        domain = urlparse(target_url).netloc
        self.results['s3_buckets'] = cloud_scanner.scan_aws_s3_buckets(domain)
        self.results['cloud_configs'] = cloud_scanner.scan_cloud_config(target_url)
        
        # SQLMap
        sqlmap = SQLMapScanner()
        self.results['sqlmap_results'] = sqlmap.run_sqlmap_scan(target_url)
        
        # الروابط المخفية
        hidden_links = HiddenLinksDiscoverer()
        self.results['hidden_links'] = hidden_links.discover_hidden_links(target_url)
        
        # توليد التقرير
        report_gen = ReportGenerator()
        report_file = report_gen.generate_report(self.results)
        
        return self.results, report_file
    
    def main(self):
        """الدالة الرئيسية"""
        self.banner()
        
        parser = argparse.ArgumentParser(description='Snike - Advanced Security Testing Tool')
        parser.add_argument('-u', '--url', required=True, help='الرابط المستهدف')
        parser.add_argument('-v', '--verbose', action='store_true', help='وضع التفصيل')
        
        args = parser.parse_args()
        
        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        
        print(f"{Colors.GREEN}[INFO] بدء المسح الأمني...{Colors.RESET}")
        
        try:
            results, report_file = self.run_full_scan(args.url)
            
            print(f"\n{Colors.GREEN}[SUCCESS] تم إكمال المسح بنجاح!{Colors.RESET}")
            print(f"{Colors.CYAN}[INFO] تم إنشاء التقرير: {report_file}{Colors.RESET}")
            
            # عرض ملخص النتائج
            print(f"\n{Colors.YELLOW}=== ملخص النتائج ==={Colors.RESET}")
            print(f"النطاقات الفرعية المكتشفة: {len(results.get('subdomains', []))}")
            print(f"الدلائل المخفية: {len(results.get('hidden_directories', []))}")
            print(f"المنافذ المفتوحة: {len(results.get('open_ports', []))}")
            print(f"الثغرات المكتشفة: {len(results.get('vulnerabilities', []))}")
            print(f"الروابط المخفية: {len(results.get('hidden_links', []))}")
            
        except Exception as e:
            print(f"{Colors.RED}[ERROR] خطأ في التنفيذ: {e}{Colors.RESET}")
            self.logger.error(f"خطأ في التنفيذ: {e}")

if __name__ == "__main__":
    snike = Snike()
    snike.main()