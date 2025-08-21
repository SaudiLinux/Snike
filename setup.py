#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Snike Setup Script - سكريبت التثبيت التلقائي
Author: SayerLinux
Website: https://github.com/SaudiLinux
Email: SayerLinux@gmail.com
"""

import os
import sys
import subprocess
import platform
import shutil
from pathlib import Path

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'

class SnikeSetup:
    def __init__(self):
        self.system = platform.system()
        self.python_version = sys.version_info
        
    def print_banner(self):
        """عرض شعار التثبيت"""
        banner = f"""
{Colors.CYAN}
███████╗███╗░░██╗██╗██████╗░░█████╗░███╗░░██╗
██╔════╝████╗░██║██║██╔══██╗██╔══██╗████╗░██║
█████╗░░██╔██╗██║██║██████╔╝███████║██╔██╗██║
██╔══╝░░██║╚████║██║██╔═══╝░██╔══██║██║╚████║
███████╗██║░╚███║██║██║░░░░░██║░░██║██║░╚███║
╚══════╝╚═╝░░╚══╝╚═╝╚═╝░░░░░╚═╝░░╚═╝╚═╝░░╚══╝
{Colors.YELLOW}
أداة اختبار الأمان المتقدمة - سكريبت التثبيت
{Colors.RESET}
        """
        print(banner)
    
    def check_python(self):
        """التحقق من إصدار Python"""
        print(f"{Colors.BLUE}[CHECK] التحقق من إصدار Python...{Colors.RESET}")
        
        if self.python_version.major < 3 or (self.python_version.major == 3 and self.python_version.minor < 7):
            print(f"{Colors.RED}[ERROR] Python 3.7 أو أحدث مطلوب{Colors.RESET}")
            return False
        
        print(f"{Colors.GREEN}[OK] Python {self.python_version.major}.{self.python_version.minor}.{self.python_version.micro}{Colors.RESET}")
        return True
    
    def install_pip_package(self, package):
        """تثبيت حزمة pip"""
        try:
            subprocess.run([sys.executable, '-m', 'pip', 'install', package], 
                         check=True, capture_output=True)
            print(f"{Colors.GREEN}[OK] تم تثبيت {package}{Colors.RESET}")
            return True
        except subprocess.CalledProcessError:
            print(f"{Colors.RED}[ERROR] فشل تثبيت {package}{Colors.RESET}")
            return False
    
    def install_system_package(self, package):
        """تثبيت حزمة نظام"""
        try:
            if self.system == "Linux":
                subprocess.run(['sudo', 'apt-get', 'install', '-y', package], 
                             check=True, capture_output=True)
            elif self.system == "Darwin":
                subprocess.run(['brew', 'install', package], 
                             check=True, capture_output=True)
            elif self.system == "Windows":
                print(f"{Colors.YELLOW}[INFO] يرجى تثبيت {package} يدوياً على Windows{Colors.RESET}")
                return False
            
            print(f"{Colors.GREEN}[OK] تم تثبيت {package}{Colors.RESET}")
            return True
        except subprocess.CalledProcessError:
            print(f"{Colors.YELLOW}[WARNING] فشل تثبيت {package} - قد يكون مثبت بالفعل{Colors.RESET}")
            return False
    
    def install_requirements(self):
        """تثبيت المتطلبات من ملف requirements.txt"""
        print(f"{Colors.BLUE}[INSTALL] تثبيت المتطلبات Python...{Colors.RESET}")
        
        if os.path.exists('requirements.txt'):
            try:
                subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'], 
                             check=True, capture_output=True)
                print(f"{Colors.GREEN}[OK] تم تثبيت جميع المتطلبات{Colors.RESET}")
                return True
            except subprocess.CalledProcessError as e:
                print(f"{Colors.RED}[ERROR] فشل تثبيت المتطلبات: {e}{Colors.RESET}")
                return False
        else:
            print(f"{Colors.RED}[ERROR] ملف requirements.txt غير موجود{Colors.RESET}")
            return False
    
    def install_sqlmap(self):
        """تثبيت SQLMap"""
        print(f"{Colors.BLUE}[INSTALL] تثبيت SQLMap...{Colors.RESET}")
        
        try:
            # محاولة تشغيل SQLMap للتحقق
            result = subprocess.run(['sqlmap', '--version'], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"{Colors.GREEN}[OK] SQLMap مثبت بالفعل{Colors.RESET}")
                return True
        except FileNotFoundError:
            pass
        
        # تثبيت SQLMap حسب النظام
        if self.system == "Linux":
            try:
                subprocess.run(['sudo', 'apt-get', 'update'], check=True, capture_output=True)
                subprocess.run(['sudo', 'apt-get', 'install', '-y', 'sqlmap'], check=True, capture_output=True)
                print(f"{Colors.GREEN}[OK] تم تثبيت SQLMap{Colors.RESET}")
                return True
            except:
                print(f"{Colors.YELLOW}[WARNING] فشل تثبيت SQLMap - قم بتثبيته يدوياً{Colors.RESET}")
        elif self.system == "Darwin":
            try:
                subprocess.run(['brew', 'install', 'sqlmap'], check=True, capture_output=True)
                print(f"{Colors.GREEN}[OK] تم تثبيت SQLMap{Colors.RESET}")
                return True
            except:
                print(f"{Colors.YELLOW}[WARNING] فشل تثبيت SQLMap - قم بتثبيته يدوياً{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[INFO] يرجى تثبيت SQLMap يدوياً من: https://github.com/sqlmapproject/sqlmap{Colors.RESET}")
        
        return False
    
    def install_chrome_driver(self):
        """تثبيت ChromeDriver عبر webdriver-manager"""
        print(f"{Colors.BLUE}[INSTALL] تثبيت ChromeDriver...{Colors.RESET}")
        
        try:
            import webdriver_manager.chrome as chrome_manager
            from webdriver_manager.chrome import ChromeDriverManager
            
            # هذا سيقوم بتثبيت ChromeDriver تلقائياً
            ChromeDriverManager().install()
            print(f"{Colors.GREEN}[OK] تم تثبيت ChromeDriver{Colors.RESET}")
            return True
        except ImportError:
            print(f"{Colors.YELLOW}[WARNING] webdriver-manager غير مثبت{Colors.RESET}")
            return self.install_pip_package('webdriver-manager')
    
    def create_directories(self):
        """إنشاء المجلدات المطلوبة"""
        print(f"{Colors.BLUE}[CREATE] إنشاء المجلدات...{Colors.RESET}")
        
        directories = ['logs', 'reports', 'screenshots', 'sqlmap_results']
        
        for directory in directories:
            if not os.path.exists(directory):
                os.makedirs(directory)
                print(f"{Colors.GREEN}[OK] تم إنشاء مجلد {directory}{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}[INFO] مجلد {directory} موجود بالفعل{Colors.RESET}")
        
        return True
    
    def set_permissions(self):
        """تعيين الأذونات المناسبة"""
        print(f"{Colors.BLUE}[PERMISSION] تعيين الأذونات...{Colors.RESET}")
        
        if self.system != "Windows":
            try:
                os.chmod('snike.py', 0o755)
                print(f"{Colors.GREEN}[OK] تم تعيين أذونات التنفيذ{Colors.RESET}")
            except:
                print(f"{Colors.YELLOW}[WARNING] فشل تعيين الأذونات{Colors.RESET}")
        
        return True
    
    def verify_installation(self):
        """التحقق من التثبيت"""
        print(f"{Colors.BLUE}[VERIFY] التحقق من التثبيت...{Colors.RESET}")
        
        checks = [
            ('requests', 'import requests'),
            ('selenium', 'from selenium import webdriver'),
            ('webdriver-manager', 'from webdriver_manager.chrome import ChromeDriverManager'),
        ]
        
        all_good = True
        for package, test_import in checks:
            try:
                exec(test_import)
                print(f"{Colors.GREEN}[OK] {package} يعمل بشكل صحيح{Colors.RESET}")
            except ImportError:
                print(f"{Colors.RED}[ERROR] {package} غير مثبت بشكل صحيح{Colors.RESET}")
                all_good = False
        
        return all_good
    
    def print_success_message(self):
        """عرض رسالة النجاح"""
        print(f"\n{Colors.GREEN}╔══════════════════════════════════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.GREEN}║                        ✅ تم إكمال التثبيت بنجاح!                          ║{Colors.RESET}")
        print(f"{Colors.GREEN}╚══════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}")
        
        print(f"\n{Colors.CYAN}📋 دليل الاستخدام السريع:{Colors.RESET}")
        print(f"{Colors.WHITE}   python snike.py -u https://example.com{Colors.RESET}")
        print(f"{Colors.WHITE}   python snike.py -u https://example.com -v{Colors.RESET}")
        
        print(f"\n{Colors.YELLOW}📁 المجلدات التي تم إنشاؤها:{Colors.RESET}")
        print(f"{Colors.WHITE}   • logs/ - سجلات التنفيذ{Colors.RESET}")
        print(f"{Colors.WHITE}   • reports/ - التقارير الناتجة{Colors.RESET}")
        print(f"{Colors.WHITE}   • screenshots/ - لقطات الشاشة{Colors.RESET}")
        print(f"{Colors.WHITE}   • sqlmap_results/ - نتائج SQLMap{Colors.RESET}")
        
        print(f"\n{Colors.PURPLE}🔗 روابط مفيدة:{Colors.RESET}")
        print(f"{Colors.WHITE}   • GitHub: https://github.com/SaudiLinux{Colors.RESET}")
        print(f"{Colors.WHITE}   • Email: SayerLinux@gmail.com{Colors.RESET}")
    
    def run_setup(self):
        """تشغيل عملية التثبيت الكاملة"""
        self.print_banner()
        
        print(f"{Colors.YELLOW}بدء عملية التثبيت...{Colors.RESET}")
        print(f"{Colors.CYAN}نظام التشغيل: {self.system}{Colors.RESET}")
        print(f"{Colors.CYAN}إصدار Python: {self.python_version.major}.{self.python_version.minor}.{self.python_version.micro}{Colors.RESET}")
        print()
        
        steps = [
            ("التحقق من Python", self.check_python),
            ("تثبيت المتطلبات", self.install_requirements),
            ("تثبيت SQLMap", self.install_sqlmap),
            ("تثبيت ChromeDriver", self.install_chrome_driver),
            ("إنشاء المجلدات", self.create_directories),
            ("تعيين الأذونات", self.set_permissions),
            ("التحقق من التثبيت", self.verify_installation),
        ]
        
        success = True
        for step_name, step_func in steps:
            try:
                if not step_func():
                    success = False
            except Exception as e:
                print(f"{Colors.RED}[ERROR] خطأ في {step_name}: {e}{Colors.RESET}")
                success = False
        
        if success:
            self.print_success_message()
        else:
            print(f"\n{Colors.RED}❌ فشلت بعض خطوات التثبيت. يرجى التحقق من الأخطاء أعلاه.{Colors.RESET}")
            print(f"{Colors.YELLOW}💡 حاول تثبيت المتطلبات يدوياً: pip install -r requirements.txt{Colors.RESET}")

if __name__ == "__main__":
    setup = SnikeSetup()
    setup.run_setup()