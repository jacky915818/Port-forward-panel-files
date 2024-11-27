import os
import time
import socket
import logging
import subprocess
import netifaces
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import psutil
import requests
from flask_cors import CORS
import sqlite3

# 配置日志
logging.basicConfig(
    filename='/var/log/port-forward-web.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# 创建Flask应用
app = Flask(__name__)
CORS(app)
app.secret_key = os.urandom(24)

# 全局变量用于存储网络数据
network_data = {
    'last_net_io': None,
    'last_time': None,
    'upload_points': [],
    'download_points': []
}

# 读取配置文件
try:
    if os.path.exists('/opt/port-forward/config.py'):
        with open('/opt/port-forward/config.py', 'r') as f:
            exec(f.read(), globals())
except Exception as e:
    logger.error(f"读取配置文件失败: {str(e)}")
    PORT = 5000
    ACCESS_PASSWORD = ''

# 添加获取服务器ID的函数
def get_server_id():
    """获取服务器唯一标识"""
    try:
        # 优先使用系统UUID
        with open('/sys/class/dmi/id/product_uuid', 'r') as f:
            system_uuid = f.read().strip()
            return system_uuid
    except:
        try:
            # 备选：使用第一个网卡的MAC地址
            interfaces = netifaces.interfaces()
            for interface in interfaces:
                if interface != 'lo':  # 排除回环接口
                    mac = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']
                    return mac.replace(':', '')
        except:
            # 最后备选：使用主机名
            return socket.gethostname()

# 添加登录验证装饰器
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# 添加授权验证装饰器
def license_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('license_key'):
            return redirect(url_for('bind_license'))
        return f(*args, **kwargs)
    return decorated_function

# 登录页面
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == ACCESS_PASSWORD:
            session['logged_in'] = True
            return redirect('/')
        return render_template('login.html', error='密码错误')
    return render_template('login.html')

# 主页面
@app.route('/')
@login_required
@license_required
def index():
    return render_template('panel.html')

# 退出登录
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/bind_license', methods=['GET', 'POST'])
def bind_license():
    """绑定授权码页面"""
    try:
        if request.method == 'POST':
            license_key = request.form.get('license_key')
            logger.info(f"收到绑定授权码请求: {license_key}")
            
            if not license_key:
                return render_template('bind_license.html', error='请输入授权码')

            # 获取服务器ID
            server_id = get_server_id()
            logger.info(f"获取到服务器ID: {server_id}")
            
            # 获取服务器真实IP
            server_ip = get_server_real_ip()
            
            # 验证授权码
            try:
                # 先重置旧的授权状态
                reset_response = requests.post(
                    'https://zhuanfa.demaweb3.com/admin/api/reset_ports.php',
                    data={
                        'license_key': session.get('license_key'),  # 旧的授权码
                        'server_id': server_id,
                        'action': 'reset'
                    },
                    verify=False,
                    timeout=10
                )
                
                # 清理所有现有的转发
                services = subprocess.Popen(['systemctl', 'list-unit-files', 'port-forward-*.service'],
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
                output, _ = services.communicate()
                
                for line in output.decode().split('\n'):
                    if 'port-forward-' in line and '.service' in line:
                        service_name = line.split()[0]
                        if service_name != 'port-forward-web.service':
                            service_path = f'/etc/systemd/system/{service_name}'
                            if os.path.exists(service_path):
                                os.system(f'systemctl stop {service_name}')
                                os.system(f'systemctl disable {service_name}')
                                os.remove(service_path)
                
                os.system('systemctl daemon-reload')
                
                # 验证新的授权码
                verify_response = requests.post(
                    'https://zhuanfa.demaweb3.com/admin/api/verify_license.php',
                    data={
                        'license_key': license_key,
                        'server_id': server_id,
                        'client_ip': server_ip,  # 使用真实IP
                        'action': 'verify'
                    },
                    verify=False,
                    timeout=10
                )
                
                if verify_response.ok:
                    # 更新激活状态
                    activate_response = requests.post(
                        'https://zhuanfa.demaweb3.com/admin/api/activate_license.php',
                        data={
                            'license_key': license_key,
                            'server_id': server_id,
                            'client_ip': server_ip  # 使用真实IP
                        },
                        verify=False,
                        timeout=10
                    )
                    
                    if not activate_response.ok:
                        logger.error(f"更新激活状态失败: {activate_response.text}")
                
                logger.info(f"验证授权码响应: {verify_response.text}")
                
                if not verify_response.ok:
                    return render_template('bind_license.html', error='授权码验证失败')
                
                try:
                    license_data = verify_response.json()
                except Exception as e:
                    logger.error(f"解析响应JSON败: {str(e)}")
                    return render_template('bind_license.html', error='验证授权码失败')
                
                if not license_data.get('valid'):
                    error_msg = license_data.get('message', '无效的授权码')
                    return render_template('bind_license.html', error=error_msg)

                # 保存新的授权码到配置文件
                config_path = '/opt/port-forward/config.py'
                try:
                    # 读取现有配置
                    current_config = {}
                    if os.path.exists(config_path):
                        with open(config_path, 'r') as f:
                            exec(f.read(), {}, current_config)
                    
                    # 更新配置
                    with open(config_path, 'w') as f:
                        f.write("# -*- coding: utf-8 -*-\n")
                        f.write(f"ACCESS_PASSWORD = '{current_config.get('ACCESS_PASSWORD', '')}'\n")
                        f.write(f"PORT = {current_config.get('PORT', 5000)}\n")
                        f.write(f"LICENSE_KEY = '{license_key}'\n")
                    
                    # 设置session
                    session['license_key'] = license_key
                    
                    # 重定向到面板
                    return redirect('/')
                    
                except Exception as e:
                    logger.error(f"保存配置文件失败: {str(e)}")
                    return render_template('bind_license.html', error='保存授权码失败')
                    
            except requests.exceptions.RequestException as e:
                logger.error(f"请求验证授权码API失败: {str(e)}")
                return render_template('bind_license.html', error='验证授权码失败，请稍后重试')

        return render_template('bind_license.html')
        
    except Exception as e:
        logger.error(f"绑定授权码失败: {str(e)}")
        return render_template('bind_license.html', error='系统错误，请稍后重试') 

# 添加字节格式化函数
def format_bytes(bytes):
    """将字节数转换为人可的"""
    if bytes == 0:
        return "0 B"
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    i = 0
    while bytes >= 1024 and i < len(units)-1:
        bytes /= 1024.
        i += 1
    return f"{bytes:.2f} {units[i]}"

@app.route('/system_status')
@login_required
def system_status():
    try:
        if not session.get('logged_in'):
            return jsonify({
                'status': 'error',
                'message': '会话已过期，请重新登录',
                'redirect': '/login'
            }), 401

        # 获取CPU使用率
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count()
        
        # 获取内存使用情况
        memory = psutil.virtual_memory()
        memory_total = round(memory.total / (1024 * 1024 * 1024), 2)  # GB
        memory_used = round(memory.used / (1024 * 1024), 2)  # MB
        memory_free = round(memory.available / (1024 * 1024), 2)  # MB
        
        # 获取磁盘使用情况
        disk = psutil.disk_usage('/')
        disk_total = round(disk.total / (1024 * 1024 * 1024), 2)  # GB
        disk_used = round(disk.used / (1024 * 1024 * 1024), 2)  # GB
        disk_free = round(disk.free / (1024 * 1024 * 1024), 2)  # GB
        
        # 获取网络IO
        net_io = psutil.net_io_counters()
        bytes_sent = format_bytes(net_io.bytes_sent)
        bytes_recv = format_bytes(net_io.bytes_recv)
        
        return jsonify({
            'status': 'success',
            'data': {
                'cpu': {
                    'percent': cpu_percent,
                    'cores': cpu_count
                },
                'memory': {
                    'total': f'{memory_total} GB',
                    'used': f'{memory_used} MB',
                    'free': f'{memory_free} MB',
                    'percent': memory.percent
                },
                'disk': {
                    'total': f'{disk_total} GB',
                    'used': f'{disk_used} GB',
                    'free': f'{disk_free} GB',
                    'percent': disk.percent
                },
                'network': {
                    'bytes_sent': bytes_sent,
                    'bytes_recv': bytes_recv,
                    'packets_sent': net_io.packets_sent,
                    'packets_recv': net_io.packets_recv
                }
            }
        })
    except Exception as e:
        logger.error(f"获取系统状态失败: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': '获取系统状态失败',
            'error': str(e)
        }), 500

# 添加获授权信息的路由
@app.route('/license_info')
@login_required
def license_info():
    try:
        license_key = session.get('license_key')
        if not license_key:
            return jsonify({
                'status': 'error',
                'message': '未绑定授权码'
            })
        
        # 获取服务器ID
        server_id = get_server_id()
        
        # 获取服务器真实IP
        server_ip = get_server_real_ip()
        
        # 验证授权码
        verify_response = requests.post(
            'https://zhuanfa.demaweb3.com/admin/api/verify_license.php',
            data={
                'license_key': license_key,
                'server_id': server_id,
                'client_ip': server_ip,  # 使用真实IP
                'action': 'verify'
            },
            verify=False,
            timeout=10
        )
        
        if not verify_response.ok:
            return jsonify({
                'status': 'error',
                'message': '授权码验证失败'
            })
            
        license_data = verify_response.json()
        if not license_data.get('valid'):
            return jsonify({
                'status': 'error',
                'message': license_data.get('message', '授权码无效')
            })
            
        # 直接使用数据库中的端口使用数
        return jsonify({
            'status': 'success',
            'license_key': license_key,
            'port_limit': license_data.get('port_limit', 0),
            'used_ports': license_data.get('used_ports', 0),  # 使用数据库中的值
            'expires_at': license_data.get('expires_at', '')
        })
        
    except Exception as e:
        logger.error(f"获取授权信息失败: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': '获取授权信息失败'
        })

# 添加检查端口是否被占用的函数
def check_port_in_use(port):
    """检查端口是否被占用"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('127.0.0.1', int(port)))
        sock.close()
        return result == 0
    except Exception as e:
        logger.error(f"检查端口占用失败: {str(e)}")
        return True

# 添加获取实际转发数量的函数
def get_active_forwards_count():
    """获取实际的转发数量"""
    try:
        # 获取所有转发服务
        services = subprocess.Popen(['systemctl', 'list-unit-files', 'port-forward-*.service'],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
        output, _ = services.communicate()
        
        # 只统计实际存在的转发服务（排除面板服务
        count = 0
        for line in output.decode().split('\n'):
            if 'port-forward-' in line and '.service' in line:
                service_name = line.split()[0]
                # 排除面板服���
                if service_name == 'port-forward-web.service':
                    continue
                    
                service_path = f'/etc/systemd/system/{service_name}'
                if os.path.exists(service_path):
                    count += 1
        
        logger.info(f"当前实际使用的端口数: {count}")
        return count
    except Exception as e:
        logger.error(f"获取转发数量败: {str(e)}")
        return 0

# 修改端口转发路由
@app.route('/setup_forward', methods=['POST'])
@login_required
@license_required
def setup_forward():
    try:
        # 获取表单数据
        local_port = request.form.get('local_port')
        target_host = request.form.get('target_host')
        target_port = request.form.get('target_port')
        protocol = request.form.get('protocol', 'tcp')
        
        logger.info(f"收到端口转发请求: {local_port} -> {target_host}:{target_port} ({protocol})")
        
        # 验证参数
        if not all([local_port, target_host, target_port]):
            return jsonify({
                'status': 'error',
                'message': '请填写完整的转发信息'
            })

        # 先获取授权信息，检查可用端口数
        license_key = session.get('license_key')
        server_id = get_server_id()
        
        verify_response = requests.post(
            'https://zhuanfa.demaweb3.com/admin/api/verify_license.php',
            data={
                'license_key': license_key,
                'server_id': server_id,
                'client_ip': request.remote_addr,
                'action': 'verify'
            },
            verify=False,
            timeout=10
        )
        
        if not verify_response.ok:
            return jsonify({
                'status': 'error',
                'message': '授权验证失败'
            })
            
        license_data = verify_response.json()
        if not license_data.get('valid'):
            return jsonify({
                'status': 'error',
                'message': license_data.get('message', '授权码无效')
            })
            
        # 检查可用端口数
        port_limit = license_data.get('port_limit', 0)
        used_ports = license_data.get('used_ports', 0)
        
        if port_limit != -1:  # 如果不是无限制
            available_ports = port_limit - used_ports
            if available_ports <= 0:
                return jsonify({
                    'status': 'error',
                    'message': f'添加失败：已达到端口数量限制（{port_limit}个）'
                })

        # 检查端口是否被占用
        if check_port_in_use(local_port):
            return jsonify({
                'status': 'error',
                'message': f'端口 {local_port} 已被占用，请使用其他端口'
            })

        # 创建转发服务
        service_name = f'port-forward-{local_port}'
        service_path = f'/etc/systemd/system/{service_name}.service'
        
        if os.path.exists(service_path):
            return jsonify({
                'status': 'error',
                'message': '端口已被使用'
            })
            
        # 修改服务内容，根据协议类型使用不同的 socat 命令
        if protocol.lower() == 'https':
            logger.info(f"创建HTTPS转发服务: {local_port} -> {target_host}:{target_port}")
            service_content = f"""[Unit]
Description=Port Forward {local_port} -> {target_host}:{target_port} (HTTPS)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/socat TCP-LISTEN:{local_port},fork,reuseaddr SSL:{target_host}:{target_port},verify=0,method=TLS1.2
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"""
        else:
            logger.info(f"创建TCP转发服务: {local_port} -> {target_host}:{target_port}")
            service_content = f"""[Unit]
Description=Port Forward {local_port} -> {target_host}:{target_port}
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/socat TCP-LISTEN:{local_port},fork,reuseaddr TCP:{target_host}:{target_port}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"""
        
        # 保存服务文件
        with open(service_path, 'w') as f:
            f.write(service_content)
            
        logger.info(f"服务文件已创建: {service_path}")
            
        # 重新加载systemd配置
        os.system('systemctl daemon-reload')
        
        # 启动服务
        logger.info(f"正在启动服务: {service_name}")
        start_result = os.system(f'systemctl start {service_name}')
        logger.info(f"启动命令返回值: {start_result}")
        
        # 检查服务状态
        status = subprocess.Popen(['systemctl', 'status', service_name], 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE)
        output, error = status.communicate()
        service_status = output.strip().decode()
        logger.info(f"服务状态输出: {service_status}")
        
        if error:
            logger.error(f"服务状态错误: {error.decode()}")
        
        # 获取服务是否活跃
        active_status = subprocess.Popen(['systemctl', 'is-active', service_name], 
                                       stdout=subprocess.PIPE, 
                                       stderr=subprocess.PIPE)
        active_output, _ = active_status.communicate()
        service_active = active_output.strip().decode()
        
        if service_active != 'active':
            # 如果启动失败，获取详细的错误信息
            journal_cmd = f"journalctl -u {service_name} -n 50 --no-pager"
            journal_output = subprocess.check_output(journal_cmd, shell=True).decode()
            logger.error(f"服务启动失败，日志输出:\n{journal_output}")
            
            # 清理并返回错误
            os.system(f'systemctl stop {service_name}')
            os.system(f'systemctl disable {service_name}')
            os.remove(service_path)
            os.system('systemctl daemon-reload')
            
            return jsonify({
                'status': 'error',
                'message': f'服务启动失败，请检查日志:\n{journal_output}'
            })

        # 更新数据库中的端口使用数
        update_response = requests.post(
            'https://zhuanfa.demaweb3.com/admin/api/update_ports.php',
            data={
                'license_key': license_key,
                'server_id': server_id,
                'action': 'increment',
                'client_ip': request.remote_addr
            },
            verify=False,
            timeout=10
        )
        
        if not update_response.ok:
            logger.error(f"更新端口使用数失败: {update_response.text}")
            return jsonify({
                'status': 'error',
                'message': '更新端口使用数失败'
            })
            
        return jsonify({
            'status': 'success',
            'message': '创建成功'
        })
        
    except Exception as e:
        logger.error(f"创建转发失败: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        })
# 添加获转发列表的路由
@app.route('/get_forwards')
@login_required
def get_forwards():
    try:
        forwards = []
        services = subprocess.Popen(['systemctl', 'list-unit-files', 'port-forward-*.service'],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
        output, error = services.communicate()
        
        logger.info(f"获取到的服务列表: {output.decode()}")
        
        for line in output.decode().split('\n'):
            if 'port-forward-' in line and '.service' in line:
                service_name = line.split()[0]
                if service_name == 'port-forward-web.service':
                    continue
                    
                service_path = f'/etc/systemd/system/{service_name}'
                if not os.path.exists(service_path):
                    continue
                    
                # 从服务名称中提取端口号
                local_port = service_name.replace('port-forward-', '').replace('.service', '')
                
                # 获取服务状态
                status = subprocess.Popen(['systemctl', 'is-active', service_name],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
                status_output, _ = status.communicate()
                service_status = status_output.strip().decode()
                
                # 获取服务配置
                config = subprocess.Popen(['systemctl', 'cat', service_name],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
                config_output, config_error = config.communicate()
                config_text = config_output.decode()
                
                try:
                    # 解析目标信息
                    for line in config_text.split('\n'):
                        if 'ExecStart=' in line:
                            socat_cmd = line.split('ExecStart=')[1].strip()
                            
                            # 解析目标信息
                            if 'SSL:' in socat_cmd:
                                # HTTPS 转发
                                target_part = socat_cmd.split('SSL:')[1].split(',')[0]
                                protocol = 'https'
                            else:
                                # TCP 转发
                                target_part = socat_cmd.split('TCP:')[1].split(',')[0]
                                protocol = 'tcp'
                            
                            target_host, target_port = target_part.rsplit(':', 1)
                            
                            forwards.append({
                                'local_port': local_port,  # 使用从服务名称中提取的端口号
                                'target_host': target_host,
                                'target_port': target_port,
                                'protocol': protocol,
                                'status': service_status
                            })
                            break
                            
                except Exception as e:
                    logger.error(f"解析服务配置失: {str(e)}")
                    continue
        
        logger.info(f"最终转发列表: {forwards}")
        return jsonify({
            'status': 'success',
            'forwards': forwards
        })
        
    except Exception as e:
        logger.error(f"获取转发列表失败: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'获取转发列表失败: {str(e)}'
        })

# 修改删除转发的路由
@app.route('/delete_forward', methods=['POST'])
@login_required
def delete_forward():
    try:
        local_port = request.form.get('local_port')
        if not local_port:
            return jsonify({
                'status': 'error',
                'message': '缺少端口参数'
            })
            
        service_name = f'port-forward-{local_port}'
        
        # 停止并禁用服务
        os.system(f'systemctl stop {service_name}')
        os.system(f'systemctl disable {service_name}')
        
        # 删除服务文件
        service_path = f'/etc/systemd/system/{service_name}.service'
        if os.path.exists(service_path):
            os.remove(service_path)
            
            # 更新数据库中的端口使用数
            license_key = session.get('license_key')
            server_id = get_server_id()
            
            update_response = requests.post(
                'https://zhuanfa.demaweb3.com/admin/api/update_ports.php',
                data={
                    'license_key': license_key,
                    'server_id': server_id,
                    'action': 'decrement',  # 减少端口使用数
                    'client_ip': request.remote_addr
                },
                verify=False,
                timeout=10
            )
            
            if not update_response.ok:
                logger.error(f"更新端口使用数失败: {update_response.text}")
            
        # 重新加载systemd配置
        os.system('systemctl daemon-reload')
        
        return jsonify({
            'status': 'success',
            'message': '转发已删除'
        })
        
    except Exception as e:
        logger.error(f"删除转发失败: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': '删除失败: ' + str(e)
        })

# 添加停止转发的路由
@app.route('/stop_forward', methods=['POST'])
@login_required
def stop_forward():
    try:
        local_port = request.form.get('local_port')
        if not local_port:
            return jsonify({
                'status': 'error',
                'message': '缺少端口参数'
            })
            
        service_name = f'port-forward-{local_port}'
        os.system(f'systemctl stop {service_name}')
        
        return jsonify({
            'status': 'success',
            'message': '转发已停止'
        })
        
    except Exception as e:
        logger.error(f"停止转发失败: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'停止失败: {str(e)}'
        })

# 添加启动转发的路由
@app.route('/start_forward', methods=['POST'])
@login_required
def start_forward():
    try:
        local_port = request.form.get('local_port')
        if not local_port:
            return jsonify({
                'status': 'error',
                'message': '缺少端口参数'
            })
            
        service_name = f'port-forward-{local_port}'
        os.system(f'systemctl start {service_name}')
        
        return jsonify({
            'status': 'success',
            'message': '转发已启动'
        })
        
    except Exception as e:
        logger.error(f"启动转发失败: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'启动失败: {str(e)}'
        })

# 添加重置端口的路由
@app.route('/reset_forwards', methods=['POST'])
@login_required
@license_required
def reset_forwards():
    try:
        # 获取授权码
        license_key = session.get('license_key')
        if not license_key:
            raise Exception('未找到授权码信息')
            
        # 获取服务器ID
        server_id = get_server_id()
        
        # 调用重置API
        reset_response = requests.post(
            'https://zhuanfa.demaweb3.com/admin/api/reset_ports.php',
            data={
                'license_key': license_key,
                'server_id': server_id,
                'action': 'reset'
            },
            verify=False,
            timeout=10
        )
        
        if not reset_response.ok:
            raise Exception('重置端口数量失败')
            
        reset_data = reset_response.json()
        if reset_data.get('status') != 'success':
            raise Exception(reset_data.get('message', '重置端口数量失败'))

        # 获取所有转发服务
        services = subprocess.Popen(['systemctl', 'list-unit-files', 'port-forward-*.service'],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
        output, _ = services.communicate()
        
        success_count = 0
        failed_count = 0
        
        # 停止并删除所有转发服务（除了面板服务）
        for line in output.decode().split('\n'):
            if 'port-forward-' in line and '.service' in line:
                try:
                    service_name = line.split()[0]
                    
                    # 跳过面板服务
                    if service_name == 'port-forward-web.service':
                        continue
                    
                    service_path = f'/etc/systemd/system/{service_name}'
                    
                    # 停止并禁用服务
                    os.system(f'systemctl stop {service_name}')
                    os.system(f'systemctl disable {service_name}')
                    
                    # 删除服务文件
                    if os.path.exists(service_path):
                        os.remove(service_path)
                        success_count += 1
                        logger.info(f"成功删除服务 {service_name}")
                            
                except Exception as e:
                    logger.error(f"处理服务 {service_name} 失败: {str(e)}")
                    failed_count += 1
                    continue
        
        # 重新加载systemd配置
        os.system('systemctl daemon-reload')
        
        message = f'成功重置 {success_count} 个转发'
        if failed_count > 0:
            message += f'，{failed_count} 个失败'
            
        return jsonify({
            'status': 'success',
            'message': message
        })
        
    except Exception as e:
        logger.error(f"重置端口转发失败: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'重置失败: {str(e)}'
        })

# 添加获取端口流量的路由
@app.route('/port_traffic/<int:port>')
@login_required
def get_port_traffic(port):
    try:
        # 获取授权码
        license_key = session.get('license_key')
        if not license_key:
            return jsonify({
                'status': 'error',
                'message': '未找到授权码信息'
            })
            
        # 获取流量统计
        traffic_response = requests.get(
            'https://zhuanfa.demaweb3.com/admin/api/get_traffic.php',
            params={
                'license_key': license_key,
                'local_port': port
            },
            verify=False,
            timeout=10
        )
        
        if not traffic_response.ok:
            return jsonify({
                'status': 'error',
                'message': '获取流量统计失败'
            })
            
        try:
            traffic_data = traffic_response.json()
            return jsonify(traffic_data)
        except Exception as e:
            logger.error(f"解析流量数据失败: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': '解析流量数据失败'
            })
        
    except Exception as e:
        logger.error(f"获取端口流量失败: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# API相关路由
@app.route('/api/token', methods=['POST'])
@login_required
def create_api_token():
    """创建API令牌"""
    try:
        description = request.form.get('description', '')
        expires_days = int(request.form.get('expires_days', 30))
        license_key = session.get('license_key')
        
        response = requests.post(
            'https://zhuanfa.demaweb3.com/admin/api/create_token.php',
            data={
                'license_key': license_key,
                'description': description,
                'expires_days': expires_days,
                'client_ip': request.remote_addr
            },
            verify=False,
            timeout=10
        )
        
        if not response.ok:
            raise Exception('创建令牌失败')
            
        return jsonify(response.json())
    except Exception as e:
        logger.error(f"创建API令牌失败: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'创建令牌失败: {str(e)}'
        })

def verify_api_token(token):
    """验证API令牌"""
    try:
        response = requests.post(
            'https://zhuanfa.demaweb3.com/admin/api/verify_token.php',
            data={'token': token},
            verify=False,
            timeout=10
        )
        
        if not response.ok:
            return False
            
        result = response.json()
        return result.get('status') == 'success'
    except:
        return False

# 添加API令牌验证装饰器
def api_auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('X-API-Token')
        if not token or not verify_api_token(token):
            return jsonify({
                'status': 'error',
                'message': 'API令牌无效或已过期'
            }), 401
        return f(*args, **kwargs)
    return decorated_function

# 修改API路由，添加验证装饰
@app.route('/api/v1/forwards', methods=['GET'])
@api_auth_required
def api_get_forwards():
    """取转发列表API"""
    try:
        forwards = []
        # 获取所有发服务
        services = subprocess.Popen(['systemctl', 'list-unit-files', 'port-forward-*.service'],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
        output, error = services.communicate()
        
        logger.info(f"获取到的服务列表: {output.decode()}")
        if error:
            logger.error(f"获取服务列表错误: {error.decode()}")
        
        # 解析服务列表
        for line in output.decode().split('\n'):
            if 'port-forward-' in line and '.service' in line:
                service_name = line.split()[0]
                service_path = f'/etc/systemd/system/{service_name}'
                
                # 只处理实际存在的服务文件
                if not os.path.exists(service_path):
                    continue
                    
                # 跳过面板服务
                if service_name == 'port-forward-web.service':
                    continue
                    
                local_port = service_name.replace('port-forward-', '').replace('.service', '')
                
                logger.info(f"处理服务: {service_name}, 本地端口: {local_port}")
                
                # 获取服务状态
                status = subprocess.Popen(['systemctl', 'is-active', service_name],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
                status_output, _ = status.communicate()
                service_status = status_output.strip().decode()
                
                # 获取服务配置
                config = subprocess.Popen(['systemctl', 'cat', service_name],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
                config_output, config_error = config.communicate()
                config_text = config_output.decode()
                
                if config_error:
                    logger.error(f"获取服务配置错误: {config_error.decode()}")
                
                logger.info(f"服务配置: {config_text}")
                
                try:
                    # 解析目标地址和端口
                    for line in config_text.split('\n'):
                        if 'ExecStart=' in line:
                            socat_cmd = line.split('ExecStart=')[1].strip()
                            listen_part = socat_cmd.split(',')[0].split(':')[1]  # 获取本地端口
                            target_part = socat_cmd.split(',')[-1].strip()  # 获取目标地址和端口
                            
                            protocol = target_part.split(':')[0].replace('TCP', 'tcp').replace('SSL', 'https')
                            target_host = target_part.split(':')[1]
                            target_port = target_part.split(':')[2]
                            
                            forwards.append({
                                'local_port': local_port,
                                'target_host': target_host,
                                'target_port': target_port,
                                'protocol': protocol,
                                'status': service_status
                            })
                            
                            logger.info(f"添加转发记录: {forwards[-1]}")
                            break
                            
                except Exception as e:
                    logger.error(f"解析务配置失败: {str(e)}")
                    continue
        
        logger.info(f"最终转发列表: {forwards}")
        return jsonify({
            'status': 'success',
            'data': forwards
        })
    except Exception as e:
        logger.error(f"API获取转发列表失败: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/v1/forwards', methods=['POST'])
@api_auth_required
def api_create_forward():
    """创建端口转发API"""
    try:
        # 获取参数
        data = request.get_json()
        if not data:
            return jsonify({
                'status': 'error',
                'message': '无效的请求数据'
            }), 400
            
        local_port = data.get('local_port')
        target_host = data.get('target_host')
        target_port = data.get('target_port')
        protocol = data.get('protocol', 'tcp')
        
        # 验证参数
        if not all([local_port, target_host, target_port]):
            return jsonify({
                'status': 'error',
                'message': '缺少必要参数'
            }), 400
        
        # 检查端口是否被占用
        if check_port_in_use(local_port):
            return jsonify({
                'status': 'error',
                'message': '端已被占用'
            }), 400

        # 获取令牌信息
        token = request.headers.get('X-API-Token')
        verify_response = requests.post(
            'https://zhuanfa.demaweb3.com/admin/api/verify_token.php',
            data={'token': token},
            verify=False
        )
        
        if not verify_response.ok:
            return jsonify({
                'status': 'error',
                'message': 'API令牌验证失败'
            }), 401
            
        token_data = verify_response.json()
        license_key = token_data.get('license_key')
        
        # 检查端口限制
        server_id = get_server_id()
        verify_license_response = requests.post(
            'https://zhuanfa.demaweb3.com/admin/api/verify_license.php',
            data={
                'license_key': license_key,
                'server_id': server_id,
                'client_ip': request.remote_addr,
                'action': 'verify'
            },
            verify=False,
            timeout=10
        )
        
        if not verify_license_response.ok:
            return jsonify({
                'status': 'error',
                'message': '授权验证失败'
            }), 401
            
        license_data = verify_license_response.json()
        if not license_data.get('valid'):
            return jsonify({
                'status': 'error',
                'message': license_data.get('message', '授权码无效')
            }), 401
            
        # 检查可用端口数
        port_limit = license_data.get('port_limit', 0)
        used_ports = license_data.get('used_ports', 0)
        
        if port_limit != -1:  # 如果不是无限制
            available_ports = port_limit - used_ports
            if available_ports <= 0:
                return jsonify({
                    'status': 'error',
                    'message': f'添加失败：已达到端口数量限制（{port_limit}个）'
                }), 400
        
        # 更新数据库中的端口使用数
        update_response = requests.post(
            'https://zhuanfa.demaweb3.com/admin/api/update_ports.php',
            data={
                'license_key': license_key,
                'server_id': server_id,
                'action': 'increment',  # 增加端口使用数
                'client_ip': request.remote_addr
            },
            verify=False,
            timeout=10
        )
        
        if not update_response.ok:
            return jsonify({
                'status': 'error',
                'message': '更新端口使用数失败'
            }), 500

        # [其余代码保持不变...]
        
        # 创建转发服务
        service_name = f'port-forward-{local_port}'
        service_path = f'/etc/systemd/system/{service_name}.service'
        service_content = f"""[Unit]
Description=Port Forward {local_port} -> {target_host}:{target_port}
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/socat {protocol.upper()}-LISTEN:{local_port},fork,reuseaddr {protocol.upper()}:{target_host}:{target_port}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"""
        
        # 保存服务文件
        with open(service_path, 'w') as f:
            f.write(service_content)
            
        # 重新加载systemd配置
        os.system('systemctl daemon-reload')
        
        # 启动服务
        os.system(f'systemctl enable {service_name}')
        os.system(f'systemctl start {service_name}')
        
        # 检查服务状态
        status = subprocess.Popen(['systemctl', 'is-active', service_name], 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE)
        output, _ = status.communicate()
        service_status = output.strip().decode()
        
        if service_status != 'active':
            # 如果启动失败，清理并返回错误
            os.system(f'systemctl stop {service_name}')
            os.system(f'systemctl disable {service_name}')
            os.remove(service_path)
            os.system('systemctl daemon-reload')
            
            return jsonify({
                'status': 'error',
                'message': '服务启动失败'
            }), 500
            
        return jsonify({
            'status': 'success',
            'message': '转发创建成功'
        })
        
    except Exception as e:
        logger.error(f"API创建转发失败: {str(e)}")
        # 如果创建失败，尝试清理
        try:
            if os.path.exists(service_path):
                os.system(f'systemctl stop {service_name}')
                os.system(f'systemctl disable {service_name}')
                os.remove(service_path)
                os.system('systemctl daemon-reload')
        except:
            pass
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/v1/forwards/<int:port>', methods=['DELETE'])
@api_auth_required
def api_delete_forward(port):
    """删除端口转发API"""
    try:
        service_name = f'port-forward-{port}'
        service_path = f'/etc/systemd/system/{service_name}.service'
        
        # 检查服务是否存在
        if not os.path.exists(service_path):
            return jsonify({
                'status': 'error',
                'message': '转发不存在'
            }), 404

        # 停止并禁用服务
        os.system(f'systemctl stop {service_name}')
        os.system(f'systemctl disable {service_name}')
        
        # 删除服务文件
        os.remove(service_path)
        
        # 重新加载systemd配置
        os.system('systemctl daemon-reload')
        
        # 获取令牌信息
        token = request.headers.get('X-API-Token')
        verify_response = requests.post(
            'https://zhuanfa.demaweb3.com/admin/api/verify_token.php',
            data={'token': token},
            verify=False
        )
        
        if verify_response.ok:
            token_data = verify_response.json()
            license_key = token_data.get('license_key')
            
            # 更新数据库中的端口使用数
            server_id = get_server_id()
            update_response = requests.post(
                'https://zhuanfa.demaweb3.com/admin/api/update_ports.php',
                data={
                    'license_key': license_key,
                    'server_id': server_id,
                    'action': 'decrement',  # 减少端口使用数
                    'client_ip': request.remote_addr
                },
                verify=False,
                timeout=10
            )
            
            if not update_response.ok:
                logger.error(f"更新端口使用数失败: {update_response.text}")
        
        return jsonify({
            'status': 'success',
            'message': '转发已删除'
        })
        
    except Exception as e:
        logger.error(f"API删除转发失败: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/help')
@login_required
def help_docs():
    """帮助文档页面"""
    try:
        # 获取授权信息
        license_key = session.get('license_key')
        if not license_key:
            return redirect(url_for('bind_license'))
            
        # 直接返回 api_docs.html 模板
        return render_template('api_docs.html')
    except Exception as e:
        logger.error(f"加载帮助文档失败: {str(e)}")
        # 修改为重定向到错误页或返回友好错误提示
        return render_template('error.html', message='加载帮助文档失败，请稍后重试')

@app.route('/api/tokens')
@login_required
def get_api_tokens():
    """获取API令牌列表"""
    try:
        license_key = session.get('license_key')
        if not license_key:
            raise Exception('未找到授权码信息')
            
        response = requests.get(
            'https://zhuanfa.demaweb3.com/admin/api/get_tokens.php',
            params={'license_key': license_key},
            verify=False,
            timeout=10
        )
        
        if not response.ok:
            raise Exception('获令牌列表失败')
            
        return jsonify(response.json())
    except Exception as e:
        logger.error(f"获取API令牌列表失败: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        })

def create_forward(local_port, target_host, target_port, protocol='tcp'):
    """创建端口转发"""
    try:
        # 检查端口是否占用
        if check_port_in_use(local_port):
            raise Exception('端口已被占用')
            
        # 创建转发服务
        service_name = f'port-forward-{local_port}'
        service_path = f'/etc/systemd/system/{service_name}.service'
        service_content = f"""[Unit]
Description=Port Forward {local_port} -> {target_host}:{target_port}
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/socat {protocol.upper()}-LISTEN:{local_port},fork,reuseaddr {protocol.upper()}:{target_host}:{target_port}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"""
        
        # 保存服务文件
        with open(service_path, 'w') as f:
            f.write(service_content)
            
        # 重新加载systemd配置
        os.system('systemctl daemon-reload')
        
        # 启动服务
        os.system(f'systemctl enable {service_name}')
        os.system(f'systemctl start {service_name}')
        
        # 检查服务状态
        status = subprocess.Popen(['systemctl', 'is-active', service_name], 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE)
        output, _ = status.communicate()
        service_status = output.strip().decode()
        
        if service_status != 'active':
            raise Exception('服务启动失败')
            
        # 更新数据库中的端口使用数
        license_key = session.get('license_key')
        server_id = get_server_id()
        
        update_response = requests.post(
            'https://zhuanfa.demaweb3.com/admin/api/update_ports.php',
            data={
                'license_key': license_key,
                'server_id': server_id,
                'action': 'increment',  # 增加端口使用数
                'client_ip': request.remote_addr
            },
            verify=False,
            timeout=10
        )
        
        if not update_response.ok:
            raise Exception('更新端口使用数失败')
            
        return {
            'status': 'success',
            'message': '转发创建成功'
        }
        
    except Exception as e:
        logger.error(f"创建转发失败: {str(e)}")
        # 如果创建失败，尝试清理
        try:
            if os.path.exists(service_path):
                os.system(f'systemctl stop {service_name}')
                os.system(f'systemctl disable {service_name}')
                os.remove(service_path)
                os.system('systemctl daemon-reload')
        except:
            pass
        raise 

def init_db():
    """初始化数据库"""
    try:
        # 确保数据库目录存在
        os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
        
        # 如果数据库文件存在，先删除它
        if os.path.exists(DATABASE_PATH):
            os.remove(DATABASE_PATH)
            
        # 创建新的数据库连接
        with sqlite3.connect(DATABASE_PATH) as conn:
            cursor = conn.cursor()
            
            # 创建表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS license (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT UNIQUE NOT NULL,
                    activated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # 创建其他必要的表...
            
            conn.commit()
            
    except Exception as e:
        logging.error(f"初始化数据库失败: {str(e)}")
        raise

def get_server_real_ip():
    """获取服务器真实IP"""
    try:
        # 尝试从公网API获取
        response = requests.get('http://ipv4.icanhazip.com', timeout=5)
        if response.ok:
            return response.text.strip()
    except:
        try:
            # 备选API
            response = requests.get('https://api.ipify.org', timeout=5)
            if response.ok:
                return response.text.strip()
        except:
            pass
    
    # 如果公网API都失败了,尝试获取本地IP
    try:
        interfaces = netifaces.interfaces()
        for interface in interfaces:
            if interface != 'lo':  # 排除回环接口
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        ip = addr['addr']
                        if not ip.startswith('127.'):  # 排除本地回环地址
                            return ip
    except:
        pass
    
    return request.remote_addr  # 最后返回请求IP

# 添加主函数
if __name__ == '__main__':
    try:
        # 确保日志目录存在
        if not os.path.exists('/var/log'):
            os.makedirs('/var/log')
        
        # 使用配置的端口
        try:
            port = int(PORT)
            if port < 1 or port > 65535:
                logger.error(f"无效的端口号: {port}，使用默认端口5000")
                port = 5000
        except:
            logger.error(f"端口号转换失败，使用默认端口5000")
            port = 5000
            
        logger.info(f"启动服务，使用端口: {port}")
        app.run(host='0.0.0.0', port=port)
    except Exception as e:
        logger.error(f"服务启动失败: {str(e)}")
        raise 