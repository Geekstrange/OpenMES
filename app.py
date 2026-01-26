from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, date, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import json
import os
import base64
from werkzeug.utils import secure_filename
import subprocess
import psycopg2
import shutil
from pathlib import Path
import gzip
import zipfile
from datetime import datetime
import configparser
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
import threading
import time
from werkzeug.exceptions import (
    BadRequest, Unauthorized, Forbidden, NotFound,
    RequestTimeout, TooManyRequests, InternalServerError,
    BadGateway, ServiceUnavailable, GatewayTimeout,
    HTTPException
)
import uuid

# -------------------------- 读取配置文件 --------------------------
config = configparser.ConfigParser()
config.read('config.conf')

# 读取PostgreSQL配置
DB_USER = config.get('postgresql', 'DB_USER')
DB_PASSWORD = config.get('postgresql', 'DB_PASSWORD')
DB_HOST = config.get('postgresql', 'DB_HOST')
DB_PORT = config.get('postgresql', 'DB_PORT')
DB_NAME = config.get('postgresql', 'DB_NAME')

# 读取文件存储配置
SIGNATURE_STORAGE_PATH = config.get('storage', 'SIGNATURE_STORAGE_PATH')
BACKUP_STORAGE_PATH = config.get('storage', 'BACKUP_STORAGE_PATH')
LOG_STORAGE_PATH = config.get('storage', 'LOG_STORAGE_PATH')
ARCHIVE_STORAGE_PATH = config.get('storage', 'ARCHIVE_STORAGE_PATH', fallback='logs/archive/')

# 读取备份配置
ENABLE_AUTO_BACKUP = config.getboolean('backup', 'ENABLE_AUTO_BACKUP', fallback=False)
AUTO_BACKUP_TIME = config.get('backup', 'AUTO_BACKUP_TIME', fallback='02:00')
BACKUP_RETENTION_DAYS = config.getint('backup', 'BACKUP_RETENTION_DAYS', fallback=30)
MAX_BACKUP_FILES = config.getint('backup', 'MAX_BACKUP_FILES', fallback=50)
DEFAULT_COMPRESS = config.getboolean('backup', 'DEFAULT_COMPRESS', fallback=True)
DEFAULT_INCLUDE_TIMESTAMP = config.getboolean('backup', 'DEFAULT_INCLUDE_TIMESTAMP', fallback=True)

# 读取日志配置
LOG_RETENTION_DAYS = config.getint('logs', 'LOG_RETENTION_DAYS', fallback=7)

# 读取应用配置
SECRET_KEY = config.get('app', 'SECRET_KEY', fallback=os.urandom(24))
DEBUG = config.getboolean('app', 'DEBUG', fallback=False)
HOST = config.get('app', 'HOST', fallback='0.0.0.0')
PORT = config.getint('app', 'PORT', fallback=80)

# 创建必要的目录
required_dirs = [
    SIGNATURE_STORAGE_PATH,
    BACKUP_STORAGE_PATH,
    LOG_STORAGE_PATH,
    ARCHIVE_STORAGE_PATH
]

for dir_path in required_dirs:
    os.makedirs(dir_path, exist_ok=True)

# 初始化Flask应用
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}'

# 初始化数据库
db = SQLAlchemy(app)

# 初始化登录管理器
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = '登录以继续访问'
login_manager.login_message_category = 'warning'

# -------------------------- 辅助函数 --------------------------
def save_signature_image(base64_data, operator_id):
    """将base64签名保存为图片文件"""
    try:
        # 移除base64前缀
        if 'base64,' in base64_data:
            base64_data = base64_data.split('base64,')[1]

        # 生成唯一文件名（包含毫秒）
        import time
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')[:-3]
        filename = f"signature_{operator_id}_{timestamp}.png"
        filepath = os.path.join(SIGNATURE_STORAGE_PATH, filename)

        # 确保目录存在
        os.makedirs(SIGNATURE_STORAGE_PATH, exist_ok=True)

        # 解码并保存图片
        with open(filepath, 'wb') as f:
            f.write(base64.b64decode(base64_data))

        app.logger.info(f"签名文件保存成功: {filename}")
        return filename
    except Exception as e:
        app.logger.error(f"保存签名失败: {str(e)}")
        return None

def delete_signature_file(filename):
    """删除签名文件"""
    try:
        if filename:
            filepath = os.path.join(SIGNATURE_STORAGE_PATH, filename)
            if os.path.exists(filepath):
                os.remove(filepath)
                return True
    except Exception as e:
        app.logger.error(f"删除签名文件失败: {str(e)}")
    return False

def format_file_size(bytes_size):
    """格式化文件大小为可读的字符串"""
    if bytes_size is None:
        return "0 B"

    try:
        bytes_size = int(bytes_size)
    except (ValueError, TypeError):
        return "0 B"

    # 处理负数
    if bytes_size < 0:
        return "0 B"

    # 单位列表
    units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']

    # 计算合适的单位
    size = float(bytes_size)
    unit_index = 0
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1

    # 格式化输出
    if unit_index == 0:
        return f"{int(size)} {units[unit_index]}"
    else:
        return f"{size:.2f} {units[unit_index]}"

# -------------------------- 数据模型 --------------------------
class User(UserMixin, db.Model):
    __tablename__ = 'production_users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    # 用户级别：0-普通用户，1-子管理员，2-管理员，3-超级管理员
    user_level = db.Column(db.Integer, default=0)

    # 权限使用 JSONB 列存储，格式示例：
    # {
    #     "production_management": 31,    # 11111 (所有权限)
    #     "process_management": 7,        # 00111 (读、创建、更新)
    #     "operator_management": 15,      # 01111 (读、创建、更新、删除)
    #     "user_management": 3,          # 00011 (读、创建)
    #     "system_management": 1         # 00001 (只读)
    # }
    permissions = db.Column(db.JSON, default={})

    # 权限追踪
    granted_by = db.Column(db.Integer, db.ForeignKey('production_users.id'), nullable=True)
    create_time = db.Column(db.DateTime, default=datetime.now)
    update_time = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    # 关系
    granted_users = db.relationship('User', backref=db.backref('grantor', remote_side=[id]))

    # 常量定义
    USER_LEVELS = {
        0: 'user',
        1: 'sub_admin',
        2: 'main_admin',
        3: 'superuser'
    }

    LEVEL_NAMES_ZH = {
        0: '普通用户',
        1: '子管理员',
        2: '管理员',
        3: '超级管理员'
    }

    # 权限位定义（5位二进制）
    PERM_READ = 1      # 00001 (1)
    PERM_CREATE = 2    # 00010 (2)
    PERM_UPDATE = 4    # 00100 (4)
    PERM_DELETE = 8    # 01000 (8)
    PERM_ADVANCED = 16 # 10000 (16)

    # 所有权限（31 = 11111）
    PERM_ALL = PERM_READ | PERM_CREATE | PERM_UPDATE | PERM_DELETE | PERM_ADVANCED

    # 模块定义
    MODULES = {
        'production_management': '生产管理',
        'process_management': '工序管理',
        'operator_management': '操作员管理',
        'user_management': '用户管理',
        'system_management': '系统管理'
    }

    @property
    def is_admin(self):
        """任何类型的管理员都返回True"""
        return self.user_level >= 1

    @property
    def is_superuser(self):
        """是否为超级管理员"""
        return self.user_level == 3

    @property
    def is_main_admin(self):
        """是否为管理员"""
        return self.user_level == 2

    @property
    def is_sub_admin(self):
        """是否为子管理员"""
        return self.user_level == 1

    @property
    def admin_level_display(self):
        """获取显示用的管理员级别"""
        return self.LEVEL_NAMES_ZH.get(self.user_level, '普通用户')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def has_permission(self, module, perm_bit='read'):
        """
        检查用户是否有特定权限

        Args:
            module: 模块名称
            perm_bit: 权限位 ('read', 'create', 'update', 'delete', 'advanced')

        Returns:
            bool: 是否有权限
        """
        # 超级管理员拥有所有权限
        if self.user_level == 3:
            return True

        # 获取模块权限值
        module_perms = self.permissions.get(module, 0)

        # 如果未指定具体权限位，检查是否有任何权限
        if perm_bit is None:
            return module_perms > 0

        # 检查具体权限位
        if perm_bit == 'read':
            return bool(module_perms & self.PERM_READ)
        elif perm_bit == 'create':
            return bool(module_perms & self.PERM_CREATE)
        elif perm_bit == 'update':
            return bool(module_perms & self.PERM_UPDATE)
        elif perm_bit == 'delete':
            return bool(module_perms & self.PERM_DELETE)
        elif perm_bit == 'advanced':
            return bool(module_perms & self.PERM_ADVANCED)

        return False

    def set_module_permission(self, module, **kwargs):
        """
        设置模块的权限

        Args:
            module: 模块名称
            **kwargs: read, create, update, delete, advanced 布尔值

        Returns:
            int: 权限值
        """
        perms = 0
        if kwargs.get('read', False):
            perms |= self.PERM_READ
        if kwargs.get('create', False):
            perms |= self.PERM_CREATE
        if kwargs.get('update', False):
            perms |= self.PERM_UPDATE
        if kwargs.get('delete', False):
            perms |= self.PERM_DELETE
        if kwargs.get('advanced', False):
            perms |= self.PERM_ADVANCED

        # 初始化权限字典
        if not self.permissions:
            self.permissions = {}

        self.permissions[module] = perms
        return perms

    def get_module_permissions(self, module):
        """
        获取模块的详细权限

        Args:
            module: 模块名称

        Returns:
            dict: 包含各个权限位的布尔值和权限值
        """
        perms = self.permissions.get(module, 0)
        return {
            'read': bool(perms & self.PERM_READ),
            'create': bool(perms & self.PERM_CREATE),
            'update': bool(perms & self.PERM_UPDATE),
            'delete': bool(perms & self.PERM_DELETE),
            'advanced': bool(perms & self.PERM_ADVANCED),
            'value': perms,
            'octal': oct(perms).replace('0o', '')
        }

    def get_all_permissions(self):
        """获取所有模块的权限"""
        result = {}
        for module in self.MODULES.keys():
            result[module] = self.get_module_permissions(module)
        return result

    def get_permissions_value(self):
        """获取所有权限的JSON值"""
        if not self.permissions:
            return {}
        return self.permissions

    def can_edit_user(self, target_user):
        """检查当前用户是否可以编辑目标用户"""
        # 自己可以编辑自己
        if self.id == target_user.id:
            return True

        # 不能编辑超级管理员（除非自己也是超级管理员）
        if target_user.user_level == 3 and self.user_level != 3:
            return False

        # 高权限可以编辑低权限
        if self.user_level > target_user.user_level:
            return True

        # 同级不能相互编辑
        return False

    def can_grant_level(self, target_level):
        """检查当前用户是否可以授予目标用户级别"""
        # 不能授予比自己高的级别或相同级别
        if target_level >= self.user_level:
            return False

        # 特定限制：
        if self.user_level == 2:  # 管理员
            # 管理员不能授予管理员级别(2)或超级管理员级别(3)
            return target_level <= 1
        elif self.user_level == 1:  # 子管理员
            # 子管理员只能授予普通用户级别(0)
            return target_level == 0
        elif self.user_level == 3:  # 超级管理员
            # 超级管理员可以授予任何低于自己的级别
            return target_level <= 2
        else:
            return False

    def get_grantable_levels(self):
        """获取当前用户可以授予的用户级别"""
        grantable = []
        for level, name in self.LEVEL_NAMES_ZH.items():
            if self.can_grant_level(level):
                grantable.append({'level': level, 'name': name})
        return grantable

class ProductionRecord(db.Model):
    __tablename__ = 'production_records'
    id = db.Column(db.Integer, primary_key=True)
    product_code = db.Column(db.String(50), nullable=False)
    process = db.Column(db.String(100), nullable=False)
    next_process = db.Column(db.String(100), nullable=True)
    number = db.Column(db.Integer, nullable=False)
    operators = db.Column(db.String(200), nullable=False)
    note = db.Column(db.Text, nullable=True)
    creator = db.Column(db.String(50), nullable=False)
    create_time = db.Column(db.DateTime, default=datetime.now)
    update_time = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    # 新增：冻结状态（当组管理员签字确认后冻结）
    is_freeze = db.Column(db.Boolean, default=False, nullable=False)

class ProcessOption(db.Model):
    __tablename__ = 'process_options'
    id = db.Column(db.Integer, primary_key=True)
    process_name = db.Column(db.String(100), unique=True, nullable=False)
    # 关联的操作员组（JSON格式存储）
    linked_groups = db.Column(db.Text, default='[]')  # 存储JSON数组，如["组1", "组2"]
    # 新增：关联的下工序列表（JSON格式存储）
    linked_next_processes = db.Column(db.Text, default='[]')  # 存储JSON数组，如["下工序1", "下工序2"]
    create_time = db.Column(db.DateTime, default=datetime.now)
    update_time = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

class OperatorGroup(db.Model):
    __tablename__ = 'operator_groups'
    id = db.Column(db.Integer, primary_key=True)
    group_name = db.Column(db.String(100), nullable=False)
    operator_name = db.Column(db.String(100), nullable=False)

    # 密码字段
    password_hash = db.Column(db.String(256), nullable=True)

    # 上次登录时间
    last_login = db.Column(db.DateTime, nullable=True)

    # 新增字段
    group_owner = db.Column(db.Boolean, default=False)  # 是否为组管理员

    # 修改：改为存储文件名而不是base64
    signature_file = db.Column(db.String(200), nullable=True)  # 签名文件名

    # 新增：签名时间（用于追踪签字时间）
    signature_time = db.Column(db.DateTime, nullable=True)

    create_time = db.Column(db.DateTime, default=datetime.now)
    update_time = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    __table_args__ = (db.UniqueConstraint('group_name', 'operator_name', name='unique_group_operator'),)

    @property
    def display_role(self):
        """获取显示角色"""
        if self.group_owner:
            return "组管理员"
        return "操作员"

    @property
    def display_signature_status(self):
        """获取显示用的签字状态（仅组管理员显示）"""
        if not self.group_owner:
            return None  # 普通操作员不显示签字状态

        if self.signature_file:
            if self.signature_time:
                return f"已签字 ({self.signature_time.strftime('%H:%M')})"
            return "已签字"
        return "未签字"

    @property
    def signature_url(self):
        """获取签名的URL"""
        if self.signature_file:
            return url_for('serve_signature_file', filename=self.signature_file)
        return None

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        if not self.password_hash:
            # 如果没有设置密码，使用默认密码
            return password == '000000'
        return check_password_hash(self.password_hash, password)

# -------------------------- 数据模型（续） --------------------------
class ProductionLog(db.Model):
    """系统日志模型"""
    __tablename__ = 'production_logs'

    id = db.Column(db.Integer, primary_key=True)
    log_type = db.Column(db.String(50), nullable=False)  # 日志类型
    action = db.Column(db.String(100), nullable=False)   # 具体操作
    user_type = db.Column(db.String(20), nullable=False) # 用户类型
    user_id = db.Column(db.Integer, nullable=True)       # 用户ID
    username = db.Column(db.String(100), nullable=False) # 用户名
    target_id = db.Column(db.Integer, nullable=True)     # 目标ID
    target_info = db.Column(db.Text, nullable=True)      # 目标信息（JSON）
    ip_address = db.Column(db.String(45), nullable=True) # IP地址
    user_agent = db.Column(db.Text, nullable=True)       # 浏览器信息
    created_at = db.Column(db.DateTime, default=datetime.now)

    # 日志类型常量
    LOG_TYPES = {
        'login_logout': '登录登出',
        'record': '生产记录',
        'process': '工序管理',
        # 'operator': '操作员管理',
        'operator': '成员管理',
        'user': '用户管理',
        'backup': '备份管理',
        'system': '系统操作'
    }

    # 操作类型常量
    ACTIONS = {
        'login': '登录',
        'logout': '登出',
        'add': '添加',
        'edit': '编辑',
        'delete': '删除',
        'backup': '备份',
        'restore': '恢复',
        'reset_password': '重置密码',
        'grant_owner': '授权组管理员',
        'revoke_owner': '移除组管理员',
        'link_groups': '关联组',
        'link_next_processes': '关联下工序',
        'sign': '签字确认'
    }

    @classmethod
    def get_action_display(cls, action):
        """获取操作的中文显示"""
        return cls.ACTIONS.get(action, action)

    @classmethod
    def get_log_type_display(cls, log_type):
        """获取日志类型的中文显示"""
        return cls.LOG_TYPES.get(log_type, log_type)

    def get_target_info_dict(self):
        """获取目标信息的字典格式"""
        if self.target_info:
            try:
                return json.loads(self.target_info)
            except:
                return {}
        return {}

# -------------------------- 日志相关辅助函数 --------------------------
def log_activity(log_type, action, user_type, user_id, username,
                 target_id=None, target_info=None, request=None):
    """
    记录系统日志

    Args:
        log_type: 日志类型
        action: 操作类型
        user_type: 用户类型 (admin/operator)
        user_id: 用户ID
        username: 用户名
        target_id: 操作目标ID
        target_info: 操作目标信息（字典）
        request: Flask请求对象
    """
    try:
        ip_address = None
        user_agent = None

        if request:
            ip_address = request.remote_addr
            user_agent = request.user_agent.string

        # 将目标信息转为JSON字符串
        target_info_str = None
        if target_info:
            target_info_str = json.dumps(target_info, ensure_ascii=False)

        # 创建日志记录
        log = ProductionLog(
            log_type=log_type,
            action=action,
            user_type=user_type,
            user_id=user_id,
            username=username,
            target_id=target_id,
            target_info=target_info_str,
            ip_address=ip_address,
            user_agent=user_agent
        )

        db.session.add(log)
        db.session.commit()

        # 同时写入文件日志
        write_file_log(log)

        # 检查并归档旧日志
        archive_old_logs()

    except Exception as e:
        app.logger.error(f"记录日志失败: {str(e)}")
        db.session.rollback()

def write_file_log(log):
    """写入文件日志"""
    try:
        log_dir = LOG_STORAGE_PATH
        if not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

        # 按日期创建日志文件
        log_date = log.created_at.strftime('%Y-%m-%d')
        log_file = os.path.join(log_dir, f'system_{log_date}.log')

        # 格式化日志内容
        log_entry = f"{log.created_at.strftime('%Y-%m-%d %H:%M:%S')} | " \
                   f"{ProductionLog.get_log_type_display(log.log_type)} | " \
                   f"{ProductionLog.get_action_display(log.action)} | " \
                   f"用户: {log.username} ({log.user_type}) | " \
                   f"IP: {log.ip_address or 'N/A'}\n"

        # 写入文件
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(log_entry)

    except Exception as e:
        app.logger.error(f"写入文件日志失败: {str(e)}")

def archive_old_logs():
    """归档一周前的日志"""
    try:
        # 计算一周前的日期
        one_week_ago = datetime.now() - timedelta(days=7)

        # 查询一周前的日志
        old_logs = ProductionLog.query.filter(
            ProductionLog.created_at < one_week_ago
        ).all()

        if old_logs:
            # 按日期分组
            logs_by_date = {}
            for log in old_logs:
                date_str = log.created_at.strftime('%Y-%m-%d')
                if date_str not in logs_by_date:
                    logs_by_date[date_str] = []
                logs_by_date[date_str].append(log)

            # 归档目录
            archive_dir = 'logs/archive/'
            if not os.path.exists(archive_dir):
                os.makedirs(archive_dir, exist_ok=True)

            # 归档每个日期的日志
            for date_str, logs in logs_by_date.items():
                archive_file = os.path.join(archive_dir, f'logs_{date_str}.json')

                # 准备归档数据
                archive_data = []
                for log in logs:
                    archive_data.append({
                        'id': log.id,
                        'log_type': log.log_type,
                        'action': log.action,
                        'user_type': log.user_type,
                        'user_id': log.user_id,
                        'username': log.username,
                        'target_id': log.target_id,
                        'target_info': log.target_info,
                        'ip_address': log.ip_address,
                        'user_agent': log.user_agent,
                        'created_at': log.created_at.strftime('%Y-%m-%d %H:%M:%S')
                    })

                # 写入归档文件
                with open(archive_file, 'w', encoding='utf-8') as f:
                    json.dump(archive_data, f, ensure_ascii=False, indent=2)

                # 删除数据库中的日志记录
                for log in logs:
                    db.session.delete(log)

                app.logger.info(f"已归档 {len(logs)} 条日志到 {archive_file}")

            db.session.commit()

    except Exception as e:
        app.logger.error(f"归档日志失败: {str(e)}")
        db.session.rollback()

# -------------------------- 辅助函数 --------------------------
@app.context_processor
def inject_permissions():
    """向所有模板注入权限检查函数"""
    def has_perm(permission):
        if not current_user.is_authenticated:
            return False

        # 将旧权限名称映射到新模块
        mapping = {
            'add_record': ('production_management', 'create'),
            'manage_process': ('process_management', 'read'),
            'manage_operator': ('operator_management', 'read'),
            'manage_users': ('user_management', 'read'),
            'manage_system': ('system_management', 'read')
        }

        if permission in mapping:
            module, perm_bit = mapping[permission]
            return current_user.has_permission(module, perm_bit)

        # 如果是模块名称，检查是否有该模块的读权限
        if permission in User.MODULES:
            return current_user.has_permission(permission, 'read')

        return False

    # 待前端模板迁移完毕全面转向新版权限管理
    # def has_perm(permission):
    #     if not current_user.is_authenticated:
    #         return False

    #     # 将旧权限名称映射到新模块（删除这段）
    #     # mapping = {
    #     #     'add_record': ('production_management', 'create'),
    #     #     'manage_process': ('process_management', 'read'),
    #     #     'manage_operator': ('operator_management', 'read'),
    #     #     'manage_users': ('user_management', 'read'),
    #     #     'manage_system': ('system_management', 'read')
    #     # }

    #     # 直接使用新权限系统检查
    #     if '.' in permission:
    #         # 格式: "module.perm_bit"
    #         parts = permission.split('.')
    #         if len(parts) == 2:
    #             module, perm_bit = parts
    #             return current_user.has_permission(module, perm_bit)
    #     else:
    #         # 如果是模块名称，检查是否有该模块的读权限
    #         return current_user.has_permission(permission, 'read')

    #     return False

    def is_admin():
        if not current_user.is_authenticated:
            return False
        return current_user.is_admin

    def is_operator():
        return session.get('operator_logged_in', False)

    def get_current_operator():
        if session.get('operator_logged_in'):
            operator_id = session.get('operator_id')
            if operator_id:
                operator = db.session.get(OperatorGroup, int(operator_id))
                if operator:
                    return {
                        'name': operator.operator_name,
                        'group': operator.group_name,
                        'id': operator.id,
                        'is_group_owner': operator.group_owner if operator else False
                    }
            return {
                'name': session.get('operator_name'),
                'group': session.get('operator_group'),
                'id': session.get('operator_id'),
                'is_group_owner': False
            }
        return None

    # 为操作员提供导航
    def get_operator_nav():
        if session.get('operator_logged_in'):
            operator_id = session.get('operator_id')
            if operator_id:
                operator = db.session.get(OperatorGroup, int(operator_id))
                nav = [
                    {'name': '今日生产', 'url': url_for('operator_dashboard'), 'icon': '📊'},
                    {'name': '修改密码', 'url': '#', 'icon': '🔒', 'onclick': 'showChangePasswordModal()'}
                ]
                if operator and operator.group_owner:
                    nav.extend([
                        {'name': '组内记录', 'url': '#', 'icon': '👥', 'onclick': 'showGroupRecordsModal()'},
                        {'name': '确认签字', 'url': '#', 'icon': '✒️', 'onclick': 'showSignatureModal()'}
                    ])
                return nav
        return []

    return {
        'has_perm': has_perm,
        'is_admin': is_admin,
        'is_operator': is_operator,
        'current_operator': get_current_operator,
        'operator_nav': get_operator_nav,
        'current_user': current_user,
        'User': User  # 将User类传递给模板，以便访问模块常量
    }

def get_process_options():
    """从数据库获取生产工序列表"""
    processes = ProcessOption.query.order_by(ProcessOption.process_name).all()
    return [p.process_name for p in processes]

def get_operator_groups():
    """从数据库获取操作员组字典"""
    groups = OperatorGroup.query.order_by(OperatorGroup.group_name, OperatorGroup.operator_name).all()
    result = {}
    for item in groups:
        if item.group_name not in result:
            result[item.group_name] = []
        result[item.group_name].append(item.operator_name)
    return result

def get_process_groups(process_name):
    """获取工序关联的操作员组"""
    process = ProcessOption.query.filter_by(process_name=process_name).first()
    if process and process.linked_groups:
        try:
            return json.loads(process.linked_groups)
        except:
            return []
    return []

def get_process_links():
    """获取所有工序的关联组（用于表单）"""
    all_processes = ProcessOption.query.all()
    result = {}
    for process in all_processes:
        if process.linked_groups:
            try:
                result[process.process_name] = json.loads(process.linked_groups)
            except:
                result[process.process_name] = []
        else:
            result[process.process_name] = []
    return result

def get_process_next_links():
    """获取所有工序的关联下工序（用于表单）"""
    all_processes = ProcessOption.query.all()
    result = {}
    for process in all_processes:
        if process.linked_next_processes:
            try:
                result[process.process_name] = json.loads(process.linked_next_processes)
            except:
                result[process.process_name] = []
        else:
            result[process.process_name] = []
    return result

def get_date_range(period):
    """根据时间段获取日期范围"""
    today = date.today()

    if period == 'today':
        return today, today
    elif period == 'week':
        start_date = today - timedelta(days=today.weekday())
        return start_date, today
    elif period == 'month':
        start_date = today.replace(day=1)
        return start_date, today
    else:
        return today, today

# -------------------------- 权限装饰器 --------------------------
def permission_required(module, perm_bit='read'):
    """
    权限检查装饰器

    Args:
        module: 模块名称
        perm_bit: 权限位 ('read', 'create', 'update', 'delete', 'advanced')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))

            if not current_user.has_permission(module, perm_bit):
                module_names = User.MODULES
                perm_names = {
                    'read': '查看',
                    'create': '新建',
                    'update': '编辑',
                    'delete': '删除',
                    'advanced': '高级操作'
                }
                flash(f'无权限{perm_names.get(perm_bit, "")}{module_names.get(module, module)}！', 'danger')
                return redirect(url_for('index'))

            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required(min_level=1):
    """管理员权限检查装饰器"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))

            if current_user.user_level < min_level:
                level_names = {
                    1: '子管理员',
                    2: '管理员',
                    3: '超级管理员'
                }
                flash(f'需要{level_names.get(min_level, "管理员")}权限！', 'danger')
                return redirect(url_for('index'))

            return f(*args, **kwargs)
        return decorated_function
    return decorator

def operator_login_required(f):
    """操作员登录装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('operator_logged_in'):
            flash('请先登录！', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def group_owner_required(f):
    """组管理员权限装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('operator_logged_in'):
            flash('请先登录！', 'danger')
            return redirect(url_for('login'))

        operator_id = session.get('operator_id')
        if operator_id:
            operator = db.session.get(OperatorGroup, int(operator_id))
            if not operator or not operator.group_owner:
                flash('需要组管理员权限才能访问！', 'danger')
                return redirect(url_for('operator_dashboard'))

            return f(*args, **kwargs)
        else:
            flash('请先登录！', 'danger')
            return redirect(url_for('login'))
    return decorated_function

# -------------------------- 错误处理配置 --------------------------
ERROR_CONFIGS = {
    400: {
        'title': '无效的请求',
        'description': '服务器无法理解此请求，可能是参数格式不正确或缺少必要参数。'
    },
    401: {
        'title': '需要身份验证',
        'description': '您需要登录才能访问此资源。'
    },
    403: {
        'title': '权限不足',
        'description': '您没有权限访问此资源。'
    },
    404: {
        'title': '资源不存在',
        'description': '您要访问的页面不存在或已被移动。'
    },
    408: {
        'title': '操作超时',
        'description': '服务器等待请求时超时。'
    },
    429: {
        'title': '操作过于频繁',
        'description': '您的请求过于频繁，请稍后再试。'
    },
    500: {
        'title': '服务器遇到错误',
        'description': '服务器在处理请求时发生了内部错误。'
    },
    502: {
        'title': '上游服务错误',
        'description': '服务器作为网关或代理时，从上游服务器收到无效响应。'
    },
    503: {
        'title': '系统维护中',
        'description': '服务器暂时无法处理请求，通常是由于维护或过载。'
    },
    504: {
        'title': '响应超时',
        'description': '服务器作为网关或代理时，未能及时从上游服务器收到响应。'
    }
}

def render_error_page(error_code, error_details=None, request_path=None,
                     request_method=None, user_agent=None, debug_mode=False,
                     is_admin=False):
    """渲染错误页面"""

    # 获取错误配置
    config = ERROR_CONFIGS.get(error_code, {
        'title': f'HTTP {error_code} 错误',
        'description': '发生了未知错误。',
        'explanation': f'HTTP {error_code} - 未定义的错误状态码。'
    })

    # 生成请求ID
    request_id = str(uuid.uuid4())[:8]

    return render_template('error.html',
        error_code=error_code,
        error_title=config['title'],
        error_description=config['description'],
        error_icon='',  # 由前端JavaScript动态设置
        solutions='',   # 由前端JavaScript动态设置
    )

# -------------------------- 全局错误处理器 --------------------------
@app.errorhandler(Exception)
def handle_all_errors(e):
    """处理所有异常"""

    # 获取HTTP状态码
    if isinstance(e, HTTPException):
        error_code = e.code
        error_details = str(e)
    else:
        error_code = 500
        error_details = str(e) if app.debug else None

    # 获取请求信息
    request_path = request.path
    request_method = request.method
    user_agent = request.user_agent.string if request.user_agent else None

    # 检查当前用户是否为管理员
    is_admin = False
    if current_user and hasattr(current_user, 'is_authenticated') and current_user.is_authenticated:
        is_admin = getattr(current_user, 'is_admin', False)

    # 渲染错误页面
    return render_error_page(
        error_code=error_code,
        error_details=error_details,
        request_path=request_path,
        request_method=request_method,
        user_agent=user_agent,
        debug_mode=app.debug,
        is_admin=is_admin
    ), error_code

# 处理404错误的特殊路由（因为404可能发生在路由匹配之前）
@app.route('/<path:invalid_path>')
def handle_404(invalid_path):
    """处理所有未匹配的路由，返回404页面"""
    return render_error_page(404), 404

# -------------------------- 登录/登出 --------------------------
@login_manager.user_loader
def load_user(user_id):
    user = db.session.get(User, int(user_id))
    if user:
        # 如果是系统用户登录，清空可能的操作员session
        if session.get('operator_logged_in'):
            session.clear()
    return user

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if session.get('operator_logged_in'):
        return redirect(url_for('operator_dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        # 首先尝试系统用户登录
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash(f'欢迎 {username} 登录！', 'success')

            # 记录登录日志
            log_activity(
                log_type='login_logout',
                action='login',
                user_type='admin',
                user_id=user.id,
                username=username,
                request=request
            )

            return redirect(url_for('index'))

        # 尝试操作员登录
        operator = OperatorGroup.query.filter_by(operator_name=username).first()
        if operator:
            # 验证密码
            if operator.check_password(password):
                # 操作员登录成功
                session['operator_logged_in'] = True
                session['operator_name'] = operator.operator_name
                session['operator_group'] = operator.group_name
                session['operator_id'] = operator.id

                # 更新最后登录时间
                operator.last_login = datetime.now()
                db.session.commit()

                # 记录操作员登录日志
                log_activity(
                    log_type='login_logout',
                    action='login',
                    user_type='operator',
                    user_id=operator.id,
                    username=operator.operator_name,
                    request=request
                )

                # 检查是否是默认密码，提示修改
                if not operator.password_hash or password == '000000':
                    flash(f'操作员 {operator.operator_name} 登录成功！请尽快修改默认密码。', 'warning')
                else:
                    flash(f'操作员 {operator.operator_name} 登录成功！', 'success')

                return redirect(url_for('operator_dashboard'))
            else:
                flash('密码错误！', 'danger')
        else:
            flash('用户名或密码错误！', 'danger')

        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    """统一登出函数，处理用户和操作员登出"""
    username = None
    user_type = None
    user_id = None

    if current_user.is_authenticated:
        username = current_user.username
        user_type = 'admin'
        user_id = current_user.id
        logout_user()
        flash('已安全退出登录', 'success')
    elif session.get('operator_logged_in'):
        username = session.get('operator_name')
        user_type = 'operator'
        user_id = session.get('operator_id')
        session.clear()
        flash('操作员已退出登录', 'success')

    # 记录登出日志
    if username:
        log_activity(
            log_type='login_logout',
            action='logout',
            user_type=user_type,
            user_id=user_id,
            username=username,
            request=request
        )

    return redirect(url_for('login'))

# -------------------------- 首页路由 --------------------------
@app.route('/')
@login_required
def index():
    # 检查是否有生产管理读取权限
    if not current_user.has_permission('production_management', 'read'):
        flash('您没有访问生产记录的权限！', 'danger')

        # 获取今天日期
        today = date.today()

        # 检查用户是否有任何其他权限
        has_any_other_perm = any(
            current_user.has_permission(m, 'read')
            for m in User.MODULES.keys()
            if m != 'production_management'
        )

        return render_template('index.html',
                             today=today,
                             has_any_other_perm=has_any_other_perm,
                             # 传递空数据，确保模板不报错
                             records=[],
                             total_today=0,
                             process_count=0,
                             operator_count=0,
                             process_stats=[],
                             process_list=[],
                             process_labels=[],
                             process_values=[],
                             operator_labels=[],
                             operator_values=[],
                             frozen_count=0,
                             search_code='',
                             search_process='',
                             search_operator='',
                             search_creator='',
                             search_next_process='',
                             min_number='',
                             max_number='',
                             start_date='',
                             end_date='')

    # 处理搜索条件
    search_code = request.args.get('search_code', '').strip()
    search_process = request.args.get('search_process', '').strip()
    search_operator = request.args.get('search_operator', '').strip()
    search_creator = request.args.get('search_creator', '').strip()
    search_next_process = request.args.get('search_next_process', '').strip()
    min_number = request.args.get('min_number', '').strip()
    max_number = request.args.get('max_number', '').strip()
    start_date = request.args.get('start_date', '').strip()
    end_date = request.args.get('end_date', '').strip()

    # 构建查询
    query = ProductionRecord.query.order_by(ProductionRecord.create_time.desc())
    if search_code:
        query = query.filter(ProductionRecord.product_code.contains(search_code))
    if search_process:
        query = query.filter(ProductionRecord.process.contains(search_process))
    if search_operator:
        query = query.filter(ProductionRecord.operators.contains(search_operator))
    if search_creator:
        query = query.filter(ProductionRecord.creator.contains(search_creator))
    if search_next_process:
        query = query.filter(ProductionRecord.next_process.contains(search_next_process))
    if min_number and min_number.isdigit():
        query = query.filter(ProductionRecord.number >= int(min_number))
    if max_number and max_number.isdigit():
        query = query.filter(ProductionRecord.number <= int(max_number))
    if start_date:
        query = query.filter(ProductionRecord.create_time >= datetime.strptime(start_date, '%Y-%m-%d'))
    if end_date:
        end_dt = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
        query = query.filter(ProductionRecord.create_time < end_dt)

    records = query.all()

    # 获取所有工序列表
    all_processes = db.session.query(ProductionRecord.process.distinct()).order_by(ProductionRecord.process).all()
    process_list = [p[0] for p in all_processes]

    # 获取今日数据
    today = date.today()

    # 1. 今日总产量
    total_today = db.session.query(db.func.sum(ProductionRecord.number)).filter(
        db.cast(ProductionRecord.create_time, db.Date) == today
    ).scalar() or 0

    # 2. 今日活跃工序数
    process_count = db.session.query(ProductionRecord.process.distinct()).filter(
        db.cast(ProductionRecord.create_time, db.Date) == today
    ).count()

    # 3. 今日参与操作员数
    today_operators = set()
    today_records = ProductionRecord.query.filter(
        db.cast(ProductionRecord.create_time, db.Date) == today
    ).all()
    for record in today_records:
        ops = [op.strip() for op in record.operators.split(',') if op.strip()]
        today_operators.update(ops)
    operator_count = len(today_operators)

    # 4. 工序产量统计（今日）
    process_stats = []
    for process in process_list:
        # 获取该工序今日数据
        process_today_data = ProductionRecord.query.filter(
            ProductionRecord.process == process,
            db.cast(ProductionRecord.create_time, db.Date) == today
        ).all()

        if process_today_data:
            total_quantity = sum(record.number for record in process_today_data)

            # 产品种类数
            product_set = set(record.product_code for record in process_today_data)

            # 操作员统计
            operator_set = set()
            for record in process_today_data:
                ops = [op.strip() for op in record.operators.split(',') if op.strip()]
                operator_set.update(ops)

            # 最高产量产品
            product_qty = {}
            for record in process_today_data:
                product_qty[record.product_code] = product_qty.get(record.product_code, 0) + record.number

            top_product = max(product_qty.items(), key=lambda x: x[1]) if product_qty else ('无', 0)

            process_stats.append({
                'process_name': process,
                'product_count': len(product_set),
                'total_quantity': total_quantity,
                'operator_count': len(operator_set),
                'avg_per_operator': total_quantity / len(operator_set) if operator_set else 0,
                'top_product': top_product[0],
                'top_product_qty': top_product[1]
            })

    # 按总产量排序
    process_stats.sort(key=lambda x: x['total_quantity'], reverse=True)

    # 5. 工序图表数据（今日）
    process_chart_data = {}
    for record in today_records:
        process_chart_data[record.process] = process_chart_data.get(record.process, 0) + record.number

    # 6. 操作员图表数据（按工序筛选）
    operator_chart_data = {}
    for record in today_records:
        ops = [op.strip() for op in record.operators.split(',') if op.strip()]
        for op in ops:
            key = f"{op} ({record.process})"
            operator_chart_data[key] = operator_chart_data.get(key, 0) + record.number

    # 计算冻结记录数量
    frozen_count = db.session.query(ProductionRecord).filter(
        ProductionRecord.is_freeze == True
    ).count()

    return render_template('index.html',
                           records=records,
                           search_code=search_code,
                           search_process=search_process,
                           search_operator=search_operator,
                           search_creator=search_creator,
                           search_next_process=search_next_process,
                           min_number=min_number,
                           max_number=max_number,
                           start_date=start_date,
                           end_date=end_date,
                           total_today=total_today,
                           process_count=process_count,
                           operator_count=operator_count,
                           process_stats=process_stats,
                           process_list=process_list,
                           process_labels=list(process_chart_data.keys()),
                           process_values=list(process_chart_data.values()),
                           operator_labels=list(operator_chart_data.keys()),
                           operator_values=list(operator_chart_data.values()),
                           today=today,
                           frozen_count=frozen_count)

# -------------------------- 添加记录 --------------------------
@app.route('/add', methods=['GET', 'POST'])
@login_required
@permission_required('production_management', 'create')
def add_record():
    # 从数据库获取数据
    process_options = get_process_options()
    operator_groups = get_operator_groups()
    process_links = get_process_links()
    process_next_links = get_process_next_links()

    if request.method == 'POST':
        product_code = request.form.get('product_code', '').strip()
        process = request.form.get('process', '').strip()
        next_process = request.form.get('next_process', '').strip()
        number = request.form.get('number', '').strip()
        operators = request.form.getlist('operator')
        note = request.form.get('note', '').strip()
        operator_str = ','.join([op.strip() for op in operators if op.strip()])

        # 数据验证
        errors = []
        if not product_code:
            errors.append('产品代码不能为空！')
        if not process:
            errors.append('生产工序不能为空！')
        if not number or not number.isdigit() or int(number) <= 0:
            errors.append('生产数量必须是正整数！')
        if not operator_str:
            errors.append('请至少选择一个操作员！')

        if errors:
            for err in errors:
                flash(err, 'danger')
            return render_template('add.html',
                                 process_options=process_options,
                                 operator_groups=operator_groups,
                                 process_links=process_links,
                                 process_next_links=process_next_links)

        new_record = ProductionRecord(
            product_code=product_code,
            process=process,
            next_process=next_process if next_process else None,
            number=int(number),
            operators=operator_str,
            note=note if note else None,
            creator=current_user.username,
            is_freeze=False
        )
        db.session.add(new_record)
        try:
            db.session.commit()

            # 记录添加日志
            log_activity(
                log_type='record',
                action='add',
                user_type='admin',
                user_id=current_user.id,
                username=current_user.username,
                target_id=new_record.id,
                target_info={
                    'product_code': product_code,
                    'process': process,
                    'number': int(number),
                    'operators': operator_str,
                    'creator': current_user.username
                },
                request=request
            )

            flash(f'生产记录 [{product_code}] 添加成功！', 'success')

            # 保持表单清空状态
            product_code = ''
            process = ''
            next_process = ''
            number = ''
            operator_str = ''
            note = ''

            # 重新获取数据并渲染当前页面
            process_options = get_process_options()
            operator_groups = get_operator_groups()
            process_links = get_process_links()
            process_next_links = get_process_next_links()

            return render_template('add.html',
                                 process_options=process_options,
                                 operator_groups=operator_groups,
                                 process_links=process_links,
                                 process_next_links=process_next_links)

        except Exception as e:
            db.session.rollback()
            flash(f'保存失败：{str(e)}', 'danger')
            return render_template('add.html',
                                 process_options=process_options,
                                 operator_groups=operator_groups,
                                 process_links=process_links,
                                 process_next_links=process_next_links)

    return render_template('add.html',
                         process_options=process_options,
                         operator_groups=operator_groups,
                         process_links=process_links,
                         process_next_links=process_next_links)

# -------------------------- 编辑记录 --------------------------
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_record(id):
    record = db.session.get(ProductionRecord, int(id))

    # 首先检查记录是否存在
    if not record:
        flash('记录不存在！', 'danger')
        return redirect(url_for('index'))

    # 检查记录是否已冻结且用户权限不足
    if record.is_freeze and not current_user.has_permission('production_management', 'advanced'):
        flash('该记录已被确认，您无权限编辑！', 'danger')
        return redirect(url_for('index'))

    # 检查编辑权限
    if not current_user.has_permission('production_management', 'update'):
        flash('无权限编辑生产记录！', 'danger')
        return redirect(url_for('index'))

    # 从数据库获取数据
    process_options = get_process_options()
    operator_groups = get_operator_groups()
    process_links = get_process_links()
    process_next_links = get_process_next_links()

    selected_operators = [op.strip() for op in record.operators.split(',') if op.strip()]

    if request.method == 'POST':
        product_code = request.form.get('product_code', '').strip()
        process = request.form.get('process', '').strip()
        next_process = request.form.get('next_process', '').strip()
        number = request.form.get('number', '').strip()
        operators = request.form.getlist('operator')
        note = request.form.get('note', '').strip()
        operator_str = ','.join([op.strip() for op in operators if op.strip()])

        errors = []
        if not product_code:
            errors.append('产品代码不能为空！')
        if not process:
            errors.append('生产工序不能为空！')
        if not number or not number.isdigit() or int(number) <= 0:
            errors.append('生产数量必须是正整数！')
        if not operator_str:
            errors.append('请至少选择一个操作员！')

        if errors:
            for err in errors:
                flash(err, 'danger')
            return render_template('edit.html',
                                 record=record,
                                 process_options=process_options,
                                 operator_groups=operator_groups,
                                 process_links=process_links,
                                 process_next_links=process_next_links,
                                 selected_operators=selected_operators)

        # 保存旧数据用于日志
        old_data = {
            'product_code': record.product_code,
            'process': record.process,
            'next_process': record.next_process,
            'number': record.number,
            'operators': record.operators,
            'note': record.note
        }

        record.product_code = product_code
        record.process = process
        record.next_process = next_process if next_process else None
        record.number = int(number)
        record.operators = operator_str
        record.note = note if note else None
        record.update_time = datetime.now()

        try:
            db.session.commit()

            # 记录编辑日志
            log_activity(
                log_type='record',
                action='edit',
                user_type='admin',
                user_id=current_user.id,
                username=current_user.username,
                target_id=record.id,
                target_info={
                    'old_data': old_data,
                    'new_data': {
                        'product_code': product_code,
                        'process': process,
                        'next_process': next_process,
                        'number': int(number),
                        'operators': operator_str,
                        'note': note
                    }
                },
                request=request
            )

            flash('生产记录更新成功！', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f'更新失败：{str(e)}', 'danger')
            return render_template('edit.html',
                                 record=record,
                                 process_options=process_options,
                                 operator_groups=operator_groups,
                                 process_links=process_links,
                                 process_next_links=process_next_links,
                                 selected_operators=selected_operators)

    return render_template('edit.html',
                         record=record,
                         process_options=process_options,
                         operator_groups=operator_groups,
                         process_links=process_links,
                         process_next_links=process_next_links,
                         selected_operators=selected_operators)

# -------------------------- API端点 --------------------------
@app.route('/api/process-model-stats')
@login_required
def process_model_stats():
    """获取工序型号统计数据的API"""
    period = request.args.get('period', 'today')
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')

    # 根据时间范围筛选
    today = date.today()

    if period == 'custom' and start_date_str and end_date_str:
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d') + timedelta(days=1)
            date_filter = ProductionRecord.create_time.between(start_date, end_date)
        except:
            date_filter = db.cast(ProductionRecord.create_time, db.Date) == today
    elif period == 'today':
        date_filter = db.cast(ProductionRecord.create_time, db.Date) == today
    elif period == 'week':
        start_of_week = today - timedelta(days=today.weekday())
        date_filter = db.cast(ProductionRecord.create_time, db.Date) >= start_of_week
    elif period == 'month':
        start_of_month = today.replace(day=1)
        date_filter = db.cast(ProductionRecord.create_time, db.Date) >= start_of_month
    else:
        date_filter = db.cast(ProductionRecord.create_time, db.Date) == today

    # 查询数据
    records = ProductionRecord.query.filter(date_filter).all()

    # 计算总产量
    total_today = sum(record.number for record in records) if records else 0

    # 获取工序数量
    process_count = len(set(record.process for record in records))

    # 按工序和型号分组统计
    process_model_data = {}
    for record in records:
        key = (record.process, record.product_code)
        if key not in process_model_data:
            process_model_data[key] = 0
        process_model_data[key] += record.number

    # 转换为前端需要的格式
    products = []
    for (process, product_code), total_number in process_model_data.items():
        products.append({
            'process': process,
            'product_code': product_code,
            'total_number': total_number
        })

    # 操作员统计
    operator_stats = {}
    operator_names = set()
    for record in records:
        ops = [op.strip() for op in record.operators.split(',') if op.strip()]
        operator_names.update(ops)
        for op in ops:
            key = f"{op} ({record.process})"
            operator_stats[key] = operator_stats.get(key, 0) + record.number

    return jsonify({
        'total_today': total_today,
        'process_count': process_count,
        'products': products,
        'operator_labels': list(operator_stats.keys()),
        'operator_values': list(operator_stats.values()),
        'today': str(today)
    })

@app.route('/delete/<int:id>')
@login_required
def delete_record(id):
    record = db.session.get(ProductionRecord, int(id))

    # 首先检查记录是否存在
    if not record:
        flash('记录不存在！', 'danger')
        return redirect(url_for('index'))

    # 检查记录是否已冻结且用户权限不足
    if record.is_freeze and not current_user.has_permission('production_management', 'advanced'):
        flash('该记录已被确认冻结，您无权限删除！', 'danger')
        return redirect(url_for('index'))

    # 检查删除权限
    if not current_user.has_permission('production_management', 'delete'):
        flash('无权限删除生产记录！', 'danger')
        return redirect(url_for('index'))

    try:
        # 保存删除前的数据用于日志
        deleted_data = {
            'product_code': record.product_code,
            'process': record.process,
            'number': record.number,
            'operators': record.operators,
            'creator': record.creator,
            'create_time': record.create_time.strftime('%Y-%m-%d %H:%M:%S')
        }

        db.session.delete(record)
        db.session.commit()

        # 记录删除日志
        log_activity(
            log_type='record',
            action='delete',
            user_type='admin',
            user_id=current_user.id,
            username=current_user.username,
            target_id=id,
            target_info=deleted_data,
            request=request
        )

        flash(f'生产记录 [{record.product_code}] 已删除！', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'删除失败：{str(e)}', 'danger')

    return redirect(url_for('index'))

@app.route('/api/today-stats')
@login_required
def today_stats():
    period = request.args.get('period', 'today')
    process_filter = request.args.get('process', 'all')
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')

    # 根据时间范围筛选
    today = date.today()

    if period == 'custom' and start_date_str and end_date_str:
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d') + timedelta(days=1)
            date_filter = ProductionRecord.create_time.between(start_date, end_date)
        except:
            date_filter = db.cast(ProductionRecord.create_time, db.Date) == today
    elif period == 'today':
        date_filter = db.cast(ProductionRecord.create_time, db.Date) == today
    elif period == 'week':
        start_of_week = today - timedelta(days=today.weekday())
        date_filter = db.cast(ProductionRecord.create_time, db.Date) >= start_of_week
    elif period == 'month':
        start_of_month = today.replace(day=1)
        date_filter = db.cast(ProductionRecord.create_time, db.Date) >= start_of_month
    else:
        date_filter = db.cast(ProductionRecord.create_time, db.Date) == today

    # 工序筛选
    query = ProductionRecord.query.filter(date_filter)
    if process_filter != 'all':
        query = query.filter(ProductionRecord.process == process_filter)

    records = query.all()

    # 计算统计
    total_today = sum(record.number for record in records) if records else 0

    # 工序分布
    process_stats = {}
    for record in records:
        process_stats[record.process] = process_stats.get(record.process, 0) + record.number

    # 操作员统计（按工序筛选）
    operator_stats = {}
    operator_names = set()
    for record in records:
        ops = [op.strip() for op in record.operators.split(',') if op.strip()]
        operator_names.update(ops)
        for op in ops:
            key = f"{op} ({record.process})" if process_filter == 'all' else op
            operator_stats[key] = operator_stats.get(key, 0) + record.number

    return jsonify({
        'total_today': total_today,
        'process_count': len(process_stats),
        'process_labels': list(process_stats.keys()),
        'process_values': list(process_stats.values()),
        'operator_count': len(operator_names),
        'operator_labels': list(operator_stats.keys()),
        'operator_values': list(operator_stats.values()),
        'today': str(today)
    })

# -------------------------- 工序管理 --------------------------
@app.route('/processes')
@login_required
@permission_required('process_management', 'read')
def process_list():
    """工序管理页面"""
    processes = ProcessOption.query.order_by(ProcessOption.process_name).all()

    # 获取所有操作员组用于关联管理
    operator_groups = get_operator_groups()

    return render_template('process_list.html',
                         processes=processes,
                         operator_groups=operator_groups)

@app.route('/process/add', methods=['GET', 'POST'])
@login_required
@permission_required('process_management', 'create')
def add_process():
    """添加工序"""
    if request.method == 'POST':
        process_name = request.form.get('process_name', '').strip()

        if not process_name:
            flash('工序名称不能为空！', 'danger')
            return render_template('add_process.html')

        # 检查是否已存在
        existing = ProcessOption.query.filter_by(process_name=process_name).first()
        if existing:
            flash(f'工序 "{process_name}" 已存在！', 'danger')
            return render_template('add_process.html')

        new_process = ProcessOption(process_name=process_name)
        db.session.add(new_process)
        try:
            db.session.commit()

            # 记录添加工序日志
            log_activity(
                log_type='process',
                action='add',
                user_type='admin',
                user_id=current_user.id,
                username=current_user.username,
                target_id=new_process.id,
                target_info={'process_name': process_name},
                request=request
            )

            flash(f'工序 "{process_name}" 添加成功！', 'success')
            return redirect(url_for('process_list'))
        except Exception as e:
            db.session.rollback()
            flash(f'添加失败：{str(e)}', 'danger')
            return render_template('add_process.html')

    return render_template('add_process.html')

@app.route('/process/delete/<int:id>')
@login_required
@permission_required('process_management', 'delete')
def delete_process(id):
    """删除工序"""
    process = db.session.get(ProcessOption, int(id))

    if not process:
        flash('工序不存在！', 'danger')
        return redirect(url_for('process_list'))

    # 保存删除前的完整数据
    try:
        linked_groups = json.loads(process.linked_groups) if process.linked_groups else []
    except:
        linked_groups = []

    try:
        linked_next_processes = json.loads(process.linked_next_processes) if process.linked_next_processes else []
    except:
        linked_next_processes = []

    deleted_data = {
        'process_name': process.process_name,
        'linked_groups': linked_groups,
        'linked_next_processes': linked_next_processes,
        'create_time': process.create_time.strftime('%Y-%m-%d %H:%M:%S'),
        'update_time': process.update_time.strftime('%Y-%m-%d %H:%M:%S'),
        'total_groups': len(linked_groups),
        'total_next_processes': len(linked_next_processes)
    }

    # 超级管理员不受限制，可以删除被使用的工序
    if not current_user.is_superuser:
        # 检查是否有生产记录在使用此工序
        records_using = ProductionRecord.query.filter_by(process=process.process_name).first()
        if records_using:
            flash(f'无法删除！有生产记录正在使用工序 "{process.process_name}"', 'danger')
            return redirect(url_for('process_list'))

    try:
        # 删除工序
        db.session.delete(process)
        db.session.commit()

        # 记录删除工序日志（已包含关联信息）
        log_activity(
            log_type='process',
            action='delete',
            user_type='admin',
            user_id=current_user.id,
            username=current_user.username,
            target_id=id,
            target_info=deleted_data,
            request=request
        )

        flash(f'工序 "{process.process_name}" 已删除！', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'删除失败：{str(e)}', 'danger')

    return redirect(url_for('process_list'))

# -------------------------- 工序关联管理API --------------------------
@app.route('/api/process/<int:id>/linked_groups')
@login_required
@permission_required('process_management', 'advanced')
def get_linked_groups(id):
    """获取工序已关联的操作员组"""
    process = db.session.get(ProcessOption, int(id))

    # 获取已关联的组
    linked_groups = get_process_groups(process.process_name)

    # 获取所有可用的组
    all_groups = list(get_operator_groups().keys())

    return jsonify({
        'process_name': process.process_name,
        'linked_groups': linked_groups,
        'all_groups': all_groups
    })

@app.route('/process/<int:id>/link_groups', methods=['POST'])
@login_required
@permission_required('process_management', 'advanced')
def link_process_groups(id):
    """为工序关联操作员组"""
    process = db.session.get(ProcessOption, int(id))

    if not process:
        flash('工序不存在！', 'danger')
        return redirect(url_for('process_list'))

    # 获取前端传递的组列表
    selected_groups = request.form.getlist('groups')

    # 获取关联前的组列表
    old_linked_groups = []
    if process.linked_groups:
        try:
            old_linked_groups = json.loads(process.linked_groups)
        except:
            old_linked_groups = []

    try:
        # 更新工序的关联组
        process.linked_groups = json.dumps(selected_groups)
        process.update_time = datetime.now()

        db.session.commit()

        # 记录工序关联组日志
        log_activity(
            log_type='process',
            action='edit',
            user_type='admin',
            user_id=current_user.id,
            username=current_user.username,
            target_id=process.id,
            target_info={
                'process_name': process.process_name,
                'operation': 'link_groups',
                'old_linked_groups': old_linked_groups,
                'new_linked_groups': selected_groups,
                'changes': {
                    'added': list(set(selected_groups) - set(old_linked_groups)),
                    'removed': list(set(old_linked_groups) - set(selected_groups))
                },
                'total_groups': len(selected_groups)
            },
            request=request
        )

        flash(f'工序 "{process.process_name}" 已成功关联 {len(selected_groups)} 个操作员组', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'关联失败：{str(e)}', 'danger')

    return redirect(url_for('process_list'))

# -------------------------- 工序关联下工序API --------------------------
@app.route('/api/process/<int:id>/linked_next_processes')
@login_required
@permission_required('process_management', 'advanced')
def get_linked_next_processes(id):
    """获取工序已关联的下工序"""
    process = db.session.get(ProcessOption, int(id))

    # 获取已关联的下工序
    if process.linked_next_processes:
        try:
            linked_next = json.loads(process.linked_next_processes)
        except:
            linked_next = []
    else:
        linked_next = []

    # 获取所有工序（除了自己）
    all_processes = ProcessOption.query.filter(ProcessOption.id != id).all()
    all_process_names = [p.process_name for p in all_processes]

    return jsonify({
        'process_name': process.process_name,
        'linked_next_processes': linked_next,
        'all_processes': all_process_names
    })

@app.route('/process/<int:id>/link_next_processes', methods=['POST'])
@login_required
@permission_required('process_management', 'advanced')
def link_process_next(id):
    """为工序关联下工序"""
    process = db.session.get(ProcessOption, int(id))

    if not process:
        flash('工序不存在！', 'danger')
        return redirect(url_for('process_list'))

    # 获取前端传递的下工序列表
    selected_next_processes = request.form.getlist('next_processes')

    # 获取关联前的下工序列表
    old_linked_next = []
    if process.linked_next_processes:
        try:
            old_linked_next = json.loads(process.linked_next_processes)
        except:
            old_linked_next = []

    try:
        # 更新工序的关联下工序
        process.linked_next_processes = json.dumps(selected_next_processes)
        process.update_time = datetime.now()

        db.session.commit()

        # 记录工序关联下工序日志
        log_activity(
            log_type='process',
            action='edit',
            user_type='admin',
            user_id=current_user.id,
            username=current_user.username,
            target_id=process.id,
            target_info={
                'process_name': process.process_name,
                'operation': 'link_next_processes',
                'old_linked_next': old_linked_next,
                'new_linked_next': selected_next_processes,
                'changes': {
                    'added': list(set(selected_next_processes) - set(old_linked_next)),
                    'removed': list(set(old_linked_next) - set(selected_next_processes))
                },
                'total_next_processes': len(selected_next_processes)
            },
            request=request
        )

        flash(f'工序 "{process.process_name}" 已成功关联 {len(selected_next_processes)} 个下工序', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'关联失败：{str(e)}', 'danger')

    return redirect(url_for('process_list'))

# -------------------------- 用户管理 --------------------------
@app.route('/users')
@login_required
@permission_required('user_management', 'read')
def user_list():
    """用户管理页面 - 根据权限过滤显示的用户"""

    # 构建查询
    query = User.query

    # 根据当前用户的权限过滤显示的用户
    if current_user.user_level < 3:  # 非超级管理员
        # 非超级管理员不能看到超级管理员
        query = query.filter(User.user_level < 3)

        if current_user.user_level == 2:  # 管理员
            # 管理员可以看到自己授权的用户和普通用户、子管理员
            query = query.filter((User.granted_by == current_user.id) |
                                (User.user_level <= 2))
        elif current_user.user_level == 1:  # 子管理员
            # 子管理员可以看到所有普通用户和自己
            query = query.filter(
                (User.user_level == 0) |  # 所有普通用户
                (User.id == current_user.id)  # 自己
            )
        else:  # 普通用户
            # 普通用户只能看到自己
            query = query.filter(User.id == current_user.id)

    users = query.order_by(
        User.user_level.desc(),
        User.create_time.desc()
    ).all()

    return render_template('users.html', users=users)

@app.route('/user/add', methods=['GET', 'POST'])
@login_required
@permission_required('user_management', 'create')
def add_user():
    """添加用户 - 使用新权限系统"""

    # 确定当前用户可以授予的用户级别
    grantable_levels = current_user.get_grantable_levels()

    # 普通用户不能添加用户
    if current_user.user_level == 0:
        flash('普通用户无法添加新用户！', 'danger')
        return redirect(url_for('user_list'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        # 获取用户级别
        user_level = int(request.form.get('user_level', 0))

        # 验证用户级别是否在可授予范围内
        if not any(level['level'] == user_level for level in grantable_levels):
            flash('无权限设置该用户级别！', 'danger')
            return render_template('add_user.html',
                                 grantable_levels=grantable_levels,
                                 modules=User.MODULES)

        # 初始化权限字典
        permissions = {}

        # 如果是超级管理员，自动拥有所有权限
        if user_level == 3:
            for module in User.MODULES.keys():
                permissions[module] = User.PERM_ALL
        else:
            # 为每个模块设置权限，并验证当前用户是否有权授予这些权限
            for module in User.MODULES.keys():
                perm_value = 0

                # 检查每个权限位
                read_perm = request.form.get(f'{module}_read') == 'on'
                create_perm = request.form.get(f'{module}_create') == 'on'
                update_perm = request.form.get(f'{module}_update') == 'on'
                delete_perm = request.form.get(f'{module}_delete') == 'on'
                advanced_perm = request.form.get(f'{module}_advanced') == 'on'

                # 验证：当前用户只能授予自己拥有的权限
                if read_perm and not current_user.has_permission(module, 'read'):
                    flash(f'您没有"{User.MODULES[module]}"模块的"查看"权限，无法授予他人！', 'danger')
                    return render_template('add_user.html',
                                         grantable_levels=grantable_levels,
                                         modules=User.MODULES)

                if create_perm and not current_user.has_permission(module, 'create'):
                    flash(f'您没有"{User.MODULES[module]}"模块的"创建"权限，无法授予他人！', 'danger')
                    return render_template('add_user.html',
                                         grantable_levels=grantable_levels,
                                         modules=User.MODULES)

                if update_perm and not current_user.has_permission(module, 'update'):
                    flash(f'您没有"{User.MODULES[module]}"模块的"更新"权限，无法授予他人！', 'danger')
                    return render_template('add_user.html',
                                         grantable_levels=grantable_levels,
                                         modules=User.MODULES)

                if delete_perm and not current_user.has_permission(module, 'delete'):
                    flash(f'您没有"{User.MODULES[module]}"模块的"删除"权限，无法授予他人！', 'danger')
                    return render_template('add_user.html',
                                         grantable_levels=grantable_levels,
                                         modules=User.MODULES)

                if advanced_perm and not current_user.has_permission(module, 'advanced'):
                    flash(f'您没有"{User.MODULES[module]}"模块的"高级"权限，无法授予他人！', 'danger')
                    return render_template('add_user.html',
                                         grantable_levels=grantable_levels,
                                         modules=User.MODULES)

                # 计算权限值
                if read_perm:
                    perm_value |= User.PERM_READ
                if create_perm:
                    perm_value |= User.PERM_CREATE
                if update_perm:
                    perm_value |= User.PERM_UPDATE
                if delete_perm:
                    perm_value |= User.PERM_DELETE
                if advanced_perm:
                    perm_value |= User.PERM_ADVANCED

                permissions[module] = perm_value

        # 验证数据
        if not username or not password:
            flash('用户名和密码不能为空！', 'danger')
            return render_template('add_user.html',
                                 grantable_levels=grantable_levels,
                                 modules=User.MODULES)

        # 检查用户名是否已存在
        if User.query.filter_by(username=username).first():
            flash('用户名已存在！', 'danger')
            return render_template('add_user.html',
                                 grantable_levels=grantable_levels,
                                 modules=User.MODULES)

        # 创建新用户
        new_user = User(
            username=username,
            user_level=user_level,
            permissions=permissions,
            granted_by=current_user.id
        )
        new_user.set_password(password)

        db.session.add(new_user)
        try:
            db.session.commit()

            # 记录添加用户日志
            log_activity(
                log_type='user',
                action='add',
                user_type='admin',
                user_id=current_user.id,
                username=current_user.username,
                target_id=new_user.id,
                target_info={
                    'username': username,
                    'user_level': user_level,
                    'user_level_display': User.LEVEL_NAMES_ZH.get(user_level, '普通用户'),
                    'granted_by': current_user.username,
                    'has_permissions': bool(permissions),
                    'permissions_summary': {module: value for module, value in permissions.items() if value > 0}
                },
                request=request
            )

            flash(f'用户 [{username}] 添加成功！', 'success')
            return redirect(url_for('user_list'))
        except Exception as e:
            db.session.rollback()
            flash(f'添加失败：{str(e)}', 'danger')

    return render_template('add_user.html',
                         grantable_levels=grantable_levels,
                         modules=User.MODULES)

@app.route('/edit_user/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_user(id):
    if not current_user.has_permission('user_management', 'update'):
        flash('您没有权限编辑用户', 'danger')
        return redirect(url_for('user_list'))

    user = User.query.get_or_404(id)

    # 检查是否可编辑
    if not current_user.can_edit_user(user):
        flash('无权限编辑该用户！', 'danger')
        return redirect(url_for('user_list'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user_level = int(request.form.get('user_level', 0))

        # 保存编辑前的数据用于日志
        old_data = {
            'username': user.username,
            'user_level': user.user_level,
            'permissions': user.permissions.copy() if user.permissions else {}
        }

        # 用户名不能重复（除非是自己）
        if username != user.username:
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('用户名已存在', 'danger')
                return redirect(url_for('edit_user', id=id))

        # 更新基本信息
        user.username = username

        # 更新密码（如果提供了新密码）
        if password:
            user.set_password(password)

        # 更新用户级别
        user.user_level = user_level

        # 超级管理员特殊处理
        if user_level == 3:
            # 超级管理员拥有所有权限
            permissions = {}
            for module in User.MODULES.keys():
                permissions[module] = User.PERM_ALL
            user.permissions = permissions
        else:
            # 获取用户当前的权限，用于设置默认值
            user_current_perms = user.get_all_permissions() if user.permissions else {}
            permissions = {}

            # 为每个模块设置权限，并验证当前用户是否有权授予这些权限
            for module in User.MODULES.keys():
                perm_value = 0

                # 检查每个权限位
                read_perm = request.form.get(f'{module}_read') == '1'
                create_perm = request.form.get(f'{module}_create') == '1'
                update_perm = request.form.get(f'{module}_update') == '1'
                delete_perm = request.form.get(f'{module}_delete') == '1'
                advanced_perm = request.form.get(f'{module}_advanced') == '1'

                # 验证：当前用户只能授予自己拥有的权限
                # 注意：这里我们只检查当前用户是否有权限授予，如果没有，则保持用户原有权限
                if read_perm and not current_user.has_permission(module, 'read'):
                    # 当前用户没有读权限，但表单却提交了读权限，这可能是个错误
                    # 保持用户原有的读权限
                    if module in user_current_perms:
                        read_perm = user_current_perms[module]['read']
                    else:
                        read_perm = False

                if create_perm and not current_user.has_permission(module, 'create'):
                    if module in user_current_perms:
                        create_perm = user_current_perms[module]['create']
                    else:
                        create_perm = False

                if update_perm and not current_user.has_permission(module, 'update'):
                    if module in user_current_perms:
                        update_perm = user_current_perms[module]['update']
                    else:
                        update_perm = False

                if delete_perm and not current_user.has_permission(module, 'delete'):
                    if module in user_current_perms:
                        delete_perm = user_current_perms[module]['delete']
                    else:
                        delete_perm = False

                if advanced_perm and not current_user.has_permission(module, 'advanced'):
                    if module in user_current_perms:
                        advanced_perm = user_current_perms[module]['advanced']
                    else:
                        advanced_perm = False

                # 计算权限值
                if read_perm:
                    perm_value |= User.PERM_READ
                if create_perm:
                    perm_value |= User.PERM_CREATE
                if update_perm:
                    perm_value |= User.PERM_UPDATE
                if delete_perm:
                    perm_value |= User.PERM_DELETE
                if advanced_perm:
                    perm_value |= User.PERM_ADVANCED

                permissions[module] = perm_value

            user.permissions = permissions

        # 设置授予者
        user.granted_by = current_user.id
        user.update_time = datetime.utcnow()

        try:
            db.session.commit()

            # 记录编辑用户日志
            log_activity(
                log_type='user',
                action='edit',
                user_type='admin',
                user_id=current_user.id,
                username=current_user.username,
                target_id=user.id,
                target_info={
                    'old_data': old_data,
                    'new_data': {
                        'username': username,
                        'user_level': user_level,
                        'user_level_display': User.LEVEL_NAMES_ZH.get(user_level, '普通用户'),
                        'permissions': permissions,
                        'granted_by': current_user.username,
                        'password_changed': bool(password)
                    }
                },
                request=request
            )

            flash(f'用户 {username} 已更新', 'success')
            return redirect(url_for('user_list'))
        except Exception as e:
            db.session.rollback()
            flash(f'更新失败: {str(e)}', 'danger')

    # GET请求时，显示编辑表单
    return render_template('edit_user.html',
                         user=user,
                         modules=User.MODULES,
                         grantable_levels=current_user.get_grantable_levels())

@app.route('/user/delete/<int:id>')
@login_required
@permission_required('user_management', 'delete')
def delete_user(id):
    """删除用户 - 权限检查"""

    # 禁止删除自己
    if id == current_user.id:
        flash('不能删除当前登录的用户！', 'danger')
        return redirect(url_for('user_list'))

    user = db.session.get(User, int(id))

    if not user:
        flash('用户不存在！', 'danger')
        return redirect(url_for('user_list'))

    # 权限检查：高权限可以删除低权限，同级不能相互删除
    if not current_user.can_edit_user(user):
        flash('无权限删除该用户！', 'danger')
        return redirect(url_for('user_list'))

    try:
        # 保存删除前的数据用于日志
        user_data = {
            'user_id': user.id,
            'username': user.username,
            'user_level': user.user_level,
            'user_level_display': User.LEVEL_NAMES_ZH.get(user.user_level, '普通用户'),
            'granted_by': user.granted_by,
            'create_time': user.create_time.strftime('%Y-%m-%d %H:%M:%S'),
            'update_time': user.update_time.strftime('%Y-%m-%d %H:%M:%S'),
            'has_permissions': bool(user.permissions),
            'permissions_summary': user.permissions if user.permissions else {}
        }

        db.session.delete(user)
        db.session.commit()

        # 记录删除用户日志
        log_activity(
            log_type='user',
            action='delete',
            user_type='admin',
            user_id=current_user.id,
            username=current_user.username,
            target_id=id,
            target_info=user_data,
            request=request
        )

        flash(f'用户 [{user.username}] 已删除！', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'删除失败：{str(e)}', 'danger')

    return redirect(url_for('user_list'))

# -------------------------- 操作员组管理 --------------------------
@app.route('/operators')
@login_required
@permission_required('operator_management', 'read')
def operator_list():
    """操作员管理页面"""
    # 按组名分组显示
    groups = db.session.query(
        OperatorGroup.group_name,
        db.func.string_agg(OperatorGroup.operator_name, ', ')
    ).group_by(OperatorGroup.group_name).order_by(OperatorGroup.group_name).all()

    # 获取所有操作员
    operators = OperatorGroup.query.order_by(
        OperatorGroup.group_name,
        OperatorGroup.operator_name
    ).all()

    # 获取当前日期，用于签字状态判断
    today = date.today()

    return render_template('operator_list.html',
                         groups=groups,
                         operators=operators,
                         today=today)

@app.route('/operator/add', methods=['GET', 'POST'])
@login_required
@permission_required('operator_management', 'create')
def add_operator():
    """添加操作员"""
    # 获取现有的组名（去重）
    existing_groups = db.session.query(
        OperatorGroup.group_name.distinct()
    ).order_by(OperatorGroup.group_name).all()
    group_list = [g[0] for g in existing_groups]

    if request.method == 'POST':
        # 处理组名
        group_selection = request.form.get('group_name', '').strip()
        new_group = request.form.get('new_group', '').strip()

        if group_selection == 'new':
            if not new_group:
                flash('请填写新的组名！', 'danger')
                return render_template('add_operator.html', groups=group_list)
            group_name = new_group
        else:
            group_name = group_selection

        if not group_name:
            flash('请选择或输入组名！', 'danger')
            return render_template('add_operator.html', groups=group_list)

        operator_names = request.form.get('operator_names', '').strip()
        password = request.form.get('password', '').strip()

        if not operator_names:
            flash('操作员名称不能为空！', 'danger')
            return render_template('add_operator.html', groups=group_list)

        # 如果未提供密码，使用默认密码
        if not password:
            password = '000000'

        # 分割操作员名称
        import re
        names = re.split(r'[,;\s\n]+', operator_names)
        names = [name.strip() for name in names if name.strip()]

        if not names:
            flash('请至少输入一个有效的操作员名称！', 'danger')
            return render_template('add_operator.html', groups=group_list)

        success_count = 0
        error_messages = []
        added_operators = []

        for name in names:
            try:
                # 检查是否已存在
                existing = OperatorGroup.query.filter_by(
                    group_name=group_name,
                    operator_name=name
                ).first()

                if not existing:
                    new_op = OperatorGroup(group_name=group_name, operator_name=name)
                    new_op.set_password(password)
                    db.session.add(new_op)
                    success_count += 1
                    added_operators.append(name)
                else:
                    error_messages.append(f"操作员 '{name}' 在组 '{group_name}' 中已存在")
            except Exception as e:
                error_messages.append(f"操作员 '{name}' 添加失败: {str(e)}")

        try:
            if success_count > 0:
                db.session.commit()

                # 记录添加操作员日志
                log_activity(
                    log_type='operator',
                    action='add',
                    user_type='admin',
                    user_id=current_user.id,
                    username=current_user.username,
                    target_info={
                        'group_name': group_name,
                        'operator_names': added_operators,
                        'success_count': success_count,
                        'total_attempted': len(names),
                        'has_password': bool(password) and password != '000000'
                    },
                    request=request
                )

                flash(f'成功添加 {success_count} 个操作员到组 "{group_name}"！', 'success')
            else:
                flash('没有成功添加任何操作员', 'warning')

            if error_messages:
                for error in error_messages:
                    flash(error, 'warning')

        except Exception as e:
            db.session.rollback()
            flash(f'保存失败：{str(e)}', 'danger')
            return render_template('add_operator.html', groups=group_list)

        return redirect(url_for('operator_list'))

    return render_template('add_operator.html', groups=group_list)

@app.route('/operator/delete/<int:id>')
@login_required
@permission_required('operator_management', 'delete')
def delete_operator(id):
    """删除操作员"""
    operator = db.session.get(OperatorGroup, int(id))

    if not operator:
        flash('操作员不存在！', 'danger')
        return redirect(url_for('operator_list'))

    # 保存删除前的数据用于日志
    operator_data = {
        'operator_id': operator.id,
        'operator_name': operator.operator_name,
        'group_name': operator.group_name,
        'group_owner': operator.group_owner,
        'has_signature': bool(operator.signature_file)
    }

    # 超级管理员不受限制，可以删除被使用的操作员
    if not current_user.is_superuser:
        # 检查是否有生产记录在使用此操作员
        records_using = ProductionRecord.query.filter(
            ProductionRecord.operators.contains(operator.operator_name)
        ).first()

        if records_using:
            flash(f'无法删除！有生产记录正在使用操作员 "{operator.operator_name}"', 'danger')
            return redirect(url_for('operator_list'))

    try:
        # 首先删除关联的签名文件（如果存在）
        if operator.signature_file:
            delete_signature_file(operator.signature_file)

        db.session.delete(operator)
        db.session.commit()

        # 记录删除操作员日志
        log_activity(
            log_type='operator',
            action='delete',
            user_type='admin',
            user_id=current_user.id,
            username=current_user.username,
            target_id=id,
            target_info=operator_data,
            request=request
        )

        flash(f'操作员 "{operator.operator_name}" 已删除！', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'删除失败：{str(e)}', 'danger')

    return redirect(url_for('operator_list'))

@app.route('/operator/delete_group/<group_name>')
@login_required
@permission_required('operator_management', 'delete')
def delete_operator_group(group_name):
    """删除操作员组"""
    group_operators = OperatorGroup.query.filter_by(group_name=group_name).all()

    if not group_operators:
        flash(f'组 "{group_name}" 不存在或为空！', 'danger')
        return redirect(url_for('operator_list'))

    # 保存删除前的数据用于日志
    group_data = {
        'group_name': group_name,
        'operator_count': len(group_operators),
        'operator_names': [op.operator_name for op in group_operators],
        'group_owners': [op.operator_name for op in group_operators if op.group_owner],
        'has_signatures': [op.operator_name for op in group_operators if op.signature_file]
    }

    # 超级管理员不受限制，可以删除被使用的操作员组
    if not current_user.is_superuser:
        # 检查每个操作员是否被使用
        used_operators = []
        for op in group_operators:
            records_using = ProductionRecord.query.filter(
                ProductionRecord.operators.contains(op.operator_name)
            ).first()
            if records_using:
                used_operators.append(op.operator_name)

        if used_operators:
            flash(f'无法删除组！以下操作员正在被使用：{", ".join(used_operators)}', 'danger')
            return redirect(url_for('operator_list'))

    try:
        # 首先删除所有操作员的签名文件
        for operator in group_operators:
            if operator.signature_file:
                delete_signature_file(operator.signature_file)

        # 删除整个组的操作员
        delete_count = OperatorGroup.query.filter_by(group_name=group_name).delete()
        db.session.commit()

        # 记录删除操作员组日志
        log_activity(
            log_type='operator',
            action='delete',
            user_type='admin',
            user_id=current_user.id,
            username=current_user.username,
            target_info=group_data,
            request=request
        )

        flash(f'成功删除组 "{group_name}" 及其 {delete_count} 个操作员！', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'删除失败：{str(e)}', 'danger')

    return redirect(url_for('operator_list'))

# --------------------------- 系统管理 ---------------------------
@app.route('/system')
@login_required
@permission_required('system_management', 'read')
def system_management():
    return render_template('system.html')

# -------------------------- 备份相关函数 --------------------------
def perform_backup(include_timestamp=True, compress=True, is_auto_backup=False):
    """执行数据库备份的核心函数"""
    try:
        # 生成备份文件名
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        db_name = DB_NAME

        if include_timestamp:
            if is_auto_backup:
                filename = f"{db_name}_backup_auto_{timestamp}.sql"
            else:
                filename = f"{db_name}_backup_manual{timestamp}.sql"
        else:
            if is_auto_backup:
                filename = f"{db_name}_backup_auto.sql"
            else:
                filename = f"{db_name}_backup_manual.sql"

        filepath = os.path.join(BACKUP_STORAGE_PATH, filename)

        # 使用 pg_dump 备份数据库
        cmd = [
            'pg_dump',
            '-h', DB_HOST,
            '-p', DB_PORT,
            '-U', DB_USER,
            '-d', DB_NAME,
            '-f', filepath
        ]

        # 设置环境变量包含密码
        env = os.environ.copy()
        env['PGPASSWORD'] = DB_PASSWORD

        result = subprocess.run(cmd, env=env, capture_output=True, text=True)

        if result.returncode != 0:
            app.logger.error(f"数据库备份失败: {result.stderr}")
            return {'success': False, 'message': f'备份失败: {result.stderr}'}

        # 如果需要压缩
        final_filename = filename
        if compress:
            compressed_filename = filename + '.gz'
            compressed_filepath = os.path.join(BACKUP_STORAGE_PATH, compressed_filename)

            with open(filepath, 'rb') as f_in:
                with gzip.open(compressed_filepath, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)

            # 删除未压缩的文件
            os.remove(filepath)
            final_filename = compressed_filename

        app.logger.info(f"数据库备份成功: {final_filename}")
        return {
            'success': True,
            'message': '数据库备份成功',
            'filename': final_filename,
            'timestamp': timestamp,
            'is_auto_backup': is_auto_backup
        }

    except Exception as e:
        app.logger.error(f"备份过程中出错: {str(e)}")
        return {'success': False, 'message': f'备份失败: {str(e)}'}

def cleanup_old_backups():
    """清理旧的备份文件"""
    try:
        backup_dir = Path(BACKUP_STORAGE_PATH)

        if not backup_dir.exists():
            return

        backup_files = []
        for file in backup_dir.iterdir():
            if file.is_file() and file.suffix in ['.sql', '.gz']:
                stats = file.stat()
                backup_files.append({
                    'file': file,
                    'ctime': stats.st_ctime,
                    'age_days': (time.time() - stats.st_ctime) / (24 * 3600)
                })

        # 按创建时间排序，最旧的在前
        backup_files.sort(key=lambda x: x['ctime'])

        # 清理超过保留天数的备份
        cleaned_count = 0
        for backup in backup_files[:]:
            if backup['age_days'] > BACKUP_RETENTION_DAYS:
                try:
                    backup['file'].unlink()
                    backup_files.remove(backup)
                    cleaned_count += 1
                    app.logger.info(f"删除旧备份: {backup['file'].name}")
                except Exception as e:
                    app.logger.error(f"删除备份文件失败 {backup['file'].name}: {str(e)}")

        # 如果文件数量超过最大限制，删除最旧的
        if len(backup_files) > MAX_BACKUP_FILES:
            files_to_delete = backup_files[:len(backup_files) - MAX_BACKUP_FILES]
            for backup in files_to_delete:
                try:
                    backup['file'].unlink()
                    cleaned_count += 1
                    app.logger.info(f"删除超额备份: {backup['file'].name}")
                except Exception as e:
                    app.logger.error(f"删除备份文件失败 {backup['file'].name}: {str(e)}")

        if cleaned_count > 0:
            app.logger.info(f"已清理 {cleaned_count} 个旧备份文件")

    except Exception as e:
        app.logger.error(f"清理旧备份失败: {str(e)}")

def auto_backup_job():
    """定时备份任务"""
    if not ENABLE_AUTO_BACKUP:
        return

    try:
        app.logger.info(f"开始执行定时备份，时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # 执行备份
        result = perform_backup(
            include_timestamp=DEFAULT_INCLUDE_TIMESTAMP,
            compress=DEFAULT_COMPRESS,
            is_auto_backup=True
        )

        if result['success']:
            # 记录备份日志
            log_activity(
                log_type='backup',
                action='backup',
                user_type='system',
                user_id=None,
                username='系统自动任务',
                target_info={
                    'filename': result['filename'],
                    'is_auto_backup': True,
                    'timestamp': result['timestamp']
                },
                request=None
            )
            app.logger.info(f"定时备份成功: {result['filename']}")

            # 清理旧备份
            cleanup_old_backups()
        else:
            app.logger.error(f"定时备份失败: {result['message']}")

    except Exception as e:
        app.logger.error(f"定时备份任务执行失败: {str(e)}")

# -------------------------- 初始化定时调度器 --------------------------
def init_scheduler():
    """初始化定时任务调度器"""
    if not ENABLE_AUTO_BACKUP:
        return None

    try:
        scheduler = BackgroundScheduler()
        scheduler.add_jobstore('memory')

        # 添加定时备份任务
        hour, minute = map(int, AUTO_BACKUP_TIME.split(':'))
        scheduler.add_job(
            auto_backup_job,
            'cron',
            hour=hour,
            minute=minute,
            id='auto_backup',
            name='自动数据库备份',
            replace_existing=True
        )

        # 添加清理任务（每天3:00执行）
        scheduler.add_job(
            cleanup_old_backups,
            'cron',
            hour=3,
            minute=0,
            id='cleanup_backups',
            name='清理旧备份',
            replace_existing=True
        )

        scheduler.start()
        app.logger.info(f"定时任务调度器已启动，自动备份时间: {AUTO_BACKUP_TIME}")
        return scheduler

    except Exception as e:
        app.logger.error(f"启动定时任务调度器失败: {str(e)}")
        return None

# -------------------------- 数据库备份功能 --------------------------
@app.route('/system/backup', methods=['POST'])
@login_required
@permission_required('system_management', 'advanced')
def backup_database():
    """创建数据库备份"""
    # 只有超级管理员可以备份
    if not current_user.is_superuser:
        return jsonify({'success': False, 'message': '需要超级管理员权限'})

    data = request.get_json()
    include_timestamp = data.get('include_timestamp', DEFAULT_INCLUDE_TIMESTAMP)
    compress = data.get('compress', DEFAULT_COMPRESS)

    result = perform_backup(include_timestamp=include_timestamp, compress=compress)

    if result['success']:
        # 记录备份日志
        log_activity(
            log_type='backup',
            action='backup',
            user_type='admin',
            user_id=current_user.id,
            username=current_user.username,
            target_info={
                'filename': result['filename'],
                'include_timestamp': include_timestamp,
                'compress': compress
            },
            request=request
        )

        download_path = f"/system/backup/download/{result['filename']}"

        return jsonify({
            'success': True,
            'message': '数据库备份成功',
            'filename': result['filename'],
            'download_url': download_path,
            'timestamp': result['timestamp']
        })
    else:
        return jsonify({'success': False, 'message': result['message']})

@app.route('/system/backup/list')
@login_required
@permission_required('system_management', 'read')
def list_backups():
    """列出所有备份文件"""
    try:
        backups = []
        backup_dir = Path(BACKUP_STORAGE_PATH)

        if backup_dir.exists():
            for file in backup_dir.iterdir():
                if file.is_file() and file.suffix in ['.sql', '.gz', '.zip']:
                    stats = file.stat()
                    backups.append({
                        'filename': file.name,
                        'size': format_file_size(stats.st_size),
                        'created_at': datetime.fromtimestamp(stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
                        'filepath': str(file)
                    })

        # 按创建时间倒序排序
        backups.sort(key=lambda x: x['created_at'], reverse=True)

        return jsonify({
            'success': True,
            'backups': backups
        })

    except Exception as e:
        app.logger.error(f"列出备份文件失败: {str(e)}")
        return jsonify({'success': False, 'message': f'列出备份文件失败: {str(e)}'})

@app.route('/system/backup/download/<filename>')
@login_required
@permission_required('system_management', 'read')
def download_backup(filename):
    """下载备份文件"""
    try:
        filepath = os.path.join(BACKUP_STORAGE_PATH, filename)

        if not os.path.exists(filepath):
            return "文件不存在", 404

        return send_file(filepath, as_attachment=True)

    except Exception as e:
        app.logger.error(f"下载备份文件失败: {str(e)}")
        return "下载失败", 500

@app.route('/system/backup/delete/<filename>', methods=['DELETE'])
@login_required
@permission_required('system_management', 'advanced')
def delete_backup(filename):
    """删除备份文件"""
    try:
        # 只有超级管理员可以删除
        if not current_user.is_superuser:
            return jsonify({'success': False, 'message': '需要超级管理员权限'})

        filepath = os.path.join(BACKUP_STORAGE_PATH, filename)

        if not os.path.exists(filepath):
            return jsonify({'success': False, 'message': '文件不存在'})

        # 获取文件大小
        file_size = os.path.getsize(filepath)

        os.remove(filepath)

        # 记录删除备份日志
        log_activity(
            log_type='backup',
            action='delete',
            user_type='admin',
            user_id=current_user.id,
            username=current_user.username,
            target_info={
                'filename': filename,
                'filepath': filepath,
                'size': file_size
            },
            request=request
        )

        app.logger.info(f"备份文件已删除: {filename}")

        return jsonify({
            'success': True,
            'message': '备份文件已删除'
        })

    except Exception as e:
        app.logger.error(f"删除备份文件失败: {str(e)}")
        return jsonify({'success': False, 'message': f'删除失败: {str(e)}'})

# -------------------------- 定时备份管理API --------------------------
@app.route('/system/backup/schedule', methods=['GET'])
@login_required
@permission_required('system_management', 'advanced')
def get_backup_schedule():
    """获取定时备份设置"""
    if not current_user.is_superuser:
        return jsonify({'success': False, 'message': '需要超级管理员权限'})

    return jsonify({
        'success': True,
        'enable_auto_backup': ENABLE_AUTO_BACKUP,
        'auto_backup_time': AUTO_BACKUP_TIME,
        'backup_retention_days': BACKUP_RETENTION_DAYS,
        'max_backup_files': MAX_BACKUP_FILES,
        'default_compress': DEFAULT_COMPRESS,
        'default_include_timestamp': DEFAULT_INCLUDE_TIMESTAMP
    })

@app.route('/system/backup/schedule/update', methods=['POST'])
@login_required
@permission_required('system_management', 'advanced')
def update_backup_schedule():
    """更新定时备份设置"""
    if not current_user.is_superuser:
        return jsonify({'success': False, 'message': '需要超级管理员权限'})

    # 全局声明移到函数顶部
    global ENABLE_AUTO_BACKUP, AUTO_BACKUP_TIME, BACKUP_RETENTION_DAYS
    global MAX_BACKUP_FILES, DEFAULT_COMPRESS, DEFAULT_INCLUDE_TIMESTAMP

    try:
        data = request.get_json()

        # 更新配置对象
        config.set('backup', 'ENABLE_AUTO_BACKUP', str(data.get('enable_auto_backup', ENABLE_AUTO_BACKUP)))
        config.set('backup', 'AUTO_BACKUP_TIME', data.get('auto_backup_time', AUTO_BACKUP_TIME))
        config.set('backup', 'BACKUP_RETENTION_DAYS', str(data.get('backup_retention_days', BACKUP_RETENTION_DAYS)))
        config.set('backup', 'MAX_BACKUP_FILES', str(data.get('max_backup_files', MAX_BACKUP_FILES)))
        config.set('backup', 'DEFAULT_COMPRESS', str(data.get('default_compress', DEFAULT_COMPRESS)))
        config.set('backup', 'DEFAULT_INCLUDE_TIMESTAMP', str(data.get('default_include_timestamp', DEFAULT_INCLUDE_TIMESTAMP)))

        # 保存到配置文件
        with open('config.conf', 'w') as configfile:
            config.write(configfile)

        # 重新加载配置
        ENABLE_AUTO_BACKUP = config.getboolean('backup', 'ENABLE_AUTO_BACKUP')
        AUTO_BACKUP_TIME = config.get('backup', 'AUTO_BACKUP_TIME')
        BACKUP_RETENTION_DAYS = config.getint('backup', 'BACKUP_RETENTION_DAYS')
        MAX_BACKUP_FILES = config.getint('backup', 'MAX_BACKUP_FILES')
        DEFAULT_COMPRESS = config.getboolean('backup', 'DEFAULT_COMPRESS')
        DEFAULT_INCLUDE_TIMESTAMP = config.getboolean('backup', 'DEFAULT_INCLUDE_TIMESTAMP')

        # 重启调度器
        if hasattr(app, 'scheduler') and app.scheduler:
            app.scheduler.shutdown()

        app.scheduler = init_scheduler()

        # 记录配置更改日志
        log_activity(
            log_type='system',
            action='update',
            user_type='admin',
            user_id=current_user.id,
            username=current_user.username,
            target_info={
                'action': 'update_backup_schedule',
                'new_settings': data
            },
            request=request
        )

        return jsonify({
            'success': True,
            'message': '备份设置已更新',
            'settings': {
                'enable_auto_backup': ENABLE_AUTO_BACKUP,
                'auto_backup_time': AUTO_BACKUP_TIME,
                'backup_retention_days': BACKUP_RETENTION_DAYS,
                'max_backup_files': MAX_BACKUP_FILES,
                'default_compress': DEFAULT_COMPRESS,
                'default_include_timestamp': DEFAULT_INCLUDE_TIMESTAMP
            }
        })

    except Exception as e:
        app.logger.error(f"更新备份设置失败: {str(e)}")
        return jsonify({'success': False, 'message': f'更新失败: {str(e)}'})

@app.route('/system/backup/run_now', methods=['POST'])
@login_required
@permission_required('system_management', 'advanced')
def run_backup_now():
    """立即执行备份（手动触发）"""
    if not current_user.is_superuser:
        return jsonify({'success': False, 'message': '需要超级管理员权限'})

    try:
        # 在新线程中执行备份，避免阻塞请求
        def backup_thread():
            result = perform_backup(
                include_timestamp=DEFAULT_INCLUDE_TIMESTAMP,
                compress=DEFAULT_COMPRESS,
                is_auto_backup=False
            )

            if result['success']:
                # 记录备份日志
                log_activity(
                    log_type='backup',
                    action='backup',
                    user_type='admin',
                    user_id=current_user.id,
                    username=current_user.username,
                    target_info={
                        'filename': result['filename'],
                        'is_auto_backup': False,
                        'timestamp': result['timestamp']
                    },
                    request=request
                )
                app.logger.info(f"手动触发备份成功: {result['filename']}")
            else:
                app.logger.error(f"手动触发备份失败: {result['message']}")

        thread = threading.Thread(target=backup_thread)
        thread.daemon = True
        thread.start()

        return jsonify({
            'success': True,
            'message': '备份任务已启动，请稍后在备份列表中查看结果'
        })

    except Exception as e:
        app.logger.error(f"启动备份任务失败: {str(e)}")
        return jsonify({'success': False, 'message': f'启动备份失败: {str(e)}'})

# -------------------------- 系统状态API --------------------------
@app.route('/system/stats')
@login_required
@permission_required('system_management', 'read')
def system_stats():
    """获取系统统计信息"""
    try:
        # 数据库大小（估算）
        db_size = 0
        try:
            conn = psycopg2.connect(
                host=DB_HOST,
                port=DB_PORT,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME
            )
            cursor = conn.cursor()

            # 获取数据库大小
            cursor.execute("SELECT pg_database_size(%s)", (DB_NAME,))
            db_size_bytes = cursor.fetchone()[0]
            db_size = format_file_size(db_size_bytes)

            cursor.close()
            conn.close()
        except Exception as e:
            app.logger.warning(f"获取数据库大小失败: {str(e)}")
            db_size = "未知"

        # 备份文件统计
        backup_dir = Path(BACKUP_STORAGE_PATH)
        backup_count = 0
        total_backup_size = 0
        last_backup = None
        auto_backup_count = 0
        manual_backup_count = 0

        if backup_dir.exists():
            backup_files = list(backup_dir.glob('*.sql')) + list(backup_dir.glob('*.gz')) + list(backup_dir.glob('*.zip'))
            backup_count = len(backup_files)

            for file in backup_files:
                total_backup_size += file.stat().st_size
                if 'auto' in file.name.lower():
                    auto_backup_count += 1
                else:
                    manual_backup_count += 1

            if backup_files:
                # 按修改时间排序，获取最新的备份
                latest_backup = max(backup_files, key=lambda f: f.stat().st_mtime)
                last_backup = datetime.fromtimestamp(latest_backup.stat().st_mtime).strftime('%Y-%m-%d %H:%M')

        # 定时备份状态
        next_backup = "未启用"
        if ENABLE_AUTO_BACKUP and hasattr(app, 'scheduler') and app.scheduler:
            try:
                job = app.scheduler.get_job('auto_backup')
                if job:
                    next_run = job.next_run_time
                    if next_run:
                        next_backup = next_run.strftime('%Y-%m-%d %H:%M:%S')
            except:
                next_backup = "未知"

        return jsonify({
            'success': True,
            'database_size': db_size,
            'backup_count': backup_count,
            'auto_backup_count': auto_backup_count,
            'manual_backup_count': manual_backup_count,
            'total_backup_size': format_file_size(total_backup_size),
            'last_backup': last_backup,
            'auto_backup_enabled': ENABLE_AUTO_BACKUP,
            'auto_backup_time': AUTO_BACKUP_TIME,
            'next_auto_backup': next_backup,
            'backup_retention_days': BACKUP_RETENTION_DAYS,
            'max_backup_files': MAX_BACKUP_FILES
        })

    except Exception as e:
        app.logger.error(f"获取系统统计失败: {str(e)}")
        return jsonify({'success': False, 'message': f'获取统计失败: {str(e)}'})

# -------------------------- 操作员功能 --------------------------
@app.route('/operator/dashboard')
@operator_login_required
def operator_dashboard():
    """操作员个人仪表板，显示当天生产记录"""
    operator_id = session.get('operator_id')
    operator = db.session.get(OperatorGroup, int(operator_id))

    if not operator:
        flash('操作员信息不存在！', 'danger')
        return redirect(url_for('login'))

    operator_name = operator.operator_name
    is_group_owner = operator.group_owner

    # 获取今天的日期
    today = date.today()

    # 修复1: 使用更精确的日期范围查询
    start_of_day = datetime.combine(today, datetime.min.time())
    end_of_day = datetime.combine(today, datetime.max.time())

    # 如果是组管理员，获取组内所有记录；否则只获取自己的记录
    if is_group_owner:
        # 获取组内所有操作员
        group_members = OperatorGroup.query.filter_by(
            group_name=operator.group_name
        ).all()

        member_names = [member.operator_name for member in group_members]

        # 查询今日所有记录，然后过滤出包含组内操作员的记录
        all_today_records = ProductionRecord.query.filter(
            ProductionRecord.create_time >= start_of_day,
            ProductionRecord.create_time <= end_of_day
        ).order_by(ProductionRecord.create_time.desc()).all()

        # 精确过滤操作员记录
        today_records = []
        for record in all_today_records:
            # 将逗号分隔的操作员字符串转换为列表
            operators_list = [op.strip() for op in record.operators.split(',')]
            # 检查是否有组内操作员参与此记录
            if any(op in member_names for op in operators_list):
                today_records.append(record)

        # 计算今日统计
        total_today = sum(record.number for record in today_records)

        # 按工序统计
        process_stats = {}
        for record in today_records:
            if record.process not in process_stats:
                process_stats[record.process] = 0
            process_stats[record.process] += record.number

        # 如果是组管理员，获取组内统计信息
        group_total = total_today

        # 获取今天已签字的组员（只统计组管理员）
        signed_members = []
        group_members_with_signatures = []
        for member in group_members:
            # 判断是否是组管理员
            if member.group_owner:
                # 检查是否有签名文件且签名时间是今天
                is_signed_today = False
                signature_time_display = None

                if member.signature_file and member.signature_time:
                    # 检查签名时间是否是今天
                    if member.signature_time.date() == today:
                        is_signed_today = True
                        signature_time_display = member.signature_time.strftime('%H:%M')
                        signed_members.append(member)
                    else:
                        # 签名不是今天的，视为未签字
                        is_signed_today = False
                        signature_time_display = f"{member.signature_time.strftime('%m-%d %H:%M')}"
                else:
                    # 没有签名或签名时间
                    is_signed_today = False
                    signature_time_display = None

                group_members_with_signatures.append({
                    'id': member.id,
                    'operator_name': member.operator_name,
                    'group_owner': member.group_owner,
                    'signature_file': member.signature_file,
                    'signature_time': member.signature_time,
                    'is_signed_today': is_signed_today,
                    'signature_time_display': signature_time_display,
                    'is_signed': bool(member.signature_file)
                })
            else:
                # 普通操作员不显示签字状态
                group_members_with_signatures.append({
                    'id': member.id,
                    'operator_name': member.operator_name,
                    'group_owner': member.group_owner,
                    'signature_file': None,
                    'signature_time': None,
                    'is_signed_today': False,
                    'signature_time_display': None,
                    'is_signed': False
                })

    else:
        # 普通操作员：只获取自己的记录
        all_today_records = ProductionRecord.query.filter(
            ProductionRecord.create_time >= start_of_day,
            ProductionRecord.create_time <= end_of_day
        ).order_by(ProductionRecord.create_time.desc()).all()

        # 精确过滤操作员记录
        today_records = []
        for record in all_today_records:
            # 将逗号分隔的操作员字符串转换为列表
            operators_list = [op.strip() for op in record.operators.split(',')]
            if operator_name in operators_list:
                today_records.append(record)

        # 计算今日统计
        total_today = sum(record.number for record in today_records)

        # 按工序统计
        process_stats = {}
        for record in today_records:
            if record.process not in process_stats:
                process_stats[record.process] = 0
            process_stats[record.process] += record.number

        # 普通操作员不需要组内信息
        group_members_with_signatures = []
        group_total = 0
        signed_members = []

    return render_template('operator_dashboard.html',
                         operator=operator,
                         operator_name=operator.operator_name,
                         today_records=today_records,
                         total_today=total_today,
                         process_stats=process_stats,
                         today=today,
                         is_group_owner=is_group_owner,
                         operator_group=operator.group_name,
                         group_members=group_members_with_signatures,
                         group_total=group_total,
                         signed_members=len(signed_members) if is_group_owner else 0)

# -------------------------- 操作员修改密码API --------------------------
@app.route('/operator/change_password', methods=['POST'])
@operator_login_required
def operator_change_password():
    """操作员修改密码（AJAX版本）"""
    operator_id = session.get('operator_id')
    operator = db.session.get(OperatorGroup, int(operator_id))

    if not operator:
        return jsonify({'success': False, 'message': '操作员不存在！'})

    old_password = request.form.get('old_password', '').strip()
    new_password = request.form.get('new_password', '').strip()
    confirm_password = request.form.get('confirm_password', '').strip()

    # 验证输入
    if not old_password or not new_password or not confirm_password:
        return jsonify({'success': False, 'message': '所有字段都必须填写！'})

    if new_password != confirm_password:
        return jsonify({'success': False, 'message': '新密码和确认密码不一致！'})

    if len(new_password) < 6:
        return jsonify({'success': False, 'message': '新密码长度至少6位！'})

    # 验证旧密码
    if not operator.check_password(old_password):
        return jsonify({'success': False, 'message': '旧密码错误！'})

    # 更新密码
    try:
        operator.set_password(new_password)
        db.session.commit()
        return jsonify({'success': True, 'message': '密码修改成功！'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'密码修改失败：{str(e)}'})

# -------------------------- 操作员重置密码API --------------------------
@app.route('/operator/<int:id>/reset_password', methods=['POST'])
@login_required
@permission_required('operator_management', 'update')
def reset_operator_password(id):
    """重置操作员密码（AJAX版本）"""
    operator = db.session.get(OperatorGroup, int(id))

    if not operator:
        return jsonify({'success': False, 'message': '操作员不存在！'})

    password = request.form.get('password', '').strip()

    if not password:
        password = '000000'  # 默认密码

    try:
        # 记录重置密码前的状态
        operator_data = {
            'operator_id': operator.id,
            'operator_name': operator.operator_name,
            'group_name': operator.group_name,
            'group_owner': operator.group_owner,
            'has_password_hash': bool(operator.password_hash)
        }

        operator.set_password(password)
        db.session.commit()

        # 记录重置密码日志
        log_activity(
            log_type='operator',
            action='reset_password',
            user_type='admin',
            user_id=current_user.id,
            username=current_user.username,
            target_id=operator.id,
            target_info=operator_data,
            request=request
        )

        return jsonify({'success': True, 'message': f'操作员 "{operator.operator_name}" 密码已重置！'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'密码重置失败：{str(e)}'})

# -------------------------- 组管理员功能 --------------------------
@app.route('/operator/<int:id>/grant_owner', methods=['POST'])
@login_required
@permission_required('operator_management', 'advanced')
def grant_group_owner(id):
    """授权操作员为组管理员"""
    password = request.form.get('password', '').strip()

    # 验证管理员密码
    if not current_user.check_password(password):
        return jsonify({'success': False, 'message': '管理员密码错误！'})

    operator = db.session.get(OperatorGroup, int(id))

    if not operator:
        return jsonify({'success': False, 'message': '操作员不存在！'})

    try:
        # 记录授权前的状态
        old_group_owners = OperatorGroup.query.filter_by(
            group_name=operator.group_name,
            group_owner=True
        ).all()

        old_owner_names = [op.operator_name for op in old_group_owners]

        # 移除同组的原组管理员
        OperatorGroup.query.filter_by(
            group_name=operator.group_name,
            group_owner=True
        ).update({'group_owner': False})

        # 设置新组管理员
        operator.group_owner = True
        db.session.commit()

        # 记录授权组管理员日志
        log_activity(
            log_type='operator',
            action='grant_owner',
            user_type='admin',
            user_id=current_user.id,
            username=current_user.username,
            target_id=operator.id,
            target_info={
                'operator_id': operator.id,
                'operator_name': operator.operator_name,
                'group_name': operator.group_name,
                'old_group_owners': old_owner_names,
                'new_group_owner': operator.operator_name
            },
            request=request
        )

        return jsonify({
            'success': True,
            'message': f'操作员 "{operator.operator_name}" 已被设为组管理员！'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'授权失败：{str(e)}'})

@app.route('/operator/<int:id>/revoke_owner', methods=['POST'])
@login_required
@permission_required('operator_management', 'advanced')
def revoke_group_owner(id):
    """移除组管理员权限"""
    password = request.form.get('password', '').strip()

    # 验证管理员密码
    if not current_user.check_password(password):
        return jsonify({'success': False, 'message': '管理员密码错误！'})

    operator = db.session.get(OperatorGroup, int(id))

    if not operator:
        return jsonify({'success': False, 'message': '操作员不存在！'})

    if not operator.group_owner:
        return jsonify({'success': False, 'message': f'操作员 "{operator.operator_name}" 不是组管理员！'})

    try:
        operator.group_owner = False
        db.session.commit()

        # 记录移除组管理员权限日志
        log_activity(
            log_type='operator',
            action='revoke_owner',
            user_type='admin',
            user_id=current_user.id,
            username=current_user.username,
            target_id=operator.id,
            target_info={
                'operator_id': operator.id,
                'operator_name': operator.operator_name,
                'group_name': operator.group_name
            },
            request=request
        )

        return jsonify({
            'success': True,
            'message': f'已移除操作员 "{operator.operator_name}" 的组管理员权限！'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'移除失败：{str(e)}'})

# -------------------------- 组管理员签字功能 --------------------------
@app.route('/operator/group/sign', methods=['POST'])
@operator_login_required
@group_owner_required
def sign_group_records():
    """组管理员签字确认组内记录"""
    operator_id = session.get('operator_id')
    operator = db.session.get(OperatorGroup, int(operator_id))

    if not operator or not operator.group_owner:
        return jsonify({'success': False, 'message': '无组管理员权限！'})

    signature_data = request.form.get('signature', '').strip()

    # 验证输入
    if not signature_data:
        return jsonify({'success': False, 'message': '请先绘制签名！'})

    try:
        # 1. 保存新的签名文件
        filename = save_signature_image(signature_data, operator.id)
        if not filename:
            return jsonify({'success': False, 'message': '保存签名文件失败！'})

        # 2. 更新数据库记录
        operator.signature_file = filename
        operator.signature_time = datetime.now()

        # 3. 冻结该组当天所有生产记录
        today = date.today()
        start_of_day = datetime.combine(today, datetime.min.time())
        end_of_day = datetime.combine(today, datetime.max.time())

        # 获取组内所有操作员
        group_members = OperatorGroup.query.filter_by(
            group_name=operator.group_name
        ).all()
        member_names = [member.operator_name for member in group_members]

        # 获取当天所有记录，然后过滤出包含组内操作员的记录
        all_today_records = ProductionRecord.query.filter(
            ProductionRecord.create_time >= start_of_day,
            ProductionRecord.create_time <= end_of_day
        ).all()

        # 冻结符合条件的记录
        freeze_count = 0
        for record in all_today_records:
            # 将逗号分隔的操作员字符串转换为列表
            operators_list = [op.strip() for op in record.operators.split(',')]
            # 检查是否有组内操作员参与此记录
            if any(op in member_names for op in operators_list):
                record.is_freeze = True
                freeze_count += 1

        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'签字确认成功！已冻结 {freeze_count} 条生产记录。您已代表全组成员确认今日生产记录。',
            'signature_url': url_for('serve_signature_file', filename=filename, _external=True),
            'signature_time': operator.signature_time.strftime('%Y-%m-%d %H:%M:%S'),
            'freeze_count': freeze_count
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"签字失败: {str(e)}")
        return jsonify({'success': False, 'message': f'签字失败：{str(e)}'})

@app.route('/operator/group/signature/clear', methods=['POST'])
@operator_login_required
@group_owner_required
def clear_signature():
    """清除组管理员签名"""
    operator_id = session.get('operator_id')
    operator = db.session.get(OperatorGroup, int(operator_id))

    if not operator or not operator.group_owner:
        return jsonify({'success': False, 'message': '无组管理员权限！'})

    try:
        # 只清空数据库记录，不删除文件
        operator.signature_file = None
        operator.signature_time = None

        db.session.commit()

        return jsonify({
            'success': True,
            'message': '签名记录已清除！'
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"清除签名失败: {str(e)}")
        return jsonify({'success': False, 'message': f'清除失败：{str(e)}'})

@app.route('/api/operator/<int:id>/signature')
@operator_login_required
def get_operator_signature(id):
    """获取操作员签名（组内成员可查看）"""
    # 检查权限：只能查看自己或同组成员的签名
    operator = db.session.get(OperatorGroup, int(id))
    operator_id = session.get('operator_id')
    current_operator = db.session.get(OperatorGroup, int(operator_id))

    if not current_operator:
        return jsonify({'success': False, 'message': '未登录！'})

    # 检查是否同组成员
    if current_operator.group_name != operator.group_name:
        return jsonify({'success': False, 'message': '无权限查看！'})

    if operator.signature_file:
        return jsonify({
            'success': True,
            'signature_url': operator.signature_url,
            'signature_time': operator.signature_time.strftime('%Y-%m-%d %H:%M:%S') if operator.signature_time else None,
            'operator_name': operator.operator_name
        })
    else:
        return jsonify({
            'success': False,
            'message': '该操作员暂无签名'
        })

@app.route('/api/operator/signatures')
@operator_login_required
def get_group_signatures():
    """获取组内成员的签名状态"""
    operator_id = session.get('operator_id')
    current_operator = db.session.get(OperatorGroup, int(operator_id))

    if not current_operator:
        return jsonify({'success': False, 'message': '操作员不存在！'})

    # 获取组内所有成员
    group_members = OperatorGroup.query.filter_by(
        group_name=current_operator.group_name
    ).order_by(OperatorGroup.operator_name).all()

    signatures = []
    for member in group_members:
        signatures.append({
            'operator_id': member.id,
            'operator_name': member.operator_name,
            'has_signature': bool(member.signature_file),
            'signature_time': member.signature_time.strftime('%Y-%m-%d %H:%M') if member.signature_time else None,
            'is_group_owner': member.group_owner
        })

    return jsonify({
        'success': True,
        'group_name': current_operator.group_name,
        'signatures': signatures,
        'total_members': len(signatures),
        'signed_count': len([m for m in signatures if m['has_signature']])
    })

# -------------------------- 日志管理 --------------------------
@app.route('/system/logs')
@login_required
@permission_required('system_management', 'read')
def system_logs():
    """系统日志管理页面"""
    return render_template('system_logs.html')

@app.route('/api/system/logs')
@login_required
@permission_required('system_management', 'read')
def get_system_logs():
    """获取系统日志（API）"""
    try:
        # 获取查询参数
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        log_type = request.args.get('log_type', 'all')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        username = request.args.get('username')

        # 构建查询
        query = ProductionLog.query

        # 日志类型筛选
        if log_type != 'all':
            query = query.filter(ProductionLog.log_type == log_type)

        # 用户筛选
        if username:
            query = query.filter(ProductionLog.username.contains(username))

        # 日期筛选
        if start_date:
            start_datetime = datetime.strptime(start_date, '%Y-%m-%d')
            query = query.filter(ProductionLog.created_at >= start_datetime)

        if end_date:
            end_datetime = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(ProductionLog.created_at < end_datetime)

        # 排序和分页
        logs = query.order_by(ProductionLog.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )

        # 格式化日志数据
        logs_data = []
        for log in logs.items:
            logs_data.append({
                'id': log.id,
                'log_type': log.log_type,
                'log_type_display': ProductionLog.get_log_type_display(log.log_type),
                'action': log.action,
                'action_display': ProductionLog.get_action_display(log.action),
                'user_type': log.user_type,
                'user_id': log.user_id,
                'username': log.username,
                'target_id': log.target_id,
                'target_info': log.get_target_info_dict(),
                'ip_address': log.ip_address,
                'user_agent': log.user_agent,
                'created_at': log.created_at.strftime('%Y-%m-%d %H:%M:%S')
            })

        return jsonify({
            'success': True,
            'logs': logs_data,
            'total': logs.total,
            'pages': logs.pages,
            'current_page': logs.page,
            'per_page': logs.per_page
        })

    except Exception as e:
        app.logger.error(f"获取系统日志失败: {str(e)}")
        return jsonify({'success': False, 'message': f'获取日志失败: {str(e)}'})

@app.route('/api/system/logs/clear', methods=['POST'])
@login_required
@permission_required('system_management', 'advanced')
def clear_system_logs():
    """清除所有系统日志（仅保留最近一周）"""
    try:
        # 只有超级管理员可以清除日志
        if not current_user.is_superuser:
            return jsonify({'success': False, 'message': '需要超级管理员权限'})

        # 计算一周前的日期
        one_week_ago = datetime.now() - timedelta(days=7)

        # 删除一周前的日志
        deleted_count = ProductionLog.query.filter(
            ProductionLog.created_at < one_week_ago
        ).delete()

        db.session.commit()

        # 记录清除日志操作
        log_activity(
            log_type='system',
            action='delete',
            user_type='admin',
            user_id=current_user.id,
            username=current_user.username,
            target_info={'deleted_count': deleted_count},
            request=request
        )

        return jsonify({
            'success': True,
            'message': f'已清除 {deleted_count} 条日志（保留最近一周的日志）'
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"清除日志失败: {str(e)}")
        return jsonify({'success': False, 'message': f'清除日志失败: {str(e)}'})

@app.route('/api/system/logs/stats')
@login_required
@permission_required('system_management', 'read')
def get_logs_stats():
    """获取日志统计信息"""
    try:
        # 总日志数
        total_logs = ProductionLog.query.count()

        # 按类型统计
        type_stats = {}
        for log_type in ProductionLog.LOG_TYPES.keys():
            count = ProductionLog.query.filter_by(log_type=log_type).count()
            type_stats[ProductionLog.get_log_type_display(log_type)] = count

        # 今日日志数
        today = date.today()
        today_logs = ProductionLog.query.filter(
            db.cast(ProductionLog.created_at, db.Date) == today
        ).count()

        # 最近一周日志趋势
        week_dates = []
        week_counts = []
        for i in range(6, -1, -1):
            day_date = today - timedelta(days=i)
            count = ProductionLog.query.filter(
                db.cast(ProductionLog.created_at, db.Date) == day_date
            ).count()
            week_dates.append(day_date.strftime('%m-%d'))
            week_counts.append(count)

        return jsonify({
            'success': True,
            'total_logs': total_logs,
            'today_logs': today_logs,
            'type_stats': type_stats,
            'week_dates': week_dates,
            'week_counts': week_counts
        })

    except Exception as e:
        app.logger.error(f"获取日志统计失败: {str(e)}")
        return jsonify({'success': False, 'message': f'获取统计失败: {str(e)}'})

# -------------------------- 静态文件路由 --------------------------
@app.route('/static/signatures/<filename>')
def serve_signature_file(filename):
    """提供签名文件的访问"""
    try:
        filepath = os.path.join(SIGNATURE_STORAGE_PATH, filename)
        app.logger.info(f"请求签名文件: {filename}, 路径: {filepath}, 是否存在: {os.path.exists(filepath)}")

        if not os.path.exists(filepath):
            app.logger.error(f"签名文件不存在: {filepath}")
            return "签名文件不存在", 404

        return send_file(filepath)
    except Exception as e:
        app.logger.error(f"提供签名文件失败: {str(e)}")
        return "签名文件访问错误", 500

# -------------------------- 启动应用 --------------------------
if __name__ == '__main__':
    # 初始化定时任务调度器
    app.scheduler = init_scheduler()

    # 确保应用退出时关闭调度器
    if app.scheduler:
        atexit.register(lambda: app.scheduler.shutdown())

    app.run(debug=DEBUG, host=HOST, port=PORT)
