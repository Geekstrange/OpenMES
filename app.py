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

# -------------------------- PostgreSQL配置 --------------------------
DB_USER = 'postgres'
DB_PASSWORD = '000000'
DB_HOST = 'localhost'
DB_PORT = '5432'
DB_NAME = 'openpms_db'

# -------------------------- 文件存储配置 --------------------------
SIGNATURE_STORAGE_PATH = 'static/signatures/'
BACKUP_STORAGE_PATH = 'backups/'
if not os.path.exists(SIGNATURE_STORAGE_PATH):
    os.makedirs(SIGNATURE_STORAGE_PATH, exist_ok=True)
if not os.path.exists(BACKUP_STORAGE_PATH):
    os.makedirs(BACKUP_STORAGE_PATH, exist_ok=True)

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
login_manager.login_message = '登录以继续访问页面'

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
    if current_user.is_authenticated:
        logout_user()
        flash('已安全退出登录', 'success')
    elif session.get('operator_logged_in'):
        session.clear()
        flash('操作员已退出登录', 'success')
    
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

        record.product_code = product_code
        record.process = process
        record.next_process = next_process if next_process else None
        record.number = int(number)
        record.operators = operator_str
        record.note = note if note else None
        record.update_time = datetime.now()

        try:
            db.session.commit()
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
        db.session.delete(record)
        db.session.commit()
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
    
    # 获取前端传递的组列表
    selected_groups = request.form.getlist('groups')
    
    try:
        # 更新工序的关联组
        process.linked_groups = json.dumps(selected_groups)
        process.update_time = datetime.now()
        
        db.session.commit()
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
    
    # 获取前端传递的下工序列表
    selected_next_processes = request.form.getlist('next_processes')
    
    try:
        # 更新工序的关联下工序
        process.linked_next_processes = json.dumps(selected_next_processes)
        process.update_time = datetime.now()
        
        db.session.commit()
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
    
    # 权限检查：高权限可以删除低权限，同级不能相互删除
    if not current_user.can_edit_user(user):
        flash('无权限删除该用户！', 'danger')
        return redirect(url_for('user_list'))
    
    try:
        db.session.delete(user)
        db.session.commit()
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
                else:
                    error_messages.append(f"操作员 '{name}' 在组 '{group_name}' 中已存在")
            except Exception as e:
                error_messages.append(f"操作员 '{name}' 添加失败: {str(e)}")

        try:
            if success_count > 0:
                db.session.commit()
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
        db.session.delete(operator)
        db.session.commit()
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
        # 删除整个组的操作员
        delete_count = OperatorGroup.query.filter_by(group_name=group_name).delete()
        db.session.commit()
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

# -------------------------- 数据库备份功能 --------------------------
@app.route('/system/backup', methods=['POST'])
@login_required
@permission_required('system_management', 'advanced')
def backup_database():
    """创建数据库备份"""
    try:
        # 只有超级管理员可以备份
        if not current_user.is_superuser:
            return jsonify({'success': False, 'message': '需要超级管理员权限'})
        
        data = request.get_json()
        include_timestamp = data.get('include_timestamp', True)
        compress = data.get('compress', True)
        
        # 生成备份文件名
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        db_name = DB_NAME
        
        if include_timestamp:
            filename = f"{db_name}_backup_{timestamp}.sql"
        else:
            filename = f"{db_name}_backup.sql"
        
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
            return jsonify({'success': False, 'message': f'备份失败: {result.stderr}'})
        
        # 如果需要压缩
        final_filename = filename
        download_path = f"/system/backup/download/{filename}"
        
        if compress:
            # 压缩文件
            compressed_filename = filename + '.gz'
            compressed_filepath = os.path.join(BACKUP_STORAGE_PATH, compressed_filename)
            
            with open(filepath, 'rb') as f_in:
                with gzip.open(compressed_filepath, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            # 删除未压缩的文件
            os.remove(filepath)
            
            final_filename = compressed_filename
            download_path = f"/system/backup/download/{compressed_filename}"
        
        app.logger.info(f"数据库备份成功: {final_filename}")
        return jsonify({
            'success': True,
            'message': '数据库备份成功',
            'filename': final_filename,
            'download_url': download_path,
            'timestamp': timestamp
        })
        
    except Exception as e:
        app.logger.error(f"备份过程中出错: {str(e)}")
        return jsonify({'success': False, 'message': f'备份失败: {str(e)}'})

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
        
        os.remove(filepath)
        app.logger.info(f"备份文件已删除: {filename}")
        
        return jsonify({
            'success': True,
            'message': '备份文件已删除'
        })
        
    except Exception as e:
        app.logger.error(f"删除备份文件失败: {str(e)}")
        return jsonify({'success': False, 'message': f'删除失败: {str(e)}'})

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
        
        if backup_dir.exists():
            backup_files = list(backup_dir.glob('*.sql')) + list(backup_dir.glob('*.gz')) + list(backup_dir.glob('*.zip'))
            backup_count = len(backup_files)
            
            for file in backup_files:
                total_backup_size += file.stat().st_size
            
            if backup_files:
                # 按修改时间排序，获取最新的备份
                latest_backup = max(backup_files, key=lambda f: f.stat().st_mtime)
                last_backup = datetime.fromtimestamp(latest_backup.stat().st_mtime).strftime('%Y-%m-%d %H:%M')
        
        return jsonify({
            'success': True,
            'database_size': db_size,
            'backup_count': backup_count,
            'total_backup_size': format_file_size(total_backup_size),
            'last_backup': last_backup
        })
        
    except Exception as e:
        app.logger.error(f"获取系统统计失败: {str(e)}")
        return jsonify({'success': False, 'message': f'获取统计失败: {str(e)}'})

def format_file_size(bytes):
    """格式化文件大小"""
    if bytes < 1024:
        return f"{bytes} B"
    elif bytes < 1024 * 1024:
        return f"{bytes / 1024:.1f} KB"
    elif bytes < 1024 * 1024 * 1024:
        return f"{bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{bytes / (1024 * 1024 * 1024):.2f} GB"

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
    
    password = request.form.get('password', '').strip()
    
    if not password:
        password = '000000'  # 默认密码
    
    try:
        operator.set_password(password)
        db.session.commit()
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
    
    try:
        # 移除同组的原组管理员
        OperatorGroup.query.filter_by(
            group_name=operator.group_name,
            group_owner=True
        ).update({'group_owner': False})
        
        # 设置新组管理员
        operator.group_owner = True
        db.session.commit()
        
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
    
    try:
        operator.group_owner = False
        db.session.commit()
        
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
    
    app.run(debug=True, host='0.0.0.0', port=80)