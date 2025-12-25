"""
AI BEE CC - Enterprise Multi-Tenant Call Center Platform
Ana Uygulama Dosyası
"""

import os
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
from werkzeug.security import generate_password_hash

from config import config
from models import (
    db, init_db, 
    # Core
    User, Tenant, TenantModule, TenantSettings, Project, ProjectUser,
    # Organization
    Role, Permission, RolePermission, UserRole, Department, Team, Skill, UserSkill,
    # Telephony
    SIPTrunk, DID, IVR, IVROption, Queue, QueueMember,
    # Campaign
    Campaign, DialList, Lead, LeadAttempt,
    # CRM
    Customer, CustomerNote, CustomField, Pipeline, PipelineStage, Ticket, TicketCategory,
    # Call
    Call, CallRecording, CallTranscript, DispositionSet, Disposition, Script,
    # QA
    QAForm, QACriteria, QAEvaluation,
    # AI
    AISettings, KnowledgeBase, KBDocument,
    # Integration
    Integration, Webhook, APIKey,
    # Audit
    AuditLog, SecurityEvent, SystemEvent,
    # Report
    Report, Dashboard, DashboardWidget,
    # Notification
    Notification
)

# Flask uygulaması oluştur
app = Flask(__name__)
app.config.from_object(config[os.getenv('FLASK_ENV', 'development')])

# Uzantıları başlat
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Bu sayfaya erişmek için giriş yapmalısınız.'
login_manager.login_message_category = 'warning'

# Veritabanını başlat
init_db(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ==================== DECORATORS ====================

def super_admin_required(f):
    """Süper admin yetkisi gerektirir"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_super_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Admin yetkisi gerektirir"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ['admin', 'super_admin']:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


def supervisor_required(f):
    """Supervisor yetkisi gerektirir"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ['admin', 'supervisor', 'super_admin']:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


def permission_required(permission_code):
    """Belirli bir yetki gerektirir"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if current_user.is_super_admin:
                return f(*args, **kwargs)
            if not current_user.has_permission(permission_code):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# ==================== TEMPLATE FİLTRELERİ ====================

@app.template_filter('datetime')
def format_datetime(value, format='%d.%m.%Y %H:%M'):
    if value is None:
        return ''
    return value.strftime(format)


@app.template_filter('duration')
def format_duration(seconds):
    if seconds is None:
        return '00:00'
    minutes, secs = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    if hours > 0:
        return f'{hours:02d}:{minutes:02d}:{secs:02d}'
    return f'{minutes:02d}:{secs:02d}'


@app.template_filter('phone')
def format_phone(number):
    if not number:
        return ''
    number = ''.join(filter(str.isdigit, str(number)))
    if len(number) == 10:
        return f'({number[:3]}) {number[3:6]} {number[6:8]} {number[8:]}'
    elif len(number) == 11 and number.startswith('0'):
        return f'({number[1:4]}) {number[4:7]} {number[7:9]} {number[9:]}'
    return number


# ==================== CONTEXT PROCESSOR ====================

@app.context_processor
def inject_globals():
    """Tüm template'lere global değişkenler ekle"""
    notifications = []
    if current_user.is_authenticated:
        notifications = Notification.query.filter_by(
            user_id=current_user.id, 
            is_read=False
        ).order_by(Notification.created_at.desc()).limit(10).all()
    
    return {
        'app_name': app.config.get('APP_NAME', 'AI BEE CC'),
        'version': app.config.get('VERSION', '2.0'),
        'current_year': datetime.now().year,
        'notifications': notifications
    }


# ==================== ERROR HANDLERS ====================

@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def server_error(e):
    return render_template('errors/500.html'), 500


# ==================== AUTH ROUTES ====================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            if not user.is_active:
                flash('Hesabınız pasif durumda. Yönetici ile iletişime geçin.', 'danger')
                return render_template('login.html')
            
            if user.is_locked:
                flash(f'Hesabınız kilitli: {user.lock_reason}', 'danger')
                return render_template('login.html')
            
            login_user(user)
            user.last_login = datetime.utcnow()
            user.current_ip = request.remote_addr
            user.failed_login_attempts = 0
            db.session.commit()
            
            # Audit log
            log_audit('login', 'user', user.id, 'Kullanıcı giriş yaptı')
            
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            # Başarısız giriş
            if user:
                user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
                user.last_failed_login = datetime.utcnow()
                
                # 5 başarısız denemeden sonra kilitle
                if user.failed_login_attempts >= 5:
                    user.is_locked = True
                    user.lock_reason = 'Çok fazla başarısız giriş denemesi'
                    
                    # Güvenlik olayı
                    event = SecurityEvent(
                        tenant_id=user.tenant_id,
                        user_id=user.id,
                        event_type='brute_force',
                        severity='critical',
                        description=f'Hesap kilitlendi: {user.failed_login_attempts} başarısız deneme',
                        ip_address=request.remote_addr
                    )
                    db.session.add(event)
                
                db.session.commit()
            
            flash('Geçersiz kullanıcı adı veya şifre.', 'danger')
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    log_audit('logout', 'user', current_user.id, 'Kullanıcı çıkış yaptı')
    current_user.status = 'offline'
    db.session.commit()
    logout_user()
    flash('Başarıyla çıkış yaptınız.', 'success')
    return redirect(url_for('login'))


# ==================== DASHBOARD ROUTES ====================

@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    """Ana dashboard - role göre yönlendir"""
    if current_user.is_super_admin:
        return render_template('dashboard/super_admin.html')
    elif current_user.role == 'admin':
        return render_template('dashboard/admin.html')
    elif current_user.role == 'supervisor':
        return render_template('dashboard/supervisor.html')
    elif current_user.role == 'qa':
        return render_template('dashboard/qa.html')
    elif current_user.role == 'client':
        return render_template('dashboard/client.html')
    else:  # agent
        # Agent için bugünkü istatistikler
        today = datetime.now().replace(hour=0, minute=0, second=0)
        today_calls = Call.query.filter(
            Call.agent_id == current_user.id,
            Call.started_at >= today
        ).all()
        
        today_stats = {
            'calls': len(today_calls),
            'sales': sum(1 for c in today_calls if c.disposition == 'sale_ok'),
            'callbacks': Lead.query.filter_by(
                assigned_agent_id=current_user.id, 
                status='callback'
            ).count(),
            'avg_duration': '{}:{:02d}'.format(
                int(sum(c.talk_duration or 0 for c in today_calls) / max(len(today_calls), 1) // 60),
                int(sum(c.talk_duration or 0 for c in today_calls) / max(len(today_calls), 1) % 60)
            )
        }
        
        # Bugünkü geri aramalar
        callbacks = Lead.query.filter(
            Lead.assigned_agent_id == current_user.id,
            Lead.status == 'callback',
            Lead.callback_at >= today
        ).order_by(Lead.callback_at.asc()).limit(10).all()
        
        return render_template('dashboard/agent.html', 
                              today_stats=today_stats,
                              callbacks=callbacks)


# ==================== SUPER ADMIN ROUTES ====================

@app.route('/platform')
@login_required
@super_admin_required
def platform_dashboard():
    """Platform yönetim dashboard'u"""
    tenants = Tenant.query.all()
    stats = {
        'total_tenants': Tenant.query.count(),
        'active_tenants': Tenant.query.filter_by(status='active').count(),
        'total_users': User.query.count(),
        'total_calls_today': Call.query.filter(
            Call.started_at >= datetime.now().replace(hour=0, minute=0, second=0)
        ).count()
    }
    return render_template('platform/dashboard.html', tenants=tenants, stats=stats)


@app.route('/platform/tenants')
@login_required
@super_admin_required
def platform_tenants():
    """Tenant (CC) listesi"""
    tenants = Tenant.query.order_by(Tenant.created_at.desc()).all()
    return render_template('platform/tenants.html', tenants=tenants)


@app.route('/platform/tenants/new', methods=['GET', 'POST'])
@login_required
@super_admin_required
def platform_tenant_new():
    """Yeni tenant oluştur"""
    if request.method == 'POST':
        tenant = Tenant(
            code=request.form.get('code'),
            name=request.form.get('name'),
            domain=request.form.get('domain'),
            timezone=request.form.get('timezone', 'Europe/Istanbul'),
            language=request.form.get('language', 'tr'),
            max_agents=int(request.form.get('max_agents', 10)),
            max_concurrent_calls=int(request.form.get('max_concurrent_calls', 20)),
            status='active'
        )
        db.session.add(tenant)
        db.session.commit()
        
        # Varsayılan ayarları oluştur
        settings = TenantSettings(tenant_id=tenant.id)
        db.session.add(settings)
        
        # Admin kullanıcı oluştur
        admin_user = User(
            tenant_id=tenant.id,
            username=f"{tenant.code}_admin",
            email=request.form.get('admin_email'),
            full_name='Sistem Yöneticisi',
            role='admin',
            is_active=True
        )
        admin_user.set_password(request.form.get('admin_password', 'Admin123!'))
        db.session.add(admin_user)
        db.session.commit()
        
        log_audit('create', 'tenant', tenant.id, f'Yeni tenant oluşturuldu: {tenant.name}')
        flash(f'"{tenant.name}" başarıyla oluşturuldu.', 'success')
        return redirect(url_for('platform_tenants'))
    
    return render_template('platform/tenant_form.html', tenant=None)


@app.route('/platform/tenants/<int:id>')
@login_required
@super_admin_required
def platform_tenant_detail(id):
    """Tenant detayı"""
    tenant = Tenant.query.get_or_404(id)
    return render_template('platform/tenant_detail.html', tenant=tenant)


@app.route('/platform/tenants/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@super_admin_required
def platform_tenant_edit(id):
    """Tenant düzenle"""
    tenant = Tenant.query.get_or_404(id)
    
    if request.method == 'POST':
        tenant.name = request.form.get('name')
        tenant.domain = request.form.get('domain')
        tenant.timezone = request.form.get('timezone')
        tenant.max_agents = int(request.form.get('max_agents', 10))
        tenant.max_concurrent_calls = int(request.form.get('max_concurrent_calls', 20))
        tenant.status = request.form.get('status')
        db.session.commit()
        
        log_audit('update', 'tenant', tenant.id, f'Tenant güncellendi: {tenant.name}')
        flash('Tenant başarıyla güncellendi.', 'success')
        return redirect(url_for('platform_tenant_detail', id=tenant.id))
    
    return render_template('platform/tenant_form.html', tenant=tenant)


@app.route('/platform/tenants/<int:id>/modules', methods=['GET', 'POST'])
@login_required
@super_admin_required
def platform_tenant_modules(id):
    """Tenant modül yönetimi"""
    tenant = Tenant.query.get_or_404(id)
    
    if request.method == 'POST':
        # Modülleri güncelle
        modules = ['crm', 'dialer', 'ai', 'omnichannel', 'wfm', 'qa', 'reporting']
        for module in modules:
            is_enabled = request.form.get(f'module_{module}') == 'on'
            existing = TenantModule.query.filter_by(tenant_id=tenant.id, module_name=module).first()
            
            if existing:
                existing.is_enabled = is_enabled
            else:
                new_module = TenantModule(
                    tenant_id=tenant.id,
                    module_name=module,
                    is_enabled=is_enabled
                )
                db.session.add(new_module)
        
        db.session.commit()
        flash('Modüller güncellendi.', 'success')
    
    return render_template('platform/tenant_modules.html', tenant=tenant)


@app.route('/platform/projects')
@login_required
@super_admin_required
def platform_projects():
    """Tüm projeler"""
    projects = Project.query.order_by(Project.created_at.desc()).all()
    return render_template('platform/projects.html', projects=projects)


@app.route('/platform/health')
@login_required
@super_admin_required
def platform_health():
    """Sistem sağlığı"""
    # Sistem metrikleri (gerçek implementasyonda psutil vb. kullanılır)
    health = {
        'cpu_usage': 45,
        'memory_usage': 62,
        'disk_usage': 38,
        'active_calls': Call.query.filter_by(status='answered').count(),
        'trunk_status': 'healthy',
        'db_status': 'healthy'
    }
    recent_events = SystemEvent.query.order_by(SystemEvent.created_at.desc()).limit(20).all()
    return render_template('platform/health.html', health=health, events=recent_events)


@app.route('/platform/audit')
@login_required
@super_admin_required
def platform_audit():
    """Audit logları"""
    page = request.args.get('page', 1, type=int)
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).paginate(page=page, per_page=50)
    return render_template('platform/audit.html', logs=logs)


# ==================== ADMIN ROUTES ====================

@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    """Admin paneli"""
    stats = get_tenant_stats()
    return render_template('admin/index.html', stats=stats)


@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    """Kullanıcı yönetimi"""
    users = User.query.filter_by(tenant_id=current_user.tenant_id).order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)


@app.route('/admin/users/new', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_user_new():
    """Yeni kullanıcı oluştur"""
    if request.method == 'POST':
        user = User(
            tenant_id=current_user.tenant_id,
            username=request.form.get('username'),
            email=request.form.get('email'),
            first_name=request.form.get('first_name'),
            last_name=request.form.get('last_name'),
            full_name=f"{request.form.get('first_name')} {request.form.get('last_name')}",
            role=request.form.get('role'),
            extension=request.form.get('extension'),
            department_id=request.form.get('department_id') or None,
            team_id=request.form.get('team_id') or None,
            is_active=True
        )
        user.set_password(request.form.get('password'))
        db.session.add(user)
        db.session.commit()
        
        log_audit('create', 'user', user.id, f'Yeni kullanıcı oluşturuldu: {user.username}')
        flash(f'"{user.full_name}" başarıyla oluşturuldu.', 'success')
        return redirect(url_for('admin_users'))
    
    departments = Department.query.filter_by(tenant_id=current_user.tenant_id, is_active=True).all()
    teams = Team.query.filter_by(tenant_id=current_user.tenant_id, is_active=True).all()
    return render_template('admin/user_form.html', user=None, departments=departments, teams=teams)


@app.route('/admin/users/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_user_edit(id):
    """Kullanıcı düzenle"""
    user = User.query.get_or_404(id)
    
    if user.tenant_id != current_user.tenant_id and not current_user.is_super_admin:
        abort(403)
    
    if request.method == 'POST':
        user.email = request.form.get('email')
        user.first_name = request.form.get('first_name')
        user.last_name = request.form.get('last_name')
        user.full_name = f"{request.form.get('first_name')} {request.form.get('last_name')}"
        user.role = request.form.get('role')
        user.extension = request.form.get('extension')
        user.department_id = request.form.get('department_id') or None
        user.team_id = request.form.get('team_id') or None
        user.is_active = request.form.get('is_active') == 'on'
        
        if request.form.get('password'):
            user.set_password(request.form.get('password'))
        
        db.session.commit()
        log_audit('update', 'user', user.id, f'Kullanıcı güncellendi: {user.username}')
        flash('Kullanıcı başarıyla güncellendi.', 'success')
        return redirect(url_for('admin_users'))
    
    departments = Department.query.filter_by(tenant_id=current_user.tenant_id, is_active=True).all()
    teams = Team.query.filter_by(tenant_id=current_user.tenant_id, is_active=True).all()
    return render_template('admin/user_form.html', user=user, departments=departments, teams=teams)


@app.route('/admin/roles')
@login_required
@admin_required
def admin_roles():
    """Rol yönetimi"""
    roles = Role.query.filter(
        (Role.tenant_id == current_user.tenant_id) | (Role.tenant_id == None)
    ).all()
    return render_template('admin/roles.html', roles=roles)


@app.route('/admin/departments')
@login_required
@admin_required
def admin_departments():
    """Departman yönetimi"""
    departments = Department.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('admin/departments.html', departments=departments)


@app.route('/admin/teams')
@login_required
@admin_required
def admin_teams():
    """Takım yönetimi"""
    teams = Team.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('admin/teams.html', teams=teams)


@app.route('/admin/skills')
@login_required
@admin_required
def admin_skills():
    """Beceri yönetimi"""
    skills = Skill.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('admin/skills.html', skills=skills)


@app.route('/admin/settings')
@login_required
@admin_required
def admin_settings():
    """Sistem ayarları"""
    settings = TenantSettings.query.filter_by(tenant_id=current_user.tenant_id).first()
    return render_template('admin/settings.html', settings=settings)


# ==================== PROJECT ROUTES ====================

@app.route('/projects')
@login_required
@admin_required
def projects():
    """Proje listesi"""
    projects = Project.query.filter_by(tenant_id=current_user.tenant_id).order_by(Project.created_at.desc()).all()
    return render_template('projects/list.html', projects=projects)


@app.route('/projects/new', methods=['GET', 'POST'])
@login_required
@admin_required
def project_new():
    """Yeni proje oluştur"""
    if request.method == 'POST':
        project = Project(
            tenant_id=current_user.tenant_id,
            code=request.form.get('code'),
            name=request.form.get('name'),
            description=request.form.get('description'),
            sector=request.form.get('sector'),
            campaign_type=request.form.get('campaign_type'),
            status='active'
        )
        db.session.add(project)
        db.session.commit()
        
        log_audit('create', 'project', project.id, f'Yeni proje oluşturuldu: {project.name}')
        flash(f'"{project.name}" projesi başarıyla oluşturuldu.', 'success')
        return redirect(url_for('projects'))
    
    return render_template('projects/form.html', project=None)


@app.route('/projects/<int:id>')
@login_required
def project_detail(id):
    """Proje detayı"""
    project = Project.query.get_or_404(id)
    return render_template('projects/detail.html', project=project)


# ==================== TELEPHONY ROUTES ====================

@app.route('/telephony/trunks')
@login_required
@admin_required
def telephony_trunks():
    """SIP Trunk yönetimi"""
    trunks = SIPTrunk.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('telephony/trunks.html', trunks=trunks)


@app.route('/telephony/dids')
@login_required
@admin_required
def telephony_dids():
    """DID yönetimi"""
    dids = DID.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('telephony/dids.html', dids=dids)


@app.route('/telephony/ivrs')
@login_required
@admin_required
def telephony_ivrs():
    """IVR yönetimi"""
    ivrs = IVR.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('telephony/ivrs.html', ivrs=ivrs)


@app.route('/queues')
@login_required
def queues():
    """Kuyruk yönetimi"""
    queues = Queue.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('queues/list.html', queues=queues)


# ==================== CAMPAIGN ROUTES ====================

@app.route('/campaigns')
@login_required
def campaigns():
    """Kampanya listesi"""
    campaigns = Campaign.query.filter_by(tenant_id=current_user.tenant_id).order_by(Campaign.created_at.desc()).all()
    return render_template('campaigns/list.html', campaigns=campaigns)


@app.route('/campaigns/new', methods=['GET', 'POST'])
@login_required
@admin_required
def campaign_new():
    """Yeni kampanya"""
    if request.method == 'POST':
        campaign = Campaign(
            tenant_id=current_user.tenant_id,
            project_id=request.form.get('project_id'),
            name=request.form.get('name'),
            description=request.form.get('description'),
            dialer_type=request.form.get('dialer_type'),
            status='draft'
        )
        db.session.add(campaign)
        db.session.commit()
        
        log_audit('create', 'campaign', campaign.id, f'Yeni kampanya oluşturuldu: {campaign.name}')
        flash(f'"{campaign.name}" kampanyası başarıyla oluşturuldu.', 'success')
        return redirect(url_for('campaigns'))
    
    projects = Project.query.filter_by(tenant_id=current_user.tenant_id, status='active').all()
    queues = Queue.query.filter_by(tenant_id=current_user.tenant_id, status='active').all()
    return render_template('campaigns/form.html', campaign=None, projects=projects, queues=queues)


@app.route('/campaigns/<int:id>')
@login_required
def campaign_detail(id):
    """Kampanya detayı"""
    campaign = Campaign.query.get_or_404(id)
    return render_template('campaigns/detail.html', campaign=campaign)


@app.route('/dialer/lists')
@login_required
@admin_required
def dialer_lists():
    """Arama listeleri"""
    lists = DialList.query.filter_by(tenant_id=current_user.tenant_id).order_by(DialList.created_at.desc()).all()
    return render_template('dialer/lists.html', lists=lists)


# ==================== CRM ROUTES ====================

@app.route('/customers')
@login_required
def customers():
    """Müşteri listesi"""
    page = request.args.get('page', 1, type=int)
    query = Customer.query.filter_by(tenant_id=current_user.tenant_id)
    
    # Filtreler
    search = request.args.get('search')
    status = request.args.get('status')
    
    if search:
        query = query.filter(
            (Customer.full_name.ilike(f'%{search}%')) |
            (Customer.phone.ilike(f'%{search}%')) |
            (Customer.email.ilike(f'%{search}%'))
        )
    
    if status:
        query = query.filter_by(status=status)
    
    customers = query.order_by(Customer.created_at.desc()).paginate(page=page, per_page=25)
    return render_template('crm/customers.html', customers=customers)


@app.route('/customers/new', methods=['GET', 'POST'])
@login_required
def customer_new():
    """Yeni müşteri"""
    if request.method == 'POST':
        customer = Customer(
            tenant_id=current_user.tenant_id,
            type=request.form.get('type', 'individual'),
            first_name=request.form.get('first_name'),
            last_name=request.form.get('last_name'),
            full_name=f"{request.form.get('first_name')} {request.form.get('last_name')}",
            phone=request.form.get('phone'),
            email=request.form.get('email'),
            company_name=request.form.get('company_name'),
            status='lead'
        )
        db.session.add(customer)
        db.session.commit()
        
        log_audit('create', 'customer', customer.id, f'Yeni müşteri oluşturuldu: {customer.full_name}')
        flash('Müşteri başarıyla oluşturuldu.', 'success')
        return redirect(url_for('customers'))
    
    return render_template('crm/customer_form.html', customer=None)


@app.route('/customers/<int:id>')
@login_required
def customer_detail(id):
    """Müşteri detayı"""
    customer = Customer.query.get_or_404(id)
    return render_template('crm/customer_detail.html', customer=customer)


@app.route('/tickets')
@login_required
def tickets():
    """Destek talepleri"""
    tickets = Ticket.query.filter_by(tenant_id=current_user.tenant_id).order_by(Ticket.created_at.desc()).all()
    return render_template('crm/tickets.html', tickets=tickets)


@app.route('/pipelines')
@login_required
@admin_required
def pipelines():
    """Pipeline yönetimi"""
    pipelines = Pipeline.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('crm/pipelines.html', pipelines=pipelines)


# ==================== CALL ROUTES ====================

@app.route('/calls')
@login_required
def calls():
    """Çağrı listesi"""
    page = request.args.get('page', 1, type=int)
    query = Call.query.filter_by(tenant_id=current_user.tenant_id)
    
    # Filtreler
    direction = request.args.get('direction')
    agent_id = request.args.get('agent_id')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    
    if direction:
        query = query.filter_by(direction=direction)
    if agent_id:
        query = query.filter_by(agent_id=agent_id)
    
    calls = query.order_by(Call.started_at.desc()).paginate(page=page, per_page=25)
    agents = User.query.filter_by(tenant_id=current_user.tenant_id, role='agent').all()
    
    return render_template('calls/list.html', calls=calls, agents=agents)


@app.route('/calls/<int:id>')
@login_required
def call_detail(id):
    """Çağrı detayı"""
    call = Call.query.get_or_404(id)
    return render_template('calls/detail.html', call=call)


# ==================== AGENT PANEL ROUTES ====================

@app.route('/agent')
@login_required
def agent_panel():
    """Agent paneli - Kampanya seçimi veya ana panel"""
    # Session'da aktif kampanya var mı kontrol et
    active_campaign_id = request.cookies.get('active_campaign_id')
    
    if not active_campaign_id:
        # Kampanya seçim sayfasına yönlendir
        return redirect(url_for('agent_campaign_select'))
    
    # Aktif kampanyayı al
    campaign = Campaign.query.get(active_campaign_id)
    if not campaign:
        return redirect(url_for('agent_campaign_select'))
    
    # Agent'ın kuyrukları
    queue_memberships = QueueMember.query.filter_by(user_id=current_user.id).all()
    queues = [qm.queue for qm in queue_memberships]
    
    # Bugünkü çağrılar
    today_calls = Call.query.filter(
        Call.agent_id == current_user.id,
        Call.started_at >= datetime.now().replace(hour=0, minute=0, second=0)
    ).all()
    
    # İstatistikler
    stats = {
        'total_calls': len(today_calls),
        'qc_ok': sum(1 for c in today_calls if c.qa_status == 'passed'),
        'cancelled_sales': sum(1 for c in today_calls if c.disposition == 'sale_cancelled'),
        'total_pause_time': current_user.total_pause_time or 0,
        'callbacks': Lead.query.filter_by(assigned_agent_id=current_user.id, status='callback').count(),
        'total_sales': sum(1 for c in today_calls if c.disposition == 'sale_ok'),
    }
    
    # Bekleyen lead'ler
    leads = Lead.query.filter_by(
        assigned_agent_id=current_user.id, 
        status='new'
    ).limit(10).all()
    
    # Disposition setleri
    disposition_sets = DispositionSet.query.filter_by(
        tenant_id=current_user.tenant_id,
        is_active=True
    ).all()
    
    # Scriptler
    scripts = Script.query.filter(
        (Script.tenant_id == current_user.tenant_id) | (Script.is_global == True),
        Script.is_active == True
    ).all()
    
    return render_template('agent/panel.html', 
                          campaign=campaign,
                          queues=queues, 
                          today_calls=today_calls, 
                          leads=leads,
                          stats=stats,
                          disposition_sets=disposition_sets,
                          scripts=scripts)


@app.route('/agent/select-campaign')
@login_required
def agent_campaign_select():
    """Agent kampanya seçim sayfası"""
    # Super admin ise tüm aktif kampanyaları göster
    if current_user.is_super_admin:
        campaigns = Campaign.query.filter(Campaign.status == 'active').all()
    else:
        # Normal kullanıcılar sadece kendi tenant'ının kampanyalarını görür
        campaigns = Campaign.query.filter(
            Campaign.tenant_id == current_user.tenant_id,
            Campaign.status == 'active'
        ).all()
    
    return render_template('agent/login.html', campaigns=campaigns)


@app.route('/agent/enter-campaign', methods=['POST'])
@login_required
def agent_enter_campaign():
    """Agent kampanyaya giriş"""
    campaign_id = request.form.get('campaign_id')
    
    if not campaign_id:
        flash('Lütfen bir kampanya seçin.', 'warning')
        return redirect(url_for('agent_campaign_select'))
    
    campaign = Campaign.query.get(campaign_id)
    if not campaign:
        flash('Geçersiz kampanya.', 'danger')
        return redirect(url_for('agent_campaign_select'))
    
    # Super admin tüm kampanyalara erişebilir, diğerleri sadece kendi tenant'ına
    if not current_user.is_super_admin and campaign.tenant_id != current_user.tenant_id:
        flash('Bu kampanyaya erişim yetkiniz yok.', 'danger')
        return redirect(url_for('agent_campaign_select'))
    
    # Agent durumunu güncelle
    current_user.status = 'available'
    current_user.current_campaign_id = campaign.id
    db.session.commit()
    
    # Audit log
    log_audit('agent_login', 'campaign', campaign.id, 
              f'Agent kampanyaya giriş yaptı: {campaign.name}')
    
    # WebSocket ile bildir
    socketio.emit('agent_logged_in', {
        'agent_id': current_user.id,
        'agent_name': current_user.full_name,
        'campaign_id': campaign.id
    }, room=f'tenant_{current_user.tenant_id}')
    
    response = redirect(url_for('agent_panel'))
    response.set_cookie('active_campaign_id', str(campaign_id), max_age=86400)  # 24 saat
    
    flash(f'{campaign.name} kampanyasına başarıyla giriş yaptınız.', 'success')
    return response


@app.route('/agent/leave-campaign', methods=['POST'])
@login_required
def agent_leave_campaign():
    """Agent kampanyadan çıkış"""
    campaign_id = request.cookies.get('active_campaign_id')
    
    # Agent durumunu güncelle
    current_user.status = 'offline'
    current_user.current_campaign_id = None
    db.session.commit()
    
    # Audit log
    if campaign_id:
        log_audit('agent_logout', 'campaign', campaign_id, 'Agent kampanyadan çıkış yaptı')
    
    # WebSocket ile bildir
    socketio.emit('agent_logged_out', {
        'agent_id': current_user.id,
    }, room=f'tenant_{current_user.tenant_id}')
    
    response = redirect(url_for('agent_campaign_select'))
    response.delete_cookie('active_campaign_id')
    
    flash('Kampanyadan başarıyla çıkış yaptınız.', 'success')
    return response


@app.route('/agent/test-headset')
@login_required
def agent_test_headset():
    """Kulaklık ve mikrofon test sayfası"""
    return render_template('agent/test_headset.html')


@app.route('/agent/status', methods=['POST'])
@login_required
def agent_status_update():
    """Agent durum güncelleme"""
    data = request.get_json() if request.is_json else request.form
    status = data.get('status')
    pause_type = data.get('pause_type')
    
    # Mola başlangıcı
    if status == 'pause' and current_user.status != 'pause':
        current_user.pause_started_at = datetime.utcnow()
        current_user.pause_type = pause_type
    # Mola bitişi
    elif status != 'pause' and current_user.status == 'pause':
        if current_user.pause_started_at:
            pause_duration = (datetime.utcnow() - current_user.pause_started_at).total_seconds()
            current_user.total_pause_time = (current_user.total_pause_time or 0) + pause_duration
        current_user.pause_started_at = None
        current_user.pause_type = None
    
    current_user.status = status
    db.session.commit()
    
    # WebSocket ile broadcast
    socketio.emit('agent_status_changed', {
        'agent_id': current_user.id,
        'agent_name': current_user.full_name,
        'status': status,
        'pause_type': pause_type
    }, room=f'tenant_{current_user.tenant_id}')
    
    return jsonify({'success': True, 'status': status})


@app.route('/agent/disposition', methods=['POST'])
@login_required
def agent_save_disposition():
    """Çağrı sonucu (disposition) kaydet"""
    data = request.get_json() if request.is_json else request.form
    call_id = data.get('call_id')
    disposition_code = data.get('disposition')
    note = data.get('note', '')
    
    call = Call.query.get(call_id)
    if not call or call.agent_id != current_user.id:
        return jsonify({'success': False, 'error': 'Geçersiz çağrı'}), 400
    
    call.disposition = disposition_code
    call.agent_note = note
    call.disposed_at = datetime.utcnow()
    db.session.commit()
    
    # Belirli disposition'lara göre lead güncelle
    if call.lead_id:
        lead = Lead.query.get(call.lead_id)
        if lead:
            if disposition_code == 'sale_ok':
                lead.status = 'converted'
            elif disposition_code == 'callback':
                lead.status = 'callback'
            elif disposition_code in ['no_interest', 'blacklist', 'wrong_number']:
                lead.status = 'closed'
            db.session.commit()
    
    return jsonify({'success': True})


@app.route('/agent/callback', methods=['POST'])
@login_required
def agent_save_callback():
    """Geri arama kaydet"""
    data = request.get_json() if request.is_json else request.form
    call_id = data.get('call_id')
    callback_date = data.get('callback_date')
    callback_time = data.get('callback_time')
    note = data.get('note', '')
    priority = data.get('priority', 'normal')
    
    call = Call.query.get(call_id)
    if not call:
        return jsonify({'success': False, 'error': 'Geçersiz çağrı'}), 400
    
    # Lead'i güncelle veya oluştur
    if call.lead_id:
        lead = Lead.query.get(call.lead_id)
        lead.status = 'callback'
        lead.callback_at = datetime.strptime(f'{callback_date} {callback_time}', '%Y-%m-%d %H:%M')
        lead.callback_note = note
        lead.priority = priority
        db.session.commit()
    
    return jsonify({'success': True})


@app.route('/api/agent/stats')
@login_required
def agent_get_stats():
    """Agent istatistiklerini getir (AJAX)"""
    today = datetime.now().replace(hour=0, minute=0, second=0)
    
    today_calls = Call.query.filter(
        Call.agent_id == current_user.id,
        Call.started_at >= today
    ).all()
    
    stats = {
        'total_calls': len(today_calls),
        'qc_ok': sum(1 for c in today_calls if c.qa_status == 'passed'),
        'cancelled_sales': sum(1 for c in today_calls if c.disposition == 'sale_cancelled'),
        'total_sales': sum(1 for c in today_calls if c.disposition == 'sale_ok'),
        'callbacks': Lead.query.filter_by(assigned_agent_id=current_user.id, status='callback').count(),
        'total_pause_time': current_user.total_pause_time or 0,
        'avg_call_duration': sum(c.talk_duration or 0 for c in today_calls) / max(len(today_calls), 1)
    }
    
    return jsonify(stats)


# ==================== SUPERVISOR PANEL ROUTES ====================

@app.route('/supervisor')
@login_required
@supervisor_required
def supervisor_panel():
    """Supervisor paneli"""
    # Takım üyeleri
    team_agents = User.query.filter_by(
        tenant_id=current_user.tenant_id,
        team_id=current_user.team_id,
        role='agent'
    ).all() if current_user.team_id else []
    
    # Aktif çağrılar
    active_calls = Call.query.filter(
        Call.tenant_id == current_user.tenant_id,
        Call.status.in_(['ringing', 'answered', 'on_hold'])
    ).all()
    
    # Kuyruk durumu
    queues = Queue.query.filter_by(tenant_id=current_user.tenant_id, status='active').all()
    
    return render_template('supervisor/panel.html', 
                          team_agents=team_agents, 
                          active_calls=active_calls,
                          queues=queues)


@app.route('/supervisor/coaching')
@login_required
@supervisor_required
def supervisor_coaching():
    """Koçluk ekranı"""
    agents = User.query.filter_by(tenant_id=current_user.tenant_id, role='agent').all()
    return render_template('supervisor/coaching.html', agents=agents)


# ==================== QA PANEL ROUTES ====================

@app.route('/qa')
@login_required
def qa_dashboard():
    """QA dashboard'u"""
    # Son değerlendirmeler
    recent_evaluations = QAEvaluation.query.filter_by(
        tenant_id=current_user.tenant_id
    ).order_by(QAEvaluation.evaluated_at.desc()).limit(20).all()
    
    # Değerlendirilmemiş çağrılar
    unevaluated_calls = Call.query.filter(
        Call.tenant_id == current_user.tenant_id,
        Call.talk_duration >= 60,  # En az 1 dakika konuşma
        ~Call.qa_evaluations.any()
    ).order_by(Call.started_at.desc()).limit(20).all()
    
    return render_template('qa/dashboard.html', 
                          recent_evaluations=recent_evaluations,
                          unevaluated_calls=unevaluated_calls)


@app.route('/qa/forms')
@login_required
@admin_required
def qa_forms():
    """QA form yönetimi"""
    forms = QAForm.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('qa/forms.html', forms=forms)


@app.route('/qa/evaluate/<int:call_id>', methods=['GET', 'POST'])
@login_required
def qa_evaluate(call_id):
    """Çağrı değerlendir"""
    call = Call.query.get_or_404(call_id)
    forms = QAForm.query.filter_by(tenant_id=current_user.tenant_id, is_active=True).all()
    
    if request.method == 'POST':
        form_id = request.form.get('form_id')
        scores = {}
        total_score = 0
        max_score = 0
        
        # Kriter puanlarını topla
        for key, value in request.form.items():
            if key.startswith('criteria_'):
                criteria_id = int(key.replace('criteria_', ''))
                score = int(value)
                scores[criteria_id] = {
                    'score': score,
                    'comment': request.form.get(f'comment_{criteria_id}', '')
                }
                criteria = QACriteria.query.get(criteria_id)
                total_score += score
                max_score += criteria.max_points
        
        percentage = (total_score / max_score * 100) if max_score > 0 else 0
        
        evaluation = QAEvaluation(
            tenant_id=current_user.tenant_id,
            call_id=call_id,
            form_id=form_id,
            agent_id=call.agent_id,
            evaluator_id=current_user.id,
            total_score=total_score,
            max_possible_score=max_score,
            percentage=percentage,
            scores=scores,
            passed=percentage >= 70,
            feedback=request.form.get('feedback')
        )
        db.session.add(evaluation)
        
        # Çağrıya QA skoru ekle
        call.qa_score = percentage
        db.session.commit()
        
        flash('Değerlendirme kaydedildi.', 'success')
        return redirect(url_for('qa_dashboard'))
    
    return render_template('qa/evaluate.html', call=call, forms=forms)


# ==================== AI PANEL ROUTES ====================

@app.route('/ai')
@login_required
@admin_required
def ai_panel():
    """AI yönetim paneli"""
    settings = AISettings.query.filter_by(tenant_id=current_user.tenant_id).first()
    knowledge_bases = KnowledgeBase.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('ai/panel.html', settings=settings, knowledge_bases=knowledge_bases)


@app.route('/ai/settings', methods=['GET', 'POST'])
@login_required
@admin_required
def ai_settings():
    """AI ayarları"""
    settings = AISettings.query.filter_by(tenant_id=current_user.tenant_id).first()
    
    if not settings:
        settings = AISettings(tenant_id=current_user.tenant_id)
        db.session.add(settings)
        db.session.commit()
    
    if request.method == 'POST':
        settings.stt_provider = request.form.get('stt_provider')
        settings.stt_model = request.form.get('stt_model')
        settings.auto_summary_enabled = request.form.get('auto_summary_enabled') == 'on'
        settings.sentiment_analysis_enabled = request.form.get('sentiment_analysis_enabled') == 'on'
        settings.auto_qa_enabled = request.form.get('auto_qa_enabled') == 'on'
        settings.agent_assist_enabled = request.form.get('agent_assist_enabled') == 'on'
        db.session.commit()
        flash('AI ayarları güncellendi.', 'success')
    
    return render_template('ai/settings.html', settings=settings)


@app.route('/ai/knowledge-base')
@login_required
@admin_required
def ai_knowledge_base():
    """Bilgi tabanı yönetimi"""
    kbs = KnowledgeBase.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('ai/knowledge_base.html', knowledge_bases=kbs)


# ==================== REPORTS ROUTES ====================

@app.route('/reports')
@login_required
def reports():
    """Raporlar ana sayfa"""
    return render_template('reports/index.html')


@app.route('/reports/agent-performance')
@login_required
def report_agent_performance():
    """Agent performans raporu"""
    agents = User.query.filter_by(tenant_id=current_user.tenant_id, role='agent').all()
    return render_template('reports/agent_performance.html', agents=agents)


@app.route('/reports/campaign')
@login_required
def report_campaign():
    """Kampanya raporu"""
    campaigns = Campaign.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('reports/campaign.html', campaigns=campaigns)


@app.route('/reports/sla')
@login_required
def report_sla():
    """SLA raporu"""
    queues = Queue.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('reports/sla.html', queues=queues)


@app.route('/reports/quality')
@login_required
def report_quality():
    """Kalite raporu"""
    return render_template('reports/quality.html')


# ==================== CLIENT PORTAL ROUTES ====================

@app.route('/portal')
@login_required
def client_portal():
    """Müşteri portalı"""
    if current_user.role != 'client':
        abort(403)
    
    # Müşterinin erişebildiği projeler
    project_users = ProjectUser.query.filter_by(user_id=current_user.id).all()
    projects = [pu.project for pu in project_users]
    
    return render_template('portal/dashboard.html', projects=projects)


@app.route('/portal/project/<int:id>')
@login_required
def client_project_detail(id):
    """Müşteri proje detayı"""
    if current_user.role != 'client':
        abort(403)
    
    # Erişim kontrolü
    project_user = ProjectUser.query.filter_by(project_id=id, user_id=current_user.id).first()
    if not project_user:
        abort(403)
    
    project = Project.query.get_or_404(id)
    return render_template('portal/project_detail.html', project=project)


# ==================== INTEGRATION ROUTES ====================

@app.route('/integrations')
@login_required
@admin_required
def integrations():
    """Entegrasyonlar"""
    integrations = Integration.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('integrations/list.html', integrations=integrations)


@app.route('/integrations/webhooks')
@login_required
@admin_required
def integration_webhooks():
    """Webhook yönetimi"""
    webhooks = Webhook.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('integrations/webhooks.html', webhooks=webhooks)


@app.route('/integrations/api-keys')
@login_required
@admin_required
def integration_api_keys():
    """API anahtar yönetimi"""
    api_keys = APIKey.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('integrations/api_keys.html', api_keys=api_keys)


# ==================== SETTINGS ROUTES ====================

@app.route('/settings/dispositions')
@login_required
@admin_required
def settings_dispositions():
    """Disposition yönetimi"""
    disposition_sets = DispositionSet.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('settings/dispositions.html', disposition_sets=disposition_sets)


@app.route('/settings/scripts')
@login_required
@admin_required
def settings_scripts():
    """Script yönetimi"""
    scripts = Script.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('settings/scripts.html', scripts=scripts)


@app.route('/settings/custom-fields')
@login_required
@admin_required
def settings_custom_fields():
    """Özel alan yönetimi"""
    fields = CustomField.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('settings/custom_fields.html', fields=fields)


# ==================== API ROUTES ====================

@app.route('/api/stats/realtime')
@login_required
def api_realtime_stats():
    """Gerçek zamanlı istatistikler"""
    stats = get_realtime_stats()
    return jsonify(stats)


@app.route('/api/calls/active')
@login_required
def api_active_calls():
    """Aktif çağrılar"""
    calls = Call.query.filter(
        Call.tenant_id == current_user.tenant_id,
        Call.status.in_(['ringing', 'answered', 'on_hold'])
    ).all()
    
    return jsonify([{
        'id': c.id,
        'direction': c.direction,
        'caller_number': c.caller_number,
        'called_number': c.called_number,
        'agent_id': c.agent_id,
        'status': c.status,
        'duration': c.talk_duration
    } for c in calls])


@app.route('/api/agents/status')
@login_required
def api_agents_status():
    """Agent durumları"""
    agents = User.query.filter_by(
        tenant_id=current_user.tenant_id,
        role='agent',
        is_active=True
    ).all()
    
    return jsonify([{
        'id': a.id,
        'name': a.full_name,
        'status': a.status,
        'extension': a.extension
    } for a in agents])


# ==================== WEBSOCKET EVENTS ====================

@socketio.on('connect')
def handle_connect():
    """WebSocket bağlantısı"""
    if current_user.is_authenticated:
        join_room(f'user_{current_user.id}')
        join_room(f'tenant_{current_user.tenant_id}')
        
        if current_user.role == 'agent':
            join_room('agents')


@socketio.on('disconnect')
def handle_disconnect():
    """WebSocket bağlantı kopması"""
    if current_user.is_authenticated:
        leave_room(f'user_{current_user.id}')
        leave_room(f'tenant_{current_user.tenant_id}')


@socketio.on('agent_status_change')
def handle_agent_status_change(data):
    """Agent durum değişikliği"""
    if current_user.is_authenticated and current_user.role == 'agent':
        current_user.status = data.get('status')
        db.session.commit()
        
        emit('agent_status_updated', {
            'agent_id': current_user.id,
            'status': data.get('status')
        }, room=f'tenant_{current_user.tenant_id}')


# ==================== HELPER FUNCTIONS ====================

def log_audit(action, resource_type, resource_id, description):
    """Audit log kaydı oluştur"""
    log = AuditLog(
        tenant_id=current_user.tenant_id if current_user.is_authenticated else None,
        user_id=current_user.id if current_user.is_authenticated else None,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        description=description,
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string,
        request_method=request.method,
        request_path=request.path
    )
    db.session.add(log)
    db.session.commit()


def get_tenant_stats():
    """Tenant istatistikleri"""
    tenant_id = current_user.tenant_id
    today = datetime.now().replace(hour=0, minute=0, second=0)
    
    return {
        'total_users': User.query.filter_by(tenant_id=tenant_id).count(),
        'active_agents': User.query.filter_by(tenant_id=tenant_id, role='agent', status='available').count(),
        'total_calls_today': Call.query.filter(
            Call.tenant_id == tenant_id,
            Call.started_at >= today
        ).count(),
        'total_customers': Customer.query.filter_by(tenant_id=tenant_id).count(),
        'open_tickets': Ticket.query.filter_by(tenant_id=tenant_id, status='open').count(),
        'active_campaigns': Campaign.query.filter_by(tenant_id=tenant_id, status='active').count()
    }


def get_realtime_stats():
    """Gerçek zamanlı istatistikler"""
    tenant_id = current_user.tenant_id
    today = datetime.now().replace(hour=0, minute=0, second=0)
    
    return {
        'inbound_calls': Call.query.filter(
            Call.tenant_id == tenant_id,
            Call.direction == 'inbound',
            Call.started_at >= today
        ).count(),
        'outbound_calls': Call.query.filter(
            Call.tenant_id == tenant_id,
            Call.direction == 'outbound',
            Call.started_at >= today
        ).count(),
        'active_agents': User.query.filter_by(
            tenant_id=tenant_id,
            role='agent',
            status='available'
        ).count(),
        'queue_waiting': Call.query.filter(
            Call.tenant_id == tenant_id,
            Call.status == 'ringing'
        ).count()
    }


def create_initial_data():
    """İlk kurulum verileri"""
    # Süper admin kontrolü
    super_admin = User.query.filter_by(is_super_admin=True).first()
    if not super_admin:
        super_admin = User(
            username='superadmin',
            email='superadmin@aibeecc.com',
            full_name='Super Admin',
            role='admin',
            is_super_admin=True,
            is_active=True
        )
        super_admin.set_password('1234')
        db.session.add(super_admin)
        db.session.commit()
    
    # Demo tenant
    demo_tenant = Tenant.query.filter_by(code='DEMO').first()
    if not demo_tenant:
        demo_tenant = Tenant(
            code='DEMO',
            name='Demo Çağrı Merkezi',
            timezone='Europe/Istanbul',
            language='tr',
            max_agents=50,
            max_concurrent_calls=100,
            status='active'
        )
        db.session.add(demo_tenant)
        db.session.commit()
        
        # Demo tenant ayarları
        settings = TenantSettings(tenant_id=demo_tenant.id)
        db.session.add(settings)
        
        # Demo proje
        project = Project(
            tenant_id=demo_tenant.id,
            code='SALES',
            name='Satış Projesi',
            description='Demo satış kampanyası',
            status='active'
        )
        db.session.add(project)
        db.session.commit()
        
        # Demo kampanyalar
        campaigns = [
            Campaign(
                tenant_id=demo_tenant.id,
                project_id=project.id,
                name='Satış Kampanyası',
                description='Outbound satış kampanyası',
                dialer_type='preview',
                status='active'
            ),
            Campaign(
                tenant_id=demo_tenant.id,
                project_id=project.id,
                name='Müşteri Memnuniyeti',
                description='Progressive dialer ile anket',
                dialer_type='progressive',
                status='active'
            ),
            Campaign(
                tenant_id=demo_tenant.id,
                project_id=project.id,
                name='Destek Hattı',
                description='Inbound destek hattı',
                dialer_type='preview',
                status='active'
            )
        ]
        for c in campaigns:
            db.session.add(c)
        
        # Demo admin
        admin = User(
            tenant_id=demo_tenant.id,
            username='admin',
            email='admin@callcenter.local',
            full_name='System Admin',
            role='admin',
            extension='100',
            is_active=True
        )
        admin.set_password('1234')
        db.session.add(admin)
        
        # Demo supervisor
        supervisor = User(
            tenant_id=demo_tenant.id,
            username='supervisor',
            email='supervisor@callcenter.local',
            full_name='Demo Supervisor',
            role='supervisor',
            extension='101',
            is_active=True
        )
        supervisor.set_password('1234')
        db.session.add(supervisor)
        
        # Demo agent
        agent = User(
            tenant_id=demo_tenant.id,
            username='agent',
            email='agent@callcenter.local',
            full_name='Demo Agent',
            role='agent',
            extension='200',
            is_active=True
        )
        agent.set_password('1234')
        db.session.add(agent)
        
        # Disposition set
        dispo_set = DispositionSet(
            tenant_id=demo_tenant.id,
            name='Standart Sonuçlar',
            is_active=True
        )
        db.session.add(dispo_set)
        db.session.commit()
        
        # Dispositions
        dispositions = [
            ('sale_ok', 'Satış Başarılı', 'positive'),
            ('callback', 'Geri Arama', 'neutral'),
            ('no_interest', 'İlgilenmiyor', 'negative'),
            ('wrong_number', 'Yanlış Numara', 'negative'),
            ('no_answer', 'Ulaşılamadı', 'neutral'),
            ('voicemail', 'Telesekreter', 'neutral'),
            ('blacklist', 'Kara Liste', 'negative'),
        ]
        for code, name, category in dispositions:
            d = Disposition(
                tenant_id=demo_tenant.id,
                disposition_set_id=dispo_set.id,
                code=code,
                name=name,
                category=category,
                is_active=True
            )
            db.session.add(d)
        
        db.session.commit()
        print('Demo veriler oluşturuldu.')
    
    # Mevcut tenant için kampanya kontrolü
    else:
        # Kampanya yoksa ekle
        if Campaign.query.filter_by(tenant_id=demo_tenant.id).count() == 0:
            project = Project.query.filter_by(tenant_id=demo_tenant.id).first()
            if not project:
                project = Project(
                    tenant_id=demo_tenant.id,
                    code='SALES',
                    name='Satış Projesi',
                    status='active'
                )
                db.session.add(project)
                db.session.commit()
            
            campaign = Campaign(
                tenant_id=demo_tenant.id,
                project_id=project.id,
                name='Demo Kampanya',
                description='Demo kampanya',
                dialer_type='preview',
                status='active'
            )
            db.session.add(campaign)
            db.session.commit()
            print('Demo kampanya eklendi.')


# ==================== STARTUP ====================

if __name__ == '__main__':
    # Gerekli klasörleri oluştur
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['RECORDINGS_FOLDER'], exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    
    # Veritabanı tablolarını oluştur ve ilk verileri ekle
    with app.app_context():
        db.create_all()
        create_initial_data()
    
    # Uygulamayı başlat
    socketio.run(
        app,
        host='0.0.0.0',
        port=3000,
        debug=app.config['DEBUG']
    )
