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
    Campaign, CampaignUser, DialList, Lead, LeadAttempt,
    # CRM
    Customer, CustomerNote, CustomField, Pipeline, PipelineStage, Ticket, TicketCategory,
    # Call
    Call, CallRecording, CallTranscript, DispositionSet, Disposition, Script,
    # QA
    QAForm, QACriteria, QAEvaluation,
    # AI
    AISettings, KnowledgeBase, KBDocument,
    AIProvider, AIProjectSettings, AITranscription, AICallAnalysis,
    AIQAEvaluation, AIAgentSuggestion, AIVoiceBot, AIVoiceBotSession,
    AISmartRouting, AILeadScoring, AIDialerOptimization, AIFraudDetection,
    AIUsage, AIFeedback, AIModelPerformance, AIPackage, TenantAISubscription,
    # Integration
    Integration, Webhook, APIKey,
    # Audit
    AuditLog, SecurityEvent, SystemEvent,
    # Report
    Report, Dashboard, DashboardWidget,
    # Notification
    Notification,
    # Billing & Subscription
    BillingPlan, TenantSubscription, TenantBillingInfo,
    # VoIP Billing
    VoIPTariff, VoIPRate, TenantVoIPConfig,
    # VoIP Provisioning
    DIDPool, CLIPool, TenantCLIAssignment, TrunkAllocation,
    # Usage & Metering
    UsageRecord, UsageSummary, Invoice, InvoiceItem, Payment,
    # White-Label
    TenantBranding, TenantDomain,
    # Support
    SupportTicket, SupportTicketMessage, SystemAnnouncement,
    # Quota
    TenantQuota, QuotaAlert
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

def process_login(username, password, allowed_roles=None, template='login.html', redirect_url='dashboard'):
    """Ortak login işlemi"""
    user = User.query.filter_by(username=username).first()
    
    if user and user.check_password(password):
        # Rol kontrolü
        if allowed_roles and user.role not in allowed_roles:
            flash('Bu sayfadan giriş yetkiniz yok.', 'danger')
            return None
        
        if not user.is_active:
            flash('Hesabınız pasif durumda. Yönetici ile iletişime geçin.', 'danger')
            return None
        
        if user.is_locked:
            flash(f'Hesabınız kilitli: {user.lock_reason}', 'danger')
            return None
        
        login_user(user)
        user.last_login = datetime.utcnow()
        user.current_ip = request.remote_addr
        user.failed_login_attempts = 0
        db.session.commit()
        
        log_audit('login', 'user', user.id, 'Kullanıcı giriş yaptı')
        return user
    else:
        if user:
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            user.last_failed_login = datetime.utcnow()
            
            if user.failed_login_attempts >= 5:
                user.is_locked = True
                user.lock_reason = 'Çok fazla başarısız giriş denemesi'
                
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
        return None


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Super Admin Giriş Sayfası"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = process_login(username, password, allowed_roles=['super_admin'])
        if user:
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
    
    return render_template('login.html', login_type='superadmin')


@app.route('/cc/login', methods=['GET', 'POST'])
@app.route('/cc-admin', methods=['GET', 'POST'])
def admin_login():
    """CC Admin Giriş Sayfası"""
    if current_user.is_authenticated:
        if current_user.role in ['admin', 'super_admin']:
            return redirect(url_for('dashboard'))
        else:
            logout_user()
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = process_login(username, password, allowed_roles=['admin', 'super_admin', 'supervisor'])
        if user:
            return redirect(url_for('dashboard'))
    
    return render_template('login_admin.html', login_type='admin')


@app.route('/agent/login', methods=['GET', 'POST'])
def agent_login():
    """Agent Giriş Sayfası"""
    if current_user.is_authenticated:
        if current_user.role == 'agent':
            return redirect(url_for('agent_panel'))
        else:
            logout_user()
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = process_login(username, password, allowed_roles=['agent'])
        if user:
            return redirect(url_for('agent_panel'))
    
    return render_template('login_agent.html', login_type='agent')


@app.route('/qc/login', methods=['GET', 'POST'])
def qc_login():
    """QC Dinleme Giriş Sayfası"""
    if current_user.is_authenticated:
        if current_user.role == 'qc_listener':
            return redirect(url_for('qc_listener_panel'))
        else:
            logout_user()
    
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = process_login(username, password, allowed_roles=['qc_listener'])
        if user:
            return redirect(url_for('qc_listener_panel'))
        else:
            error = True
    
    return render_template('login_qc.html', error=error)


@app.route('/qc/login/post', methods=['POST'])
def login_qc_post():
    """QC Login POST handler"""
    return qc_login()


@app.route('/qc/panel')
@login_required
def qc_listener_panel():
    """QC Dinleme Paneli"""
    if current_user.role not in ['qc_listener', 'supervisor', 'admin', 'super_admin']:
        flash('Bu sayfaya erişim yetkiniz yok.', 'danger')
        return redirect(url_for('dashboard'))
    
    return render_template('qc/listener_panel.html')


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
def landing():
    """Landing page - giriş yapmamış kullanıcılar için tanıtım sayfası"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')

@app.route('/privacy')
def privacy():
    """Gizlilik Politikası / Datenschutzrichtlinie"""
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    """Kullanım Şartları / Nutzungsbedingungen"""
    return render_template('terms.html')

@app.route('/about')
def about():
    """Hakkımızda / Über Uns"""
    return render_template('about.html')

@app.route('/our-integrations')
def our_integrations():
    """Entegrasyonlar / Integrationen - Public sayfa"""
    return render_template('integrations.html')

@app.route('/api-docs')
def api_docs():
    """API Dokümantasyon"""
    return render_template('api_docs.html')

@app.route('/career')
def career():
    """Kariyer / Karriere"""
    return render_template('career.html')

@app.route('/blog')
def blog():
    """Blog"""
    return render_template('blog.html')

@app.route('/press')
def press():
    """Basın / Presse"""
    return render_template('press.html')

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


@app.route('/platform/backup')
@login_required
@super_admin_required
def platform_backup():
    """Sistem backup yönetimi"""
    return render_template('platform/backup.html')


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
    """Kullan??c?? y??netimi"""
    selected_tenant_id = request.args.get('tenant_id', type=int)

    if current_user.is_super_admin:
        q = User.query
        if selected_tenant_id:
            q = q.filter_by(tenant_id=selected_tenant_id)
        users = q.order_by(User.created_at.desc()).all()
        tenants = Tenant.query.order_by(Tenant.name.asc()).all()
    else:
        users = User.query.filter_by(tenant_id=current_user.tenant_id).order_by(User.created_at.desc()).all()
        tenants = None
        selected_tenant_id = current_user.tenant_id

    return render_template('admin/users.html', users=users, tenants=tenants, selected_tenant_id=selected_tenant_id)


@app.route('/admin/users/new', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_user_new():
    """Yeni kullanıcı oluştur - Detaylı form"""
    if request.method == 'POST':
        # Kullanıcı oluştur
        user = User(
            tenant_id=current_user.tenant_id,
            username=request.form.get('username'),
            email=request.form.get('email'),
            first_name=request.form.get('first_name'),
            last_name=request.form.get('last_name'),
            full_name=f"{request.form.get('first_name')} {request.form.get('last_name')}",
            german_first_name=request.form.get('german_first_name'),
            german_last_name=request.form.get('german_last_name'),
            german_full_name=f"{request.form.get('german_first_name', '')} {request.form.get('german_last_name', '')}".strip() or None,
            phone=request.form.get('phone'),
            role=request.form.get('role'),
            extension=request.form.get('extension'),
            department_id=request.form.get('department_id') or None,
            team_id=request.form.get('team_id') or None,
            is_active=request.form.get('is_active') == '1',
            must_change_password='must_change_password' in request.form
        )
        user.set_password(request.form.get('password'))
        
        # Super admin kontrolü
        if request.form.get('role') == 'super_admin' and current_user.is_super_admin:
            user.is_super_admin = True
        
        db.session.add(user)
        db.session.flush()  # ID almak için
        
        # Proje atamaları
        project_ids = request.form.getlist('projects[]')
        for proj_id in project_ids:
            if proj_id:
                project_user = ProjectUser(
                    project_id=int(proj_id),
                    user_id=user.id,
                    role=user.role,
                    can_view_recordings=True,
                    can_export_data=user.role in ['supervisor', 'admin', 'super_admin'],
                    can_edit_customers=True
                )
                db.session.add(project_user)

        # Kampanya atamalar??
        campaign_ids = request.form.getlist('campaigns[]')
        for camp_id in campaign_ids:
            if camp_id:
                db.session.add(CampaignUser(
                    campaign_id=int(camp_id),
                    user_id=user.id,
                    role=user.role,
                    is_active=True
                ))
        
        db.session.commit()
        
        log_audit('create', 'user', user.id, f'Yeni kullanıcı oluşturuldu: {user.username} (Rol: {user.role})')
        flash(f'"{user.full_name}" başarıyla oluşturuldu.', 'success')
        return redirect(url_for('admin_users'))
    
    # GET - Form verilerini hazırla
    departments = Department.query.filter_by(tenant_id=current_user.tenant_id, is_active=True).all()
    teams = Team.query.filter_by(tenant_id=current_user.tenant_id, is_active=True).all()
    projects = Project.query.filter_by(tenant_id=current_user.tenant_id, is_active=True).all()
    campaigns = Campaign.query.filter_by(tenant_id=current_user.tenant_id, is_active=True).all()
    
    return render_template('admin/user_form.html', 
                          user=None, 
                          departments=departments, 
                          teams=teams,
                          projects=projects,
                          campaigns=campaigns)


@app.route('/admin/users/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_user_edit(id):
    """Kullan??c?? d??zenle"""
    user = User.query.get_or_404(id)

    if user.tenant_id != current_user.tenant_id and not current_user.is_super_admin:
        abort(403)

    if request.method == 'POST':
        user.email = request.form.get('email')
        user.first_name = request.form.get('first_name')
        user.last_name = request.form.get('last_name')
        user.full_name = f"{request.form.get('first_name')} {request.form.get('last_name')}"

        user.german_first_name = request.form.get('german_first_name')
        user.german_last_name = request.form.get('german_last_name')
        user.german_full_name = f"{request.form.get('german_first_name', '')} {request.form.get('german_last_name', '')}".strip() or None

        user.phone = request.form.get('phone')
        user.role = request.form.get('role')
        user.extension = request.form.get('extension')
        user.department_id = request.form.get('department_id') or None
        user.team_id = request.form.get('team_id') or None
        user.is_active = request.form.get('is_active') == '1'
        user.must_change_password = 'must_change_password' in request.form

        if request.form.get('password'):
            user.set_password(request.form.get('password'))

        # Reset assignments
        ProjectUser.query.filter_by(user_id=user.id).delete()
        CampaignUser.query.filter_by(user_id=user.id).delete()

        # Projects
        for proj_id in request.form.getlist('projects[]'):
            if proj_id:
                db.session.add(ProjectUser(
                    project_id=int(proj_id),
                    user_id=user.id,
                    role=user.role,
                    can_view_recordings=True,
                    can_export_data=user.role in ['supervisor', 'admin', 'super_admin'],
                    can_edit_customers=True
                ))

        # Campaigns
        for camp_id in request.form.getlist('campaigns[]'):
            if camp_id:
                db.session.add(CampaignUser(
                    campaign_id=int(camp_id),
                    user_id=user.id,
                    role=user.role,
                    is_active=True
                ))

        db.session.commit()
        log_audit('update', 'user', user.id, f'Kullan??c?? g??ncellendi: {user.username}')
        flash('Kullan??c?? ba??ar??yla g??ncellendi.', 'success')
        return redirect(url_for('admin_users'))

    departments = Department.query.filter_by(tenant_id=user.tenant_id, is_active=True).all()
    teams = Team.query.filter_by(tenant_id=user.tenant_id, is_active=True).all()
    projects = Project.query.filter_by(tenant_id=user.tenant_id, is_active=True).all()
    campaigns = Campaign.query.filter_by(tenant_id=user.tenant_id, is_active=True).all()

    user_projects = [pu.project_id for pu in ProjectUser.query.filter_by(user_id=user.id).all()]
    user_campaigns = [cu.campaign_id for cu in CampaignUser.query.filter_by(user_id=user.id).all()]

    return render_template('admin/user_form.html', user=user, departments=departments, teams=teams, projects=projects, campaigns=campaigns, user_projects=user_projects, user_campaigns=user_campaigns)


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


@app.route('/admin/tenants')
@login_required
@super_admin_required
def admin_tenants():
    """Tenant (Çağrı Merkezi) yönetimi - Super Admin"""
    tenants = Tenant.query.all()
    return render_template('admin/tenants.html', tenants=tenants)


@app.route('/admin/tenants/new', methods=['GET', 'POST'])
@login_required
@super_admin_required
def admin_tenant_new():
    """Yeni tenant oluştur"""
    if request.method == 'POST':
        import secrets
        tenant = Tenant(
            code=request.form.get('code'),
            name=request.form.get('name'),
            domain=request.form.get('domain'),
            timezone=request.form.get('timezone', 'Europe/Istanbul'),
            language=request.form.get('language', 'tr'),
            max_agents=request.form.get('max_agents', type=int),
            max_concurrent_calls=request.form.get('max_concurrent_calls', type=int),
            api_key=secrets.token_urlsafe(32)
        )
        db.session.add(tenant)
        db.session.commit()
        
        # Varsayılan kota oluştur
        quota = TenantQuota(tenant_id=tenant.id)
        db.session.add(quota)
        db.session.commit()
        
        flash(f'Tenant "{tenant.name}" başarıyla oluşturuldu.', 'success')
        return redirect(url_for('admin_tenants'))
    return render_template('admin/tenant_form.html', tenant=None)


@app.route('/admin/tenants/<int:tenant_id>/edit', methods=['GET', 'POST'])
@login_required
@super_admin_required
def admin_tenant_edit(tenant_id):
    """Tenant düzenle"""
    tenant = Tenant.query.get_or_404(tenant_id)
    if request.method == 'POST':
        tenant.name = request.form.get('name')
        tenant.domain = request.form.get('domain')
        tenant.timezone = request.form.get('timezone')
        tenant.language = request.form.get('language')
        tenant.max_agents = request.form.get('max_agents', type=int)
        tenant.max_concurrent_calls = request.form.get('max_concurrent_calls', type=int)
        tenant.status = request.form.get('status')
        db.session.commit()
        flash('Tenant güncellendi.', 'success')
        return redirect(url_for('admin_tenants'))
    return render_template('admin/tenant_form.html', tenant=tenant)


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


# ==================== VOIP / TELEPHONY ROUTES ====================

@app.route('/voip')
@app.route('/voip/dashboard')
@login_required
@super_admin_required
def voip_dashboard():
    """VoIP Dashboard - Gerçek zamanlı izleme"""
    return render_template('voip/dashboard.html')


@app.route('/voip/trunks')
@app.route('/telephony/trunks')
@login_required
@super_admin_required
def voip_trunks():
    """SIP Trunk yönetimi"""
    if current_user.is_super_admin:
        trunks = SIPTrunk.query.all()
    else:
        trunks = SIPTrunk.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('voip/trunks.html', trunks=trunks)


@app.route('/voip/dids')
@app.route('/telephony/dids')
@login_required
@super_admin_required
def voip_dids():
    """DID / Numara yönetimi"""
    if current_user.is_super_admin:
        dids = DID.query.all()
        trunks = SIPTrunk.query.all()
    else:
        dids = DID.query.filter_by(tenant_id=current_user.tenant_id).all()
        trunks = SIPTrunk.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('voip/dids.html', dids=dids, trunks=trunks)


@app.route('/voip/ivr')
@app.route('/voip/ivr-builder')
@app.route('/telephony/ivrs')
@login_required
@super_admin_required
def voip_ivr_builder():
    """IVR Builder"""
    if current_user.is_super_admin:
        ivrs = IVR.query.all()
        queues_list = Queue.query.all()
    else:
        ivrs = IVR.query.filter_by(tenant_id=current_user.tenant_id).all()
        queues_list = Queue.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('voip/ivr_builder.html', ivrs=ivrs, queues=queues_list)


@app.route('/voip/recordings')
@app.route('/telephony/recordings')
@login_required
@admin_required
def voip_recordings():
    """Ses Kayıtları - Call Recordings"""
    return render_template('voip/recordings.html')


@app.route('/voip/trunk-monitor')
@login_required
@admin_required
def voip_trunk_monitor():
    """Trunk Monitor & Failover"""
    return render_template('voip/trunk_monitor.html')


@app.route('/voip/queues')
@app.route('/queues')
@login_required
@admin_required
def voip_queues():
    """CC Satış & QC yönetimi"""
    if current_user.is_super_admin:
        queues_list = Queue.query.all()
    else:
        queues_list = Queue.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('voip/queues.html', queues=queues_list)


@app.route('/voip/call-queue')
@app.route('/call-queue')
@login_required
@admin_required
def call_queue():
    """Çağrı Kuyruğu - Aktif çağrılar ve arama hızı yönetimi"""
    return render_template('voip/call_queue.html')


@app.route('/voip/cdr')
@login_required
@admin_required
def voip_cdr():
    """CDR - Çağrı Kayıtları"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    query = Call.query
    if not current_user.is_super_admin:
        query = query.filter_by(tenant_id=current_user.tenant_id)
    
    # Filters
    call_type = request.args.get('type')
    status = request.args.get('status')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    
    if call_type:
        query = query.filter_by(direction=call_type)
    if status:
        query = query.filter_by(status=status)
    
    calls = query.order_by(Call.started_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    return render_template('voip/cdr.html', calls=calls)


@app.route('/voip/softphone')
@login_required
def voip_softphone():
    """WebRTC Softphone"""
    return render_template('voip/softphone.html')


# ==================== VOIP API ENDPOINTS ====================

@app.route('/api/voip/trunks', methods=['GET', 'POST'])
@login_required
@super_admin_required
def api_voip_trunks():
    """SIP Trunk API"""
    if request.method == 'GET':
        if current_user.is_super_admin:
            trunks = SIPTrunk.query.all()
        else:
            trunks = SIPTrunk.query.filter_by(tenant_id=current_user.tenant_id).all()
        return jsonify([{
            'id': t.id,
            'name': t.name,
            'host': t.host,
            'port': t.port,
            'username': t.username,
            'transport': t.transport,
            'max_channels': t.max_channels,
            'codecs': t.codecs,
            'status': t.status
        } for t in trunks])
    
    elif request.method == 'POST':
        data = request.get_json()
        trunk = SIPTrunk(
            tenant_id=current_user.tenant_id if not current_user.is_super_admin else data.get('tenant_id'),
            name=data.get('name'),
            host=data.get('host'),
            port=data.get('port', 5060),
            username=data.get('username'),
            password=data.get('password'),
            transport=data.get('transport', 'udp'),
            max_channels=data.get('max_channels', 30),
            codecs=data.get('codecs'),
            status='inactive'
        )
        db.session.add(trunk)
        db.session.commit()
        
        log_audit('create', 'sip_trunk', trunk.id, f'SIP Trunk oluşturuldu: {trunk.name}')
        return jsonify({'success': True, 'id': trunk.id})


@app.route('/api/voip/trunks/<int:trunk_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
@super_admin_required
def api_voip_trunk(trunk_id):
    """SIP Trunk detay API"""
    trunk = SIPTrunk.query.get_or_404(trunk_id)
    
    if request.method == 'GET':
        return jsonify({
            'id': trunk.id,
            'name': trunk.name,
            'host': trunk.host,
            'port': trunk.port,
            'username': trunk.username,
            'transport': trunk.transport,
            'max_channels': trunk.max_channels,
            'codecs': trunk.codecs,
            'status': trunk.status,
            'provider': trunk.provider,
            'outbound_proxy': trunk.outbound_proxy
        })
    
    elif request.method == 'PUT':
        data = request.get_json()
        trunk.name = data.get('name', trunk.name)
        trunk.host = data.get('host', trunk.host)
        trunk.port = data.get('port', trunk.port)
        trunk.username = data.get('username', trunk.username)
        if data.get('password'):
            trunk.password = data.get('password')
        trunk.transport = data.get('transport', trunk.transport)
        trunk.max_channels = data.get('max_channels', trunk.max_channels)
        trunk.codecs = data.get('codecs', trunk.codecs)
        db.session.commit()
        
        log_audit('update', 'sip_trunk', trunk.id, f'SIP Trunk güncellendi: {trunk.name}')
        return jsonify({'success': True})
    
    elif request.method == 'DELETE':
        name = trunk.name
        db.session.delete(trunk)
        db.session.commit()
        
        log_audit('delete', 'sip_trunk', trunk_id, f'SIP Trunk silindi: {name}')
        return jsonify({'success': True})


@app.route('/api/voip/trunks/<int:trunk_id>/test', methods=['POST'])
@login_required
@super_admin_required
def api_voip_trunk_test(trunk_id):
    """SIP Trunk bağlantı testi"""
    trunk = SIPTrunk.query.get_or_404(trunk_id)
    
    # Gerçek implementasyonda SIP OPTIONS veya REGISTER test çağrısı yapılır
    # Şimdilik simülasyon
    import random
    success = random.random() > 0.2
    latency = random.randint(20, 100)
    
    if success:
        trunk.status = 'active'
        trunk.last_check = datetime.utcnow()
        db.session.commit()
        return jsonify({'success': True, 'latency': latency})
    else:
        trunk.status = 'error'
        db.session.commit()
        return jsonify({'success': False, 'error': 'Connection timeout'})


@app.route('/api/voip/dids', methods=['GET', 'POST'])
@login_required
@admin_required
def api_voip_dids():
    """DID API"""
    if request.method == 'GET':
        if current_user.is_super_admin:
            dids = DID.query.all()
        else:
            dids = DID.query.filter_by(tenant_id=current_user.tenant_id).all()
        return jsonify([{
            'id': d.id,
            'number': d.number,
            'type': d.did_type,
            'trunk_id': d.trunk_id,
            'is_active': d.is_active
        } for d in dids])
    
    elif request.method == 'POST':
        data = request.get_json()
        did = DID(
            tenant_id=current_user.tenant_id if not current_user.is_super_admin else data.get('tenant_id'),
            trunk_id=data.get('trunk_id'),
            number=data.get('number'),
            did_type=data.get('type', 'inbound'),
            description=data.get('description'),
            is_active=True
        )
        db.session.add(did)
        db.session.commit()
        
        log_audit('create', 'did', did.id, f'DID oluşturuldu: {did.number}')
        return jsonify({'success': True, 'id': did.id})


@app.route('/api/voip/queues', methods=['GET', 'POST'])
@login_required
@admin_required
def api_voip_queues():
    """Queue API"""
    if request.method == 'GET':
        if current_user.is_super_admin:
            queues_list = Queue.query.all()
        else:
            queues_list = Queue.query.filter_by(tenant_id=current_user.tenant_id).all()
        return jsonify([{
            'id': q.id,
            'name': q.name,
            'extension': q.extension,
            'strategy': q.strategy,
            'max_wait_time': q.max_wait_time,
            'status': q.status
        } for q in queues_list])
    
    elif request.method == 'POST':
        data = request.get_json()
        queue = Queue(
            tenant_id=current_user.tenant_id if not current_user.is_super_admin else data.get('tenant_id'),
            name=data.get('name'),
            extension=data.get('extension'),
            strategy=data.get('strategy', 'ringall'),
            max_wait_time=data.get('max_wait', 300),
            ring_timeout=data.get('ring_timeout', 20),
            wrapup_time=data.get('wrapup', 30),
            status='active'
        )
        db.session.add(queue)
        db.session.commit()
        
        log_audit('create', 'queue', queue.id, f'Kuyruk oluşturuldu: {queue.name}')
        return jsonify({'success': True, 'id': queue.id})


@app.route('/api/voip/calls/active')
@login_required
def api_voip_active_calls():
    """Aktif çağrılar"""
    # Gerçek implementasyonda PBX'ten aktif çağrı bilgisi alınır
    # Şimdilik demo veri
    return jsonify([
        {
            'id': 1,
            'caller': '+90 532 XXX XX45',
            'callee': '8001',
            'direction': 'inbound',
            'duration': 342,
            'agent': 'Ahmet Y.',
            'queue': 'Satış',
            'status': 'connected'
        },
        {
            'id': 2,
            'caller': '+90 212 555 0001',
            'callee': '+90 555 XXX XX12',
            'direction': 'outbound',
            'duration': 138,
            'agent': 'Ayşe K.',
            'queue': 'Satış',
            'status': 'connected'
        }
    ])


@app.route('/api/voip/stats')
@login_required
def api_voip_stats():
    """VoIP istatistikleri"""
    return jsonify({
        'active_calls': 24,
        'waiting_calls': 8,
        'available_agents': 32,
        'sla_percentage': 94,
        'aht': '3:42',
        'trunk_usage': 67
    })


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


@app.route('/api/data/analyze', methods=['POST'])
@login_required
def api_data_analyze():
    """Data dosyasını analiz et"""
    import os
    import uuid
    
    if 'file' not in request.files:
        return jsonify({'error': 'Dosya bulunamadı'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Dosya seçilmedi'}), 400
    
    # Dosyayı geçici olarak kaydet
    file_id = str(uuid.uuid4())
    upload_dir = os.path.join(app.root_path, 'uploads', 'temp')
    os.makedirs(upload_dir, exist_ok=True)
    
    file_ext = os.path.splitext(file.filename)[1]
    temp_path = os.path.join(upload_dir, f'{file_id}{file_ext}')
    file.save(temp_path)
    
    # Dosyayı analiz et
    try:
        import pandas as pd
        
        if file_ext.lower() == '.csv':
            df = pd.read_csv(temp_path, encoding='utf-8', sep=None, engine='python')
        else:
            df = pd.read_excel(temp_path)
        
        total = len(df)
        
        # Zorunlu alan kontrolü
        required_cols = []
        phone_cols = ['telefon', 'tel', 'phone', 'handy', 'mobiltelefon']
        name_cols = ['vorname', 'name', 'firstname']
        surname_cols = ['nachname', 'lastname', 'surname']
        
        df.columns = df.columns.str.lower().str.strip()
        
        # Telefon kontrolü
        phone_col = None
        for col in phone_cols:
            if col in df.columns:
                phone_col = col
                break
        
        # Hatalı kayıtlar (telefon eksik veya geçersiz)
        errors = 0
        if phone_col:
            # Telefon numarası kontrolü
            df['_phone_valid'] = df[phone_col].astype(str).str.replace(r'\D', '', regex=True)
            errors = len(df[df['_phone_valid'].str.len() < 8])
        else:
            errors = total  # Telefon sütunu yoksa tümü hatalı
        
        # IBAN kontrolü
        iban_cols = ['iban']
        iban_col = None
        for col in iban_cols:
            if col in df.columns:
                iban_col = col
                break
        
        with_iban = 0
        if iban_col:
            with_iban = len(df[df[iban_col].notna() & (df[iban_col].astype(str).str.len() > 10)])
        
        valid = total - errors
        
        # Sonuçları döndür
        return jsonify({
            'success': True,
            'file_id': file_id,
            'filename': file.filename,
            'total': total,
            'valid': valid,
            'errors': errors,
            'duplicates': 0,  # İlk yüklemede dublet yok
            'blacklist': 0,   # Blacklist kontrolü sonra
            'with_iban': with_iban,
            'columns': list(df.columns)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/data/confirm', methods=['POST'])
@login_required
def api_data_confirm():
    """Analiz edilen datayı onayla ve veritabanına kaydet"""
    import os
    import pandas as pd
    
    data = request.get_json()
    file_id = data.get('file_id')
    name = data.get('name')
    campaign_id = data.get('campaign_id')
    
    # Geçici dosyayı bul
    upload_dir = os.path.join(app.root_path, 'uploads', 'temp')
    temp_files = [f for f in os.listdir(upload_dir) if f.startswith(file_id)]
    
    if not temp_files:
        return jsonify({'error': 'Dosya bulunamadı'}), 404
    
    temp_path = os.path.join(upload_dir, temp_files[0])
    
    try:
        # Dosyayı oku
        file_ext = os.path.splitext(temp_files[0])[1]
        if file_ext.lower() == '.csv':
            df = pd.read_csv(temp_path, encoding='utf-8', sep=None, engine='python')
        else:
            df = pd.read_excel(temp_path)
        
        df.columns = df.columns.str.lower().str.strip()
        
        # DialList oluştur
        dial_list = DialList(
            tenant_id=current_user.tenant_id,
            campaign_id=int(campaign_id) if campaign_id else None,
            name=name,
            total_records=len(df),
            valid_records=data.get('valid', len(df)),
            duplicate_records=data.get('duplicates', 0),
            status='active'
        )
        db.session.add(dial_list)
        db.session.flush()
        
        # Müşterileri ekle
        phone_cols = ['telefon', 'tel', 'phone', 'handy']
        phone_col = next((c for c in phone_cols if c in df.columns), None)
        
        added = 0
        for _, row in df.iterrows():
            try:
                phone = str(row.get(phone_col, '')).strip() if phone_col else ''
                if not phone or len(phone) < 8:
                    continue
                
                customer = Customer(
                    tenant_id=current_user.tenant_id,
                    project_id=dial_list.campaign.project_id if dial_list.campaign else None,
                    phone=phone,
                    first_name=str(row.get('vorname', row.get('name', ''))).strip(),
                    last_name=str(row.get('nachname', row.get('lastname', ''))).strip(),
                    email=str(row.get('email', row.get('e-mail', ''))).strip() or None,
                    address=str(row.get('strasse', row.get('straße', row.get('adresse', '')))).strip() or None,
                    postal_code=str(row.get('plz', '')).strip() or None,
                    city=str(row.get('ort', row.get('stadt', ''))).strip() or None,
                    iban=str(row.get('iban', '')).strip() or None,
                    status='new',
                    source='import',
                    source_detail=name
                )
                db.session.add(customer)
                added += 1
                
                # Lead de oluştur
                lead = Lead(
                    tenant_id=current_user.tenant_id,
                    dial_list_id=dial_list.id,
                    customer_id=customer.id,
                    phone=phone,
                    first_name=customer.first_name,
                    last_name=customer.last_name,
                    status='new',
                    priority=data.get('priority', 'normal')
                )
                db.session.add(lead)
                
            except Exception as e:
                continue
        
        dial_list.valid_records = added
        db.session.commit()
        
        # Geçici dosyayı sil
        os.remove(temp_path)
        
        return jsonify({
            'success': True,
            'list_id': dial_list.id,
            'added': added,
            'message': f'{added} kayıt başarıyla eklendi'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/data/cancel', methods=['POST'])
@login_required
def api_data_cancel():
    """Analizi iptal et ve geçici dosyayı sil"""
    import os
    
    data = request.get_json()
    file_id = data.get('file_id')
    
    if file_id:
        upload_dir = os.path.join(app.root_path, 'uploads', 'temp')
        if os.path.exists(upload_dir):
            for f in os.listdir(upload_dir):
                if f.startswith(file_id):
                    os.remove(os.path.join(upload_dir, f))
    
    return jsonify({'success': True})


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
    """Müşteri detayı - Tam panel görünümü"""
    customer = Customer.query.get_or_404(id)
    
    # Get call history
    calls = Call.query.filter_by(customer_id=id).order_by(Call.started_at.desc()).limit(10).all()
    
    # Get recordings
    recordings = CallRecording.query.join(Call).filter(Call.customer_id == id).all()
    
    # Get notes
    notes = CustomerNote.query.filter_by(customer_id=id).order_by(CustomerNote.created_at.desc()).all()
    
    # Get QA evaluations
    qa_evals = QAEvaluation.query.join(Call).filter(Call.customer_id == id).all()
    
    # Numara/Email görünürlüğü - Admin/Supervisor/QC tam görür, Agent maskelenmiş görür
    show_full_phone = current_user.role in ['admin', 'super_admin', 'supervisor', 'qc_listener']
    show_full_email = show_full_phone
    
    return render_template('crm/customer_panel.html', 
                          customer=customer,
                          calls=calls,
                          recordings=recordings,
                          notes=notes,
                          qa_evals=qa_evals,
                          show_full_phone=show_full_phone,
                          show_full_email=show_full_email)


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


@app.route('/agent/call/<int:customer_id>')
@login_required
def agent_call_card(customer_id):
    """Agent müşteri arama kartı - Numara maskelenmiş"""
    customer = Customer.query.get_or_404(customer_id)
    
    # Kampanya ayarlarından numara görünürlüğü kontrolü
    show_full_phone = False
    active_campaign = session.get('active_campaign_id')
    if active_campaign:
        campaign = Campaign.query.get(active_campaign)
        if campaign:
            # Kampanya ayarında show_phone_number varsa kontrol et
            campaign_settings = campaign.settings or {}
            show_full_phone = campaign_settings.get('show_phone_number', False)
    
    # Admin veya Supervisor her zaman görebilir
    if current_user.role in ['admin', 'super_admin', 'supervisor']:
        show_full_phone = True
    
    # Önceki aramalar
    previous_calls = Call.query.filter_by(customer_id=customer_id).order_by(Call.started_at.desc()).limit(5).all()
    
    # Bugünkü istatistikler
    today = datetime.now().replace(hour=0, minute=0, second=0)
    today_calls = Call.query.filter(
        Call.agent_id == current_user.id,
        Call.started_at >= today
    ).all()
    
    # Script (kampanyaya ait)
    script = None
    if active_campaign:
        campaign = Campaign.query.get(active_campaign)
        if campaign and campaign.script_id:
            script = Script.query.get(campaign.script_id)
    
    return render_template('agent/call_card.html',
                          customer=customer,
                          show_full_phone=show_full_phone,
                          previous_calls=previous_calls,
                          script=script,
                          today_calls=len(today_calls),
                          today_sales=sum(1 for c in today_calls if c.disposition == 'sale'),
                          today_termin=sum(1 for c in today_calls if c.disposition == 'termin'),
                          today_keine=sum(1 for c in today_calls if c.disposition == 'keine'),
                          today=datetime.now().strftime('%Y-%m-%d'))


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
    
    # Stats hesapla
    total_evaluations = QAEvaluation.query.filter_by(tenant_id=current_user.tenant_id).count()
    
    # Ortalama puan
    from sqlalchemy import func
    avg_result = db.session.query(func.avg(QAEvaluation.percentage)).filter_by(
        tenant_id=current_user.tenant_id
    ).scalar()
    avg_score = round(avg_result) if avg_result else 78
    
    stats = {
        'total_evaluations': total_evaluations,
        'avg_score': avg_score,
        'pending_count': len(unevaluated_calls)
    }
    
    return render_template('qa/dashboard.html', 
                          recent_evaluations=recent_evaluations,
                          unevaluated_calls=unevaluated_calls,
                          stats=stats)


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

def get_tenant_id_for_ai():
    """Super Admin için varsayılan tenant_id döndürür, aksi halde kullanıcının tenant_id'sini döndürür"""
    if current_user.is_super_admin:
        # Super admin için demo tenant'ı kullan
        demo_tenant = Tenant.query.first()
        return demo_tenant.id if demo_tenant else 1
    return current_user.tenant_id


@app.route('/ai')
@login_required
@admin_required
def ai_panel():
    """AI yönetim paneli"""
    tenant_id = get_tenant_id_for_ai()
    settings = AISettings.query.filter_by(tenant_id=tenant_id).first()
    knowledge_bases = KnowledgeBase.query.filter_by(tenant_id=tenant_id).all()
    return render_template('ai/panel.html', settings=settings, knowledge_bases=knowledge_bases)


@app.route('/ai/settings', methods=['GET', 'POST'])
@login_required
@admin_required
def ai_settings():
    """AI ayarları"""
    tenant_id = get_tenant_id_for_ai()
    settings = AISettings.query.filter_by(tenant_id=tenant_id).first()
    
    if not settings:
        settings = AISettings(tenant_id=tenant_id)
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
    tenant_id = get_tenant_id_for_ai()
    kbs = KnowledgeBase.query.filter_by(tenant_id=tenant_id).all()
    return render_template('ai/knowledge_base.html', knowledge_bases=kbs)


@app.route('/ai/dashboard')
@login_required
@admin_required
def ai_dashboard():
    """AI Dashboard - Performans ve kullanım izleme"""
    tenant_id = get_tenant_id_for_ai()
    settings = AISettings.query.filter_by(tenant_id=tenant_id).first()
    if not settings:
        settings = AISettings(tenant_id=tenant_id)
        db.session.add(settings)
        db.session.commit()
    
    # AI kullanım istatistikleri
    ai_stats = {
        'transcription_minutes': 245,
        'summaries_generated': 156,
        'qa_evaluations': 89,
        'total_cost': 127.50
    }
    
    # AI içgörüleri
    ai_insights = {
        'time_saved': 45,
        'qa_improvement': 12,
        'satisfaction_increase': 8,
        'risks_detected': 3
    }
    
    # Son aktiviteler
    recent_activities = [
        {'type': 'transcription', 'title': 'Çağrı Transkripti', 'detail': 'Çağrı #1234 metne dönüştürüldü', 'created_at': 'az önce'},
        {'type': 'summary', 'title': 'Özet Üretildi', 'detail': 'Çağrı #1233 için özet oluşturuldu', 'created_at': '5 dk önce'},
        {'type': 'qa', 'title': 'QA Değerlendirme', 'detail': 'Agent Ali için %85 skor', 'created_at': '10 dk önce'},
    ]
    
    return render_template('ai/dashboard.html', 
                         ai_settings=settings,
                         ai_stats=ai_stats,
                         ai_insights=ai_insights,
                         recent_activities=recent_activities)


@app.route('/ai/settings/full', methods=['GET', 'POST'])
@login_required
@admin_required
def ai_settings_full():
    """AI ayarları - Tam versiyon"""
    tenant_id = get_tenant_id_for_ai()
    settings = AISettings.query.filter_by(tenant_id=tenant_id).first()
    if not settings:
        settings = AISettings(tenant_id=tenant_id)
        db.session.add(settings)
        db.session.commit()
    
    ai_packages = []  # AIPackage.query.filter_by(is_active=True).all()
    current_package = None
    
    return render_template('ai/settings_full.html', 
                         ai_settings=settings,
                         ai_packages=ai_packages,
                         current_package=current_package)


@app.route('/ai/settings/save', methods=['POST'])
@login_required
@admin_required
def ai_settings_save():
    """AI ayarlarını kaydet"""
    tenant_id = get_tenant_id_for_ai()
    settings = AISettings.query.filter_by(tenant_id=tenant_id).first()
    if not settings:
        settings = AISettings(tenant_id=tenant_id)
        db.session.add(settings)
    
    # STT ayarları
    settings.stt_provider = request.form.get('stt_provider', 'whisper')
    settings.stt_model = request.form.get('stt_model', 'base')
    settings.stt_language = request.form.get('default_language', 'tr')
    settings.stt_secondary_language = request.form.get('secondary_language', 'de')
    
    # TTS ayarları
    settings.tts_provider = request.form.get('tts_provider', 'elevenlabs')
    settings.tts_voice_id = request.form.get('tts_voice_id')
    settings.tts_language = request.form.get('tts_language', 'tr')
    settings.tts_speed = float(request.form.get('tts_speed', 1.0))
    
    # LLM ayarları
    settings.llm_provider = request.form.get('llm_provider', 'openai')
    settings.llm_model = request.form.get('llm_model', 'gpt-4')
    settings.llm_temperature = float(request.form.get('llm_temperature', 0.3))
    settings.llm_max_tokens = int(request.form.get('llm_max_tokens', 2000))
    
    # Özellikler - Genel
    settings.auto_transcription_enabled = 'auto_transcription' in request.form
    settings.auto_summary_enabled = 'auto_summary' in request.form
    settings.sentiment_analysis_enabled = 'sentiment_analysis' in request.form
    settings.topic_detection_enabled = 'topic_detection' in request.form
    settings.keyword_extraction_enabled = 'keyword_extraction' in request.form
    settings.next_action_suggestions = 'next_action_suggestions' in request.form
    
    # Özellikler - Agent
    settings.agent_assist_enabled = 'agent_assist' in request.form
    settings.realtime_script_suggestions = 'realtime_script' in request.form
    settings.objection_handling_enabled = 'objection_handling' in request.form
    
    # Özellikler - QA
    settings.auto_qa_enabled = 'auto_qa' in request.form
    settings.kvkk_compliance_check = 'kvkk_compliance' in request.form
    settings.forbidden_words_enabled = 'forbidden_words' in request.form
    settings.aggressive_language_detection = 'aggressive_detection' in request.form
    
    # Özellikler - Routing & Dialer
    settings.smart_routing_enabled = 'smart_routing' in request.form
    settings.intent_detection_enabled = 'intent_detection' in request.form
    settings.lead_scoring_enabled = 'lead_scoring' in request.form
    settings.best_time_to_call = 'best_time_to_call' in request.form
    settings.predictive_dialer_ai = 'predictive_dialer_ai' in request.form
    
    # Özellikler - Voice Bot & VIP
    settings.voice_bot_enabled = 'voice_bot' in request.form
    settings.vip_detection_enabled = 'vip_detection' in request.form
    settings.churn_prediction_enabled = 'churn_prediction' in request.form
    
    # Uyum ayarları
    settings.mask_credit_card = 'mask_credit_card' in request.form
    settings.mask_tc_no = 'mask_tc_no' in request.form
    settings.mask_phone = 'mask_phone' in request.form
    settings.mask_email = 'mask_email' in request.form
    
    settings.sentiment_alert_threshold = float(request.form.get('sentiment_alert_threshold', -0.5))
    settings.qa_auto_fail_threshold = float(request.form.get('qa_auto_fail_threshold', 50))
    settings.confidence_threshold = float(request.form.get('confidence_threshold', 0.7))
    
    # Yasaklı kelimeler
    forbidden_words_list = request.form.get('forbidden_words_list', '')
    if forbidden_words_list:
        settings.forbidden_words = [w.strip() for w in forbidden_words_list.split('\n') if w.strip()]
    
    # Promptlar
    settings.summary_template = request.form.get('summary_template')
    settings.agent_assist_prompt = request.form.get('agent_assist_prompt')
    
    db.session.commit()
    flash('AI ayarları başarıyla kaydedildi.', 'success')
    return redirect(url_for('ai_settings_full'))


@app.route('/ai/logs')
@login_required
@admin_required
def ai_logs():
    """AI işlem logları"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    tenant_id = get_tenant_id_for_ai()
    
    # AIUsage modelinden logları çek
    query = AIUsage.query.filter_by(tenant_id=tenant_id)
    
    # Filtreler
    usage_type = request.args.get('type')
    if usage_type:
        query = query.filter_by(usage_type=usage_type)
    
    date_from = request.args.get('date_from')
    if date_from:
        query = query.filter(AIUsage.usage_date >= date_from)
    
    date_to = request.args.get('date_to')
    if date_to:
        query = query.filter(AIUsage.usage_date <= date_to)
    
    ai_logs = query.order_by(AIUsage.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    # Kullanım dağılımı
    usage_distribution = {
        'transcription': 35,
        'summary': 25,
        'qa': 15,
        'suggestion': 10,
        'routing': 10,
        'voice_bot': 5
    }
    
    # Maliyet özeti
    cost_summary = {
        'transcription': 45.20,
        'llm': 62.30,
        'voice_bot': 20.00,
        'total': 127.50
    }
    
    return render_template('ai/logs.html',
                         ai_logs=ai_logs.items,
                         pagination=ai_logs,
                         usage_distribution=usage_distribution,
                         cost_summary=cost_summary)


@app.route('/ai/voice-bot')
@login_required
@admin_required
def ai_voice_bot():
    """Voice Bot yönetimi"""
    tenant_id = get_tenant_id_for_ai()
    voice_bots = AIVoiceBot.query.filter_by(tenant_id=tenant_id).all()
    active_bots = len([b for b in voice_bots if b.is_active])
    
    recent_sessions = AIVoiceBotSession.query.filter_by(
        tenant_id=tenant_id
    ).order_by(AIVoiceBotSession.started_at.desc()).limit(20).all()
    
    projects = Project.query.filter_by(tenant_id=tenant_id).all()
    queues = Queue.query.filter_by(tenant_id=tenant_id).all()
    knowledge_bases = KnowledgeBase.query.filter_by(tenant_id=tenant_id).all()
    
    return render_template('ai/voice_bot.html',
                         voice_bots=voice_bots,
                         active_bots=active_bots,
                         today_sessions=len(recent_sessions),
                         resolution_rate=72,
                         recent_sessions=recent_sessions,
                         projects=projects,
                         queues=queues,
                         knowledge_bases=knowledge_bases)


@app.route('/ai/voice-bot/save', methods=['POST'])
@login_required
@admin_required
def ai_voice_bot_save():
    """Voice Bot kaydet"""
    tenant_id = get_tenant_id_for_ai()
    bot_id = request.form.get('bot_id')
    
    if bot_id:
        bot = AIVoiceBot.query.get(bot_id)
    else:
        bot = AIVoiceBot(tenant_id=tenant_id)
        db.session.add(bot)
    
    bot.name = request.form.get('name')
    bot.description = request.form.get('description')
    bot.language = request.form.get('language', 'tr')
    bot.voice_id = request.form.get('voice_id')
    bot.voice_name = request.form.get('voice_name')
    bot.speed = float(request.form.get('speed', 1.0))
    
    bot.greeting_message = request.form.get('greeting_message')
    bot.fallback_message = request.form.get('fallback_message')
    bot.transfer_message = request.form.get('transfer_message')
    bot.goodbye_message = request.form.get('goodbye_message')
    
    bot.max_turns = int(request.form.get('max_turns', 5))
    bot.transfer_on_frustration = 'transfer_on_frustration' in request.form
    
    transfer_queue_id = request.form.get('transfer_queue_id')
    if transfer_queue_id:
        bot.transfer_queue_id = int(transfer_queue_id)
    
    knowledge_base_id = request.form.get('knowledge_base_id')
    if knowledge_base_id:
        bot.knowledge_base_id = int(knowledge_base_id)
    
    project_id = request.form.get('project_id')
    if project_id:
        bot.project_id = int(project_id)
    
    bot.active_hours_start = request.form.get('active_hours_start')
    bot.active_hours_end = request.form.get('active_hours_end')
    
    db.session.commit()
    flash('Voice Bot kaydedildi.', 'success')
    return redirect(url_for('ai_voice_bot'))


@app.route('/ai/voice-bot/sessions')
@login_required
@admin_required
def ai_voice_bot_sessions():
    """Voice Bot oturumları"""
    sessions = AIVoiceBotSession.query.filter_by(
        tenant_id=current_user.tenant_id
    ).order_by(AIVoiceBotSession.started_at.desc()).all()
    
    return render_template('ai/voice_bot_sessions.html', sessions=sessions)


@app.route('/ai/packages')
@login_required
@admin_required
def ai_packages():
    """AI paketleri"""
    packages = AIPackage.query.filter_by(is_active=True).all()
    return render_template('ai/packages.html', packages=packages)


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


# ==================== BILLING ROUTES ====================

@app.route('/billing/plans')
@login_required
@super_admin_required
def billing_plans():
    """Fiyatlandırma planları yönetimi"""
    plans = BillingPlan.query.all()
    return render_template('billing/plans.html', plans=plans)


@app.route('/billing/plans/new', methods=['GET', 'POST'])
@login_required
@super_admin_required
def billing_plan_new():
    """Yeni fiyat planı oluştur"""
    if request.method == 'POST':
        plan = BillingPlan(
            code=request.form.get('code'),
            name=request.form.get('name'),
            description=request.form.get('description'),
            price_monthly=request.form.get('price_monthly', type=float),
            price_yearly=request.form.get('price_yearly', type=float),
            price_per_agent=request.form.get('price_per_agent', type=float),
            included_agents=request.form.get('included_agents', type=int),
            max_agents=request.form.get('max_agents', type=int),
            max_concurrent_calls=request.form.get('max_concurrent_calls', type=int),
            storage_gb=request.form.get('storage_gb', type=int),
            recording_retention_days=request.form.get('recording_retention_days', type=int)
        )
        db.session.add(plan)
        db.session.commit()
        flash('Plan başarıyla oluşturuldu.', 'success')
        return redirect(url_for('billing_plans'))
    return render_template('billing/plan_form.html', plan=None)


@app.route('/billing/tariffs')
@login_required
@super_admin_required
def billing_tariffs():
    """VoIP tarifeleri yönetimi"""
    tariffs = VoIPTariff.query.all()
    return render_template('billing/tariffs.html', tariffs=tariffs)


@app.route('/billing/tariffs/new', methods=['GET', 'POST'])
@login_required
@super_admin_required
def billing_tariff_new():
    """Yeni VoIP tarifesi oluştur"""
    if request.method == 'POST':
        tariff = VoIPTariff(
            code=request.form.get('code'),
            name=request.form.get('name'),
            description=request.form.get('description'),
            default_rate_inbound=request.form.get('rate_inbound', type=float),
            default_rate_outbound=request.form.get('rate_outbound', type=float),
            connection_fee=request.form.get('connection_fee', type=float),
            billing_increment=request.form.get('billing_increment', type=int)
        )
        db.session.add(tariff)
        db.session.commit()
        flash('Tarife başarıyla oluşturuldu.', 'success')
        return redirect(url_for('billing_tariffs'))
    return render_template('billing/tariff_form.html', tariff=None)


@app.route('/billing/tariffs/<int:tariff_id>/rates')
@login_required
@super_admin_required
def billing_tariff_rates(tariff_id):
    """Tarife fiyat detayları"""
    tariff = VoIPTariff.query.get_or_404(tariff_id)
    rates = tariff.rates.all()
    return render_template('billing/tariff_rates.html', tariff=tariff, rates=rates)


@app.route('/billing/invoices')
@login_required
@super_admin_required
def billing_invoices():
    """Tüm faturaları listele"""
    invoices = Invoice.query.order_by(Invoice.created_at.desc()).all()
    return render_template('billing/invoices.html', invoices=invoices)


@app.route('/billing/payments')
@login_required
@super_admin_required
def billing_payments():
    """Tüm ödemeleri listele"""
    payments = Payment.query.order_by(Payment.created_at.desc()).all()
    return render_template('billing/payments.html', payments=payments)


# ==================== CC ADMIN PANEL ROUTES ====================

@app.route('/cc/settings')
@login_required
@admin_required
def cc_settings():
    """CC Kurum Ayarları"""
    tenant = Tenant.query.get(current_user.tenant_id)
    settings = TenantSettings.query.filter_by(tenant_id=current_user.tenant_id).first()
    billing_info = TenantBillingInfo.query.filter_by(tenant_id=current_user.tenant_id).first()
    branding = TenantBranding.query.filter_by(tenant_id=current_user.tenant_id).first()
    return render_template('cc_admin/settings.html', 
                          tenant=tenant, 
                          settings=settings, 
                          billing_info=billing_info,
                          branding=branding)


@app.route('/cc/settings/update', methods=['POST'])
@login_required
@admin_required
def cc_settings_update():
    """CC Kurum Ayarlarını Güncelle"""
    tenant = Tenant.query.get(current_user.tenant_id)
    if tenant:
        tenant.name = request.form.get('name')
        tenant.timezone = request.form.get('timezone')
        tenant.language = request.form.get('language')
        db.session.commit()
        flash('Kurum ayarları güncellendi.', 'success')
    return redirect(url_for('cc_settings'))


@app.route('/cc/billing')
@login_required
@admin_required
def cc_billing():
    """CC Faturalama ve Kullanım"""
    subscription = TenantSubscription.query.filter_by(tenant_id=current_user.tenant_id).first()
    billing_info = TenantBillingInfo.query.filter_by(tenant_id=current_user.tenant_id).first()
    invoices = Invoice.query.filter_by(tenant_id=current_user.tenant_id).order_by(Invoice.created_at.desc()).limit(10).all()
    
    # Kullanım özeti
    from datetime import date
    today = date.today()
    current_month_start = today.replace(day=1)
    usage = UsageSummary.query.filter(
        UsageSummary.tenant_id == current_user.tenant_id,
        UsageSummary.period_type == 'daily',
        UsageSummary.period_date >= current_month_start
    ).all()
    
    return render_template('cc_admin/billing.html',
                          subscription=subscription,
                          billing_info=billing_info,
                          invoices=invoices,
                          usage=usage)


@app.route('/cc/voip')
@login_required
@admin_required
def cc_voip():
    """CC VoIP Ayarları ve Durumu"""
    voip_config = TenantVoIPConfig.query.filter_by(tenant_id=current_user.tenant_id).first()
    quota = TenantQuota.query.filter_by(tenant_id=current_user.tenant_id).first()
    
    # Atanmış DID'ler
    dids = DIDPool.query.filter_by(tenant_id=current_user.tenant_id).all()
    
    # Atanmış CLI'lar
    cli_assignments = TenantCLIAssignment.query.filter_by(tenant_id=current_user.tenant_id).all()
    
    return render_template('cc_admin/voip.html',
                          voip_config=voip_config,
                          quota=quota,
                          dids=dids,
                          cli_assignments=cli_assignments)


@app.route('/cc/usage')
@login_required
@admin_required
def cc_usage():
    """CC Kullanım Detayları"""
    from datetime import date, timedelta
    
    # Tarih aralığı
    end_date = date.today()
    start_date = end_date - timedelta(days=30)
    
    # Günlük kullanım
    daily_usage = UsageSummary.query.filter(
        UsageSummary.tenant_id == current_user.tenant_id,
        UsageSummary.period_type == 'daily',
        UsageSummary.period_date >= start_date
    ).order_by(UsageSummary.period_date.desc()).all()
    
    # Kota durumu
    quota = TenantQuota.query.filter_by(tenant_id=current_user.tenant_id).first()
    
    return render_template('cc_admin/usage.html',
                          daily_usage=daily_usage,
                          quota=quota,
                          start_date=start_date,
                          end_date=end_date)


@app.route('/cc/support')
@login_required
@admin_required
def cc_support():
    """CC Destek Talepleri"""
    tickets = []
    announcements = []
    
    try:
        # Super admin tüm ticketları görebilir
        if current_user.is_super_admin:
            tickets = SupportTicket.query.order_by(SupportTicket.created_at.desc()).limit(50).all()
        elif current_user.tenant_id:
            tickets = SupportTicket.query.filter_by(tenant_id=current_user.tenant_id).order_by(SupportTicket.created_at.desc()).all()
    except Exception as e:
        app.logger.error(f"Support tickets error: {str(e)}")
        db.session.rollback()
    
    try:
        announcements = SystemAnnouncement.query.filter(
            SystemAnnouncement.is_public == True,
            (SystemAnnouncement.expires_at == None) | (SystemAnnouncement.expires_at > datetime.utcnow())
        ).order_by(SystemAnnouncement.publish_at.desc()).limit(5).all()
    except Exception as e:
        app.logger.error(f"Announcements error: {str(e)}")
        db.session.rollback()
    
    return render_template('cc_admin/support.html',
                          tickets=tickets,
                          announcements=announcements)


@app.route('/cc/support/new', methods=['GET', 'POST'])
@login_required
@admin_required
def cc_support_new():
    """Yeni destek talebi oluştur"""
    if request.method == 'POST':
        import random
        ticket = SupportTicket(
            tenant_id=current_user.tenant_id,
            ticket_number=f'TKT-{random.randint(100000, 999999)}',
            subject=request.form.get('subject'),
            description=request.form.get('description'),
            category=request.form.get('category'),
            priority=request.form.get('priority', 'normal'),
            created_by_id=current_user.id
        )
        db.session.add(ticket)
        db.session.commit()
        flash('Destek talebiniz oluşturuldu.', 'success')
        return redirect(url_for('cc_support'))
    return render_template('cc_admin/support_form.html')


# ==================== PROVISIONING ROUTES (SUPER ADMIN) ====================

@app.route('/provisioning/dids')
@login_required
@super_admin_required
def provisioning_dids():
    """DID Havuzu Yönetimi"""
    dids = DIDPool.query.all()
    tenants = Tenant.query.filter_by(status='active').all()
    return render_template('provisioning/dids.html', dids=dids, tenants=tenants)


@app.route('/provisioning/dids/assign', methods=['POST'])
@login_required
@super_admin_required
def provisioning_did_assign():
    """DID'i tenant'a ata"""
    did_id = request.form.get('did_id', type=int)
    tenant_id = request.form.get('tenant_id', type=int)
    
    did = DIDPool.query.get_or_404(did_id)
    did.tenant_id = tenant_id
    did.assigned_at = datetime.utcnow()
    did.status = 'assigned' if tenant_id else 'available'
    db.session.commit()
    
    flash('DID ataması güncellendi.', 'success')
    return redirect(url_for('provisioning_dids'))


@app.route('/provisioning/cli')
@login_required
@super_admin_required
def provisioning_cli():
    """CLI Havuzu Yönetimi"""
    clis = CLIPool.query.all()
    tenants = Tenant.query.filter_by(status='active').all()
    return render_template('provisioning/cli.html', clis=clis, tenants=tenants)


@app.route('/provisioning/trunks')
@login_required
@super_admin_required
def provisioning_trunks():
    """Trunk Tahsis Yönetimi"""
    allocations = TrunkAllocation.query.all()
    trunks = SIPTrunk.query.all()
    tenants = Tenant.query.filter_by(status='active').all()
    return render_template('provisioning/trunks.html', 
                          allocations=allocations, 
                          trunks=trunks, 
                          tenants=tenants)


@app.route('/provisioning/quotas')
@login_required
@super_admin_required
def provisioning_quotas():
    """Tenant Kota Yönetimi"""
    quotas = TenantQuota.query.all()
    tenants = Tenant.query.all()
    return render_template('provisioning/quotas.html', quotas=quotas, tenants=tenants)


@app.route('/provisioning/quotas/<int:tenant_id>/edit', methods=['GET', 'POST'])
@login_required
@super_admin_required
def provisioning_quota_edit(tenant_id):
    """Tenant kotalarını düzenle"""
    quota = TenantQuota.query.filter_by(tenant_id=tenant_id).first()
    tenant = Tenant.query.get_or_404(tenant_id)
    
    if not quota:
        quota = TenantQuota(tenant_id=tenant_id)
        db.session.add(quota)
        db.session.commit()
    
    if request.method == 'POST':
        quota.max_agents = request.form.get('max_agents', type=int)
        quota.max_supervisors = request.form.get('max_supervisors', type=int)
        quota.max_projects = request.form.get('max_projects', type=int)
        quota.max_concurrent_inbound = request.form.get('max_concurrent_inbound', type=int)
        quota.max_concurrent_outbound = request.form.get('max_concurrent_outbound', type=int)
        quota.storage_quota_gb = request.form.get('storage_quota_gb', type=int)
        quota.recording_retention_days = request.form.get('recording_retention_days', type=int)
        quota.ai_monthly_minutes = request.form.get('ai_monthly_minutes', type=int)
        db.session.commit()
        flash('Kotalar güncellendi.', 'success')
        return redirect(url_for('provisioning_quotas'))
    
    return render_template('provisioning/quota_form.html', quota=quota, tenant=tenant)


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
