"""
Bee Life Consulting CC - Kullanıcı ve Proje Seed Script
Çalıştırma: python seed_beelife.py
"""

from app import app, db
from models import User, Tenant, Project, ProjectUser
from werkzeug.security import generate_password_hash
from datetime import datetime
import random
import string

def generate_password():
    """Güvenli şifre oluştur"""
    chars = string.ascii_letters + string.digits + "!@#$"
    return ''.join(random.choice(chars) for _ in range(10))

def generate_username(name):
    """İsimden kullanıcı adı oluştur"""
    # Türkçe karakterleri değiştir
    tr_chars = {'ı': 'i', 'ğ': 'g', 'ü': 'u', 'ş': 's', 'ö': 'o', 'ç': 'c',
                'İ': 'I', 'Ğ': 'G', 'Ü': 'U', 'Ş': 'S', 'Ö': 'O', 'Ç': 'C'}
    for tr, en in tr_chars.items():
        name = name.replace(tr, en)
    
    parts = name.lower().split()
    if len(parts) >= 2:
        # İlk isim + soyisim
        username = parts[0] + "." + parts[-1]
    else:
        username = parts[0]
    
    return username.strip()

def main():
    with app.app_context():
        print("=" * 60)
        print("🐝 BEE LIFE CONSULTING CC - KURULUM BAŞLIYOR")
        print("=" * 60)
        
        # 1. Tenant Oluştur
        print("\n📦 Tenant oluşturuluyor...")
        tenant = Tenant.query.filter_by(code='BEELIFE').first()
        if not tenant:
            tenant = Tenant(
                code='BEELIFE',
                name='Bee Life Consulting CC',
                status='active',
                max_agents=50,
                max_concurrent_calls=30,
                created_at=datetime.utcnow()
            )
            db.session.add(tenant)
            db.session.commit()
            print(f"   ✅ Tenant oluşturuldu: {tenant.name} (ID: {tenant.id})")
        else:
            print(f"   ℹ️  Tenant zaten mevcut: {tenant.name} (ID: {tenant.id})")
        
        # 2. Projeleri Oluştur
        print("\n📂 Projeler oluşturuluyor...")
        projects_data = {
            'EMS': {'name': 'Europe Mega Service', 'code': 'EMS', 'sector': 'Finans'},
            'MPS': {'name': 'Mega Promo Service', 'code': 'MPS', 'sector': 'Gewinnspiel'}
        }
        
        project_objs = {}
        for key, proj_data in projects_data.items():
            project = Project.query.filter_by(code=proj_data['code'], tenant_id=tenant.id).first()
            if not project:
                project = Project(
                    code=proj_data['code'],
                    name=proj_data['name'],
                    tenant_id=tenant.id,
                    sector=proj_data['sector'],
                    campaign_type='outbound',
                    status='active',
                    created_at=datetime.utcnow()
                )
                db.session.add(project)
                db.session.commit()
                print(f"   ✅ Proje oluşturuldu: {project.name} ({project.code})")
            else:
                print(f"   ℹ️  Proje zaten mevcut: {project.name}")
            project_objs[key] = project
        
        # 3. Kullanıcıları Tanımla
        users_data = []
        
        # Super Admin - Ferhat Açıkgöz
        users_data.append({
            'name': 'Ferhat Açıkgöz',
            'role': 'super_admin',
            'project': None,
            'is_super_admin': True
        })
        
        # Supervisor - Ayhan Yıldızdoğan
        users_data.append({
            'name': 'Ayhan Yıldızdoğan',
            'role': 'supervisor',
            'project': None,  # Tüm projeleri görecek
            'is_super_admin': False
        })
        
        # QC Dinleme Ekibi
        qc_team = ['Ahmet Kömür', 'Hatice Yıldız', 'Meral Taşdoğan']
        for name in qc_team:
            users_data.append({
                'name': name,
                'role': 'qc_listener',
                'project': None,
                'is_super_admin': False
            })
        
        # Agentler - EMS Projesi
        ems_agents = [
            'Abdulcelil Arslan',
            'Aslı Akdoğan',
            'Eda Nur Bağır Hatipoğlu',
            'Erdoğan Çuvoğlu',
            'Fatma Karipçin',
            'Gönül Dağ',
            'Gülay Dikmen',
            'Hilal Coşkun',
            'Leyla Doğan',
            'Nihat Kedi',
            'Selma Delioğlu',
            'Şeyda Uludağ',
            'Tuncay Karaca',
            'Turgay Yumrukaya',
            'Yücel Gökçe',
            'Yüksel Taşkın'
        ]
        for name in ems_agents:
            users_data.append({
                'name': name,
                'role': 'agent',
                'project': 'EMS',
                'is_super_admin': False
            })
        
        # Agent - MPS Projesi
        users_data.append({
            'name': 'Taner Turan',
            'role': 'agent',
            'project': 'MPS',
            'is_super_admin': False
        })
        
        # 4. Kullanıcıları Oluştur
        print("\n👥 Kullanıcılar oluşturuluyor...")
        print("-" * 80)
        
        created_users = []
        
        for user_data in users_data:
            username = generate_username(user_data['name'])
            email = f"{username}@beelife-cc.com"
            password = generate_password()
            
            # Kullanıcı zaten var mı kontrol et
            existing = User.query.filter_by(username=username).first()
            if existing:
                print(f"   ⚠️  {user_data['name']} zaten mevcut (username: {username})")
                continue
            
            # İsim parçala
            name_parts = user_data['name'].split()
            first_name = name_parts[0]
            last_name = ' '.join(name_parts[1:]) if len(name_parts) > 1 else ''
            
            # Yeni kullanıcı oluştur
            user = User(
                username=username,
                email=email,
                first_name=first_name,
                last_name=last_name,
                full_name=user_data['name'],
                german_first_name=None,  # Sonradan eklenecek
                german_last_name=None,
                password_hash=generate_password_hash(password),
                role=user_data['role'],
                tenant_id=tenant.id,
                is_active=True,
                is_super_admin=user_data['is_super_admin'],
                created_at=datetime.utcnow()
            )
            
            db.session.add(user)
            db.session.flush()  # ID almak için
            
            # Proje ataması (ProjectUser tablosu üzerinden)
            if user_data['project']:
                project = project_objs.get(user_data['project'])
                if project:
                    project_user = ProjectUser(
                        project_id=project.id,
                        user_id=user.id,
                        role=user_data['role'],
                        can_view_recordings=True,
                        can_export_data=user_data['role'] in ['supervisor', 'admin'],
                        can_edit_customers=True,
                        assigned_at=datetime.utcnow()
                    )
                    db.session.add(project_user)
            
            # Bilgileri kaydet
            created_users.append({
                'name': user_data['name'],
                'username': username,
                'password': password,
                'email': email,
                'role': user_data['role'],
                'project': user_data['project'] or 'Tümü'
            })
        
        db.session.commit()
        
        # 5. Sonuçları Göster
        print("\n" + "=" * 100)
        print("📋 OLUŞTURULAN KULLANICILAR - BEE LIFE CONSULTING CC")
        print("=" * 100)
        print(f"{'İsim':<28} {'Kullanıcı Adı':<22} {'Şifre':<14} {'Rol':<15} {'Proje':<10}")
        print("-" * 100)
        
        role_translations = {
            'super_admin': 'Super Admin',
            'supervisor': 'Supervisor',
            'qc_listener': 'QC Dinleme',
            'agent': 'Agent',
            'admin': 'Admin'
        }
        
        # Önce yöneticileri göster
        for u in created_users:
            if u['role'] in ['super_admin', 'supervisor', 'qc_listener']:
                role_tr = role_translations.get(u['role'], u['role'])
                print(f"{u['name']:<28} {u['username']:<22} {u['password']:<14} {role_tr:<15} {u['project']:<10}")
        
        print("-" * 100)
        
        # Sonra agentleri göster
        for u in created_users:
            if u['role'] == 'agent':
                role_tr = role_translations.get(u['role'], u['role'])
                print(f"{u['name']:<28} {u['username']:<22} {u['password']:<14} {role_tr:<15} {u['project']:<10}")
        
        print("-" * 100)
        print(f"\n✅ Toplam {len(created_users)} kullanıcı oluşturuldu!")
        print(f"🏢 Tenant: Bee Life Consulting CC")
        print(f"📂 Projeler: EMS (Europe Mega Service), MPS (Mega Promo Service)")
        
        # CSV olarak kaydet
        print("\n📄 Kullanıcı listesi 'beelife_users.csv' dosyasına kaydediliyor...")
        with open('beelife_users.csv', 'w', encoding='utf-8-sig') as f:
            f.write("İsim;Kullanıcı Adı;Şifre;Email;Rol;Proje\n")
            for u in created_users:
                role_tr = role_translations.get(u['role'], u['role'])
                f.write(f"{u['name']};{u['username']};{u['password']};{u['email']};{role_tr};{u['project']}\n")
        print("   ✅ CSV dosyası oluşturuldu (Excel ile açılabilir)")
        
        # Özet
        print("\n" + "=" * 60)
        print("📊 ÖZET")
        print("=" * 60)
        print(f"   Super Admin: 1 (Ferhat Açıkgöz)")
        print(f"   Supervisor:  1 (Ayhan Yıldızdoğan)")
        print(f"   QC Dinleme:  3 (Ahmet, Hatice, Meral)")
        print(f"   Agent EMS:   16")
        print(f"   Agent MPS:   1 (Taner Turan)")
        print(f"   ─────────────────")
        print(f"   TOPLAM:      22 kullanıcı")
        
        print("\n" + "=" * 60)
        print("🎉 KURULUM TAMAMLANDI!")
        print("=" * 60)
        print("\n⚠️  ÖNEMLİ: Bu şifreleri güvenli bir yerde saklayın!")
        print("   CSV dosyası: beelife_users.csv\n")

if __name__ == '__main__':
    main()
