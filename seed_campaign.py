#!/usr/bin/env python3
"""
BEE LIFE CONSULTING Kampanya ve Projeler Seed Script
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from models import Tenant, Project, Campaign, User

def seed_campaign():
    with app.app_context():
        # Tenant bul veya oluştur
        tenant = Tenant.query.filter_by(name='Bee Life Consulting CC').first()
        if not tenant:
            tenant = Tenant.query.first()  # İlk tenant'ı kullan
            if not tenant:
                print("❌ Tenant bulunamadı!")
                return
        
        print(f"✅ Tenant: {tenant.name} (ID: {tenant.id})")
        
        # Projeleri oluştur
        # 1. EMS - Europe Mega Service
        ems_project = Project.query.filter_by(name='EMS - Europe Mega Service', tenant_id=tenant.id).first()
        if not ems_project:
            ems_project = Project(
                tenant_id=tenant.id,
                name='EMS - Europe Mega Service',
                code='EMS',
                description='Europe Mega Service - Avrupa genelinde hizmet',
                status='active'
            )
            db.session.add(ems_project)
            db.session.flush()
            print(f"✅ Proje oluşturuldu: EMS - Europe Mega Service (ID: {ems_project.id})")
        else:
            print(f"ℹ️ Proje zaten var: EMS (ID: {ems_project.id})")
        
        # 2. MPS - Mega Promo Service
        mps_project = Project.query.filter_by(name='MPS - Mega Promo Service', tenant_id=tenant.id).first()
        if not mps_project:
            mps_project = Project(
                tenant_id=tenant.id,
                name='MPS - Mega Promo Service',
                code='MPS',
                description='Mega Promo Service - Promosyon hizmetleri',
                status='active'
            )
            db.session.add(mps_project)
            db.session.flush()
            print(f"✅ Proje oluşturuldu: MPS - Mega Promo Service (ID: {mps_project.id})")
        else:
            print(f"ℹ️ Proje zaten var: MPS (ID: {mps_project.id})")
        
        # Ana Kampanya oluştur - BEE LIFE CONSULTING
        campaign = Campaign.query.filter_by(name='BEE LIFE CONSULTING', tenant_id=tenant.id).first()
        if not campaign:
            campaign = Campaign(
                tenant_id=tenant.id,
                project_id=ems_project.id,  # EMS projesine bağlı
                name='BEE LIFE CONSULTING',
                description='Bee Life Consulting ana kampanyası',
                dialer_type='preview',
                status='active'
            )
            db.session.add(campaign)
            db.session.flush()
            print(f"✅ Kampanya oluşturuldu: BEE LIFE CONSULTING (ID: {campaign.id})")
        else:
            print(f"ℹ️ Kampanya zaten var: BEE LIFE CONSULTING (ID: {campaign.id})")
        
        # EMS Kampanyası
        ems_campaign = Campaign.query.filter_by(name='EMS - Outbound Sales', tenant_id=tenant.id).first()
        if not ems_campaign:
            ems_campaign = Campaign(
                tenant_id=tenant.id,
                project_id=ems_project.id,
                name='EMS - Outbound Sales',
                description='Europe Mega Service Satış Kampanyası',
                dialer_type='progressive',
                status='active'
            )
            db.session.add(ems_campaign)
            print(f"✅ Kampanya oluşturuldu: EMS - Outbound Sales")
        
        # MPS Kampanyası
        mps_campaign = Campaign.query.filter_by(name='MPS - Promo Campaign', tenant_id=tenant.id).first()
        if not mps_campaign:
            mps_campaign = Campaign(
                tenant_id=tenant.id,
                project_id=mps_project.id,
                name='MPS - Promo Campaign',
                description='Mega Promo Service Promosyon Kampanyası',
                dialer_type='preview',
                status='active'
            )
            db.session.add(mps_campaign)
            print(f"✅ Kampanya oluşturuldu: MPS - Promo Campaign")
        
        db.session.commit()
        print("\n" + "="*50)
        print("✅ Tüm kampanya ve projeler başarıyla oluşturuldu!")
        print("="*50)
        
        # Özet
        print("\n📊 ÖZET:")
        print(f"   Tenant: {tenant.name}")
        print(f"   Projeler:")
        print(f"      - EMS - Europe Mega Service (ID: {ems_project.id})")
        print(f"      - MPS - Mega Promo Service (ID: {mps_project.id})")
        print(f"   Kampanyalar:")
        all_campaigns = Campaign.query.filter_by(tenant_id=tenant.id).all()
        for c in all_campaigns:
            print(f"      - {c.name} (ID: {c.id})")

if __name__ == '__main__':
    seed_campaign()

