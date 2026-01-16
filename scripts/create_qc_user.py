"""
Create QC listener user for testing/operations.

Usage (on VPS):
  cd /var/www/aibeecc
  source venv/bin/activate
  python scripts/create_qc_user.py --username ahmet.komur --full-name "Ahmet Kömür" --password "QcDinleme!2026"

Optional:
  --tenant-id 1
"""

import argparse

from app import app
from models import db, User, Tenant


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--username", required=True)
    p.add_argument("--full-name", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--email", default=None)
    p.add_argument("--tenant-id", type=int, default=None)
    args = p.parse_args()

    with app.app_context():
        tenant_id = args.tenant_id
        if tenant_id is None:
            t = Tenant.query.order_by(Tenant.id.asc()).first()
            if not t:
                raise SystemExit("No tenant found in DB. Create tenant first.")
            tenant_id = t.id

        user = User.query.filter_by(username=args.username).first()
        if user:
            user.full_name = args.full_name
            user.role = "qc_listener"
            user.tenant_id = tenant_id
            user.is_active = True
            if args.email:
                user.email = args.email
            user.set_password(args.password)
            db.session.commit()
            print(f"Updated existing user: {args.username} (tenant_id={tenant_id})")
            return

        user = User(
            tenant_id=tenant_id,
            username=args.username,
            email=args.email or f"{args.username}@ai-bee-cc.local",
            full_name=args.full_name,
            role="qc_listener",
            is_active=True,
        )
        user.set_password(args.password)
        db.session.add(user)
        db.session.commit()
        print(f"Created QC user: {args.username} (tenant_id={tenant_id})")


if __name__ == "__main__":
    main()

