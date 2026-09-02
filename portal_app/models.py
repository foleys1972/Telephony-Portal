from __future__ import annotations

from datetime import datetime

from flask_login import UserMixin

from .db import db


class User(UserMixin, db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")
    name = db.Column(db.String(200))

    is_active = db.Column(db.Boolean, default=True)
    disabled_date = db.Column(db.DateTime)
    disabled_by = db.Column(db.String(100))
    disable_reason = db.Column(db.String(500))
    must_change_password = db.Column(db.Boolean, default=False)
    can_approve_changes = db.Column(db.Boolean, default=False)
    can_provide_regional_approval = db.Column(db.Boolean, default=False)
    can_approve_global_service = db.Column(db.Boolean, default=False)

    can_approve_turret_moves = db.Column(db.Boolean, default=False)
    can_execute_turret_moves = db.Column(db.Boolean, default=False)
    can_import_turret_moves = db.Column(db.Boolean, default=False)
    can_export_turret_moves = db.Column(db.Boolean, default=False)

    can_import_private_wires = db.Column(db.Boolean, default=False)
    can_export_private_wires = db.Column(db.Boolean, default=False)

    last_activity = db.Column(db.DateTime)

    def is_admin(self) -> bool:
        return (self.role or "").lower() == "admin"

    def can_edit_inventory(self) -> bool:
        r = (self.role or "").lower()
        return r in {"admin", "user"}

    def can_edit_changes(self) -> bool:
        r = (self.role or "").lower()
        return r in {"admin", "user", "change_user"}

    def can_edit_incidents(self) -> bool:
        r = (self.role or "").lower()
        return r in {"admin", "user", "change_user"}


class ChangeRecord(db.Model):
    __tablename__ = "change_record"

    id = db.Column(db.Integer, primary_key=True)
    region = db.Column(db.String(100))
    cr_number = db.Column(db.String(50))
    title = db.Column(db.String(300))
    technology = db.Column(db.String(200))
    status = db.Column(db.String(50))

    ice_sent = db.Column(db.Boolean)
    ice_approved = db.Column(db.Boolean)
    coo_update = db.Column(db.String(200))
    change_category = db.Column(db.String(100))

    regional_approval = db.Column(db.String(200))
    regional_approval_status = db.Column(db.String(20))
    regional_approver_name = db.Column(db.String(100))

    risk_mitigation = db.Column(db.Text)
    snow_link = db.Column(db.String(500))
    bau_project = db.Column(db.String(50))
    raised_by = db.Column(db.String(100))
    tech_lead = db.Column(db.String(100))
    change_risk_level = db.Column(db.String(50))
    start_date = db.Column(db.DateTime)

    regular_change = db.Column(db.Boolean, default=False)
    rtc_cab = db.Column(db.Boolean, default=False)
    comments = db.Column(db.Text)

    approved = db.Column(db.Boolean, default=False)
    approved_by = db.Column(db.String(100))
    cab_date = db.Column(db.DateTime)
    approved_status = db.Column(db.String(20), default="No")

    raised_datetime = db.Column(db.DateTime)

    global_service_approval = db.Column(db.String(50))

    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    last_updated_by = db.Column(db.String(100))

    custom_fields_json = db.Column(db.Text)


class CeasedRMATurret(db.Model):
    __tablename__ = "ceased_rma_turret"

    id = db.Column(db.Integer, primary_key=True)
    original_turret_id = db.Column(db.Integer)

    moved_at = db.Column(db.DateTime)
    moved_by = db.Column(db.String(100))
    move_reason = db.Column(db.String(100))

    mac_address = db.Column(db.String(50))
    mac_address_2 = db.Column(db.String(50))
    mac_address_3 = db.Column(db.String(50))
    mac_address_4 = db.Column(db.String(50))
    mac_address_5 = db.Column(db.String(50))

    serial_number = db.Column(db.String(100))

    ip_address = db.Column(db.String(50))
    dns_hostname = db.Column(db.String(200))
    zone = db.Column(db.String(50))
    firmware_version = db.Column(db.String(50))
    model = db.Column(db.String(50))
    country = db.Column(db.String(50))
    office = db.Column(db.String(100))
    desk_location = db.Column(db.String(100))

    date_created = db.Column(db.DateTime)
    last_updated = db.Column(db.DateTime)
    last_change = db.Column(db.String(200))
    custom_fields_json = db.Column(db.Text)

    rma_date_sent = db.Column(db.DateTime)
    rma_date_received = db.Column(db.DateTime)
    dealerboard_issue = db.Column(db.String(100))
    summary = db.Column(db.String(100))


class AppSetting(db.Model):
    __tablename__ = "app_setting"

    key = db.Column(db.String(100), primary_key=True)
    value = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_by = db.Column(db.String(100))


class LookupOption(db.Model):
    __tablename__ = "lookup_option"

    id = db.Column(db.Integer, primary_key=True)
    group = db.Column("group", db.String(50), nullable=False)
    value = db.Column(db.String(200), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    sort_order = db.Column(db.Integer, default=0)
    created_date = db.Column(db.DateTime, default=datetime.utcnow)


class CabLock(db.Model):
    __tablename__ = "cab_lock"

    id = db.Column(db.Integer, primary_key=True)
    cab_monday = db.Column(db.Date, unique=True, nullable=False)
    is_locked = db.Column(db.Boolean, default=True)
    locked_by = db.Column(db.String(100))
    locked_at = db.Column(db.DateTime)


class CustomFieldDef(db.Model):
    __tablename__ = "custom_field_def"

    id = db.Column(db.Integer, primary_key=True)
    entity = db.Column(db.String(50), nullable=False)
    field_key = db.Column(db.String(100), nullable=False)
    label = db.Column(db.String(200), nullable=False)
    field_type = db.Column(db.String(50), nullable=False, default="text")
    sort_order = db.Column(db.Integer, default=0)
    is_required = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)


class Server(db.Model):
    __tablename__ = "server"

    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(200), unique=True, nullable=False)
    ip_address = db.Column(db.String(50))
    application = db.Column(db.String(200))
    role = db.Column(db.String(200))
    service = db.Column(db.String(200))
    db_server = db.Column(db.String(200))
    prod_dev = db.Column(db.String(50))
    country = db.Column(db.String(50))
    site = db.Column(db.String(200))
    verint_id = db.Column(db.String(100))
    os = db.Column(db.String(200))
    status = db.Column(db.String(100))
    hardware = db.Column(db.String(200))
    esxi_host = db.Column(db.String(200))
    server_type = db.Column(db.String(200))
    eol_date = db.Column(db.DateTime)

    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    last_updated_by = db.Column(db.String(100))


class CeasedServer(db.Model):
    __tablename__ = "ceased_server"

    id = db.Column(db.Integer, primary_key=True)
    original_server_id = db.Column(db.Integer)

    hostname = db.Column(db.String(200))
    ip_address = db.Column(db.String(50))
    application = db.Column(db.String(200))
    role = db.Column(db.String(200))
    service = db.Column(db.String(200))
    db_server = db.Column(db.String(200))
    prod_dev = db.Column(db.String(50))
    country = db.Column(db.String(50))
    site = db.Column(db.String(200))
    verint_id = db.Column(db.String(100))
    os = db.Column(db.String(200))
    status = db.Column(db.String(100))
    hardware = db.Column(db.String(200))
    esxi_host = db.Column(db.String(200))
    server_type = db.Column(db.String(200))
    eol_date = db.Column(db.DateTime)

    ceased_date = db.Column(db.DateTime)
    ceased_by = db.Column(db.String(100))
    cease_reason = db.Column(db.String(500))


class ActivityLogEntry(db.Model):
    __tablename__ = "activity_log"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    username = db.Column(db.String(100))
    action_type = db.Column(db.String(100))
    method = db.Column(db.String(20))
    path = db.Column(db.String(500))
    success = db.Column(db.Boolean, default=True)
    details = db.Column(db.String(1000))


class DDINumber(db.Model):
    __tablename__ = "ddi_number"

    id = db.Column(db.Integer, primary_key=True)
    ddi_number = db.Column(db.String(12), unique=True, nullable=False)
    username = db.Column(db.String(100))
    cisco_cluster = db.Column(db.String(100))
    bt_system = db.Column(db.String(50))
    location = db.Column(db.String(50))
    tpo = db.Column(db.String(100))
    status = db.Column(db.String(20), default="Active")
    date_spare = db.Column(db.DateTime)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    last_change = db.Column(db.String(200))

    # Added later via migration
    line_type = db.Column(db.String(50))
    tpo_dns_name = db.Column(db.String(100))
    voice_recording = db.Column(db.String(10))
    place = db.Column(db.String(100))
    slots = db.Column(db.String(50))
    virtual_slot_start = db.Column(db.String(50))
    virtual_slot_stop = db.Column(db.String(50))


class PrivateWire(db.Model):
    __tablename__ = "private_wire"

    id = db.Column(db.Integer, primary_key=True)
    record_no = db.Column(db.String(50), unique=True)
    location = db.Column(db.String(50))
    dc_locale = db.Column(db.String(100))
    vega_port = db.Column(db.String(50))
    channel = db.Column(db.String(50))
    bearer_no = db.Column(db.String(50))
    circuit_no = db.Column(db.String(50))
    back_up_bearer = db.Column(db.String(100))
    cluster_name = db.Column(db.String(100))
    tpo_name = db.Column(db.String(100))
    vega_hostname = db.Column(db.String(100))
    back_up_vega_gw = db.Column(db.String(100))
    vendor = db.Column(db.String(100))
    pw_type = db.Column(db.String(50))
    btt_slot = db.Column(db.String(50))
    aor = db.Column(db.String(50))
    a_or_b = db.Column(db.String(10))
    dedicated_country = db.Column(db.String(50))
    hsbc_main_user = db.Column(db.String(100))
    employee_id = db.Column(db.String(50))
    private_public = db.Column(db.String(20))
    line_label = db.Column(db.String(100))
    company_name = db.Column(db.String(100))
    company_contact = db.Column(db.String(100))
    company_email = db.Column(db.String(100))
    vr_yn = db.Column(db.String(10))
    snow_ref = db.Column(db.String(50))
    date_created = db.Column(db.DateTime)
    last_updated = db.Column(db.DateTime)
    last_change = db.Column(db.String(200))

    # Added later via migration
    aor_number = db.Column(db.String(50))
    port_number = db.Column(db.String(50))
    channel_number = db.Column(db.String(50))

    custom_fields_json = db.Column(db.Text)


class DealerboardTurret(db.Model):
    __tablename__ = "dealerboard_turret"

    id = db.Column(db.Integer, primary_key=True)

    mac_address = db.Column(db.String(50), unique=True)
    mac_address_2 = db.Column(db.String(50))
    mac_address_3 = db.Column(db.String(50))
    mac_address_4 = db.Column(db.String(50))
    mac_address_5 = db.Column(db.String(50))

    serial_number = db.Column(db.String(100))

    ip_address = db.Column(db.String(50))
    dns_hostname = db.Column(db.String(200))
    zone = db.Column(db.String(50))
    firmware_version = db.Column(db.String(50))
    model = db.Column(db.String(50))
    country = db.Column(db.String(50))
    office = db.Column(db.String(100))
    desk_location = db.Column(db.String(100))

    switchport_1 = db.Column(db.String(100))
    switchport_2 = db.Column(db.String(100))

    date_created = db.Column(db.DateTime)
    last_updated = db.Column(db.DateTime)
    last_change = db.Column(db.String(200))

    # Added later via migration
    installed_by = db.Column(db.String(100))
    installation_date = db.Column(db.DateTime)
    installation_snow_ref = db.Column(db.String(50))
    status = db.Column(db.String(20), default="Active")
    created_by = db.Column(db.String(100))
    last_updated_by = db.Column(db.String(100))

    custom_fields_json = db.Column(db.Text)


class TurretMoveGroup(db.Model):
    __tablename__ = "turret_move_group"

    id = db.Column(db.Integer, primary_key=True)
    move_name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    created_by = db.Column(db.String(100), nullable=False)
    created_date = db.Column(db.DateTime)
    planned_execution_date = db.Column(db.DateTime)
    status = db.Column(db.String(20), default="Planning")
    executed_date = db.Column(db.DateTime)
    executed_by = db.Column(db.String(100))
    notes = db.Column(db.Text)
    last_updated = db.Column(db.DateTime)
    last_updated_by = db.Column(db.String(100))

    moves = db.relationship("TurretMove", back_populates="move_group", lazy="select")


class TurretMove(db.Model):
    __tablename__ = "turret_move"

    id = db.Column(db.Integer, primary_key=True)
    move_group_id = db.Column(db.Integer, db.ForeignKey("turret_move_group.id"), nullable=False)
    turret_id = db.Column(db.Integer, db.ForeignKey("dealerboard_turret.id"), nullable=False)

    from_desk = db.Column(db.String(100))
    to_desk = db.Column(db.String(100), nullable=False)
    from_office = db.Column(db.String(100))
    to_office = db.Column(db.String(100))
    from_country = db.Column(db.String(50))
    to_country = db.Column(db.String(50))
    move_reason = db.Column(db.String(500))
    priority = db.Column(db.String(20), default="Normal")
    status = db.Column(db.String(20), default="Planned")
    snow_reference = db.Column(db.String(50))
    business_justification = db.Column(db.Text)
    estimated_downtime_minutes = db.Column(db.Integer)
    actual_downtime_minutes = db.Column(db.Integer)
    requires_network_config = db.Column(db.Boolean, default=False)
    requires_phone_config = db.Column(db.Boolean, default=False)
    execution_notes = db.Column(db.Text)
    created_date = db.Column(db.DateTime)
    executed_date = db.Column(db.DateTime)

    move_group = db.relationship("TurretMoveGroup", back_populates="moves", lazy="select")
    turret = db.relationship("DealerboardTurret", lazy="select")


class IncidentRecord(db.Model):
    __tablename__ = "incident_record"

    id = db.Column(db.Integer, primary_key=True)

    incident_number = db.Column(db.String(50))
    zendesk_number = db.Column(db.String(50))
    verint_number = db.Column(db.String(50))
    small_title = db.Column(db.String(100))
    region = db.Column(db.String(100))
    incident_date = db.Column(db.DateTime)
    incident_time = db.Column(db.String(20))
    technology = db.Column(db.String(200))
    location = db.Column(db.String(200))
    severity = db.Column(db.String(50))
    calls_lost = db.Column(db.Integer)
    overview = db.Column(db.Text)
    incident_summary = db.Column(db.Text)
    rca_link = db.Column(db.String(500))

    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    last_updated_by = db.Column(db.String(100))


class TurretMoveHistory(db.Model):
    __tablename__ = "turret_move_history"

    id = db.Column(db.Integer, primary_key=True)
    turret_id = db.Column(db.Integer, db.ForeignKey("dealerboard_turret.id"), nullable=False)
    move_id = db.Column(db.Integer, db.ForeignKey("turret_move.id"))
    move_group_id = db.Column(db.Integer, db.ForeignKey("turret_move_group.id"))

    from_desk = db.Column(db.String(100))
    to_desk = db.Column(db.String(100))
    from_office = db.Column(db.String(100))
    to_office = db.Column(db.String(100))
    from_country = db.Column(db.String(50))
    to_country = db.Column(db.String(50))
    move_date = db.Column(db.DateTime, nullable=False)
    moved_by = db.Column(db.String(100), nullable=False)
    move_reason = db.Column(db.String(500))
    snow_reference = db.Column(db.String(50))
    actual_downtime_minutes = db.Column(db.Integer)
    issues_encountered = db.Column(db.Text)
    resolution_notes = db.Column(db.Text)
    notes = db.Column(db.Text)

    turret = db.relationship("DealerboardTurret", lazy="select")


class CeasedPrivateWire(db.Model):
    __tablename__ = "ceased_private_wire"

    id = db.Column(db.Integer, primary_key=True)
    record_no = db.Column(db.String(50))
    original_record_no = db.Column(db.String(50))
    location = db.Column(db.String(50))
    dc_locale = db.Column(db.String(100))
    vega_port = db.Column(db.String(50))
    channel = db.Column(db.String(50))
    bearer_no = db.Column(db.String(50))
    circuit_no = db.Column(db.String(50))
    back_up_bearer = db.Column(db.String(100))
    cluster_name = db.Column(db.String(100))
    tpo_name = db.Column(db.String(100))
    vega_hostname = db.Column(db.String(100))
    back_up_vega_gw = db.Column(db.String(100))
    vendor = db.Column(db.String(100))
    pw_type = db.Column(db.String(50))
    btt_slot = db.Column(db.String(50))
    aor = db.Column(db.String(50))
    a_or_b = db.Column(db.String(10))
    dedicated_country = db.Column(db.String(50))
    hsbc_main_user = db.Column(db.String(100))
    employee_id = db.Column(db.String(50))
    private_public = db.Column(db.String(20))
    line_label = db.Column(db.String(100))
    company_name = db.Column(db.String(100))
    company_contact = db.Column(db.String(100))
    company_email = db.Column(db.String(100))
    vr_yn = db.Column(db.String(10))
    snow_ref = db.Column(db.String(50))
    date_created = db.Column(db.DateTime)
    last_updated = db.Column(db.DateTime)
    last_change = db.Column(db.String(200))

    cease_date = db.Column(db.DateTime)
    ceased_by = db.Column(db.String(100))
    cease_reason = db.Column(db.String(500))

    # Added later via migration
    aor_number = db.Column(db.String(50))
    port_number = db.Column(db.String(50))
    channel_number = db.Column(db.String(50))
