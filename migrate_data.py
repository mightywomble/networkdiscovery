#!/usr/bin/env python3
"""
Data migration script from SQLite to PostgreSQL
"""

import sqlite3
import psycopg2
import psycopg2.extras
import json
from datetime import datetime

def migrate_data():
    """Migrate data from SQLite to PostgreSQL"""
    
    # SQLite connection
    sqlite_conn = sqlite3.connect('networkmap.db')
    sqlite_conn.row_factory = sqlite3.Row
    
    # PostgreSQL connection
    pg_conn = psycopg2.connect(
        host='localhost',
        database='networkmap',
        user='networkmap',
        password='networkmap123',
        port=5432
    )
    pg_conn.autocommit = True
    
    try:
        print("Starting data migration from SQLite to PostgreSQL...")
        
        # Tables to migrate in order (respecting foreign key dependencies)
        tables = [
            'hosts',
            'agents', 
            'host_info',
            'network_connections',
            'port_scans',
            'traffic_stats',
            'network_discovery',
            'topology_analysis',
            'diagram_layouts',
            'agent_configs',
            'agent_logs',
            'agent_scan_results',
            'ai_api_settings',
            'application_settings',
            'chatbot_conversations',
            'chatbot_messages'
        ]
        
        for table in tables:
            print(f"Migrating table: {table}")
            migrate_table(sqlite_conn, pg_conn, table)
        
        print("Data migration completed successfully!")
        
    except Exception as e:
        print(f"Migration failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        sqlite_conn.close()
        pg_conn.close()

def migrate_table(sqlite_conn, pg_conn, table_name):
    """Migrate a specific table from SQLite to PostgreSQL"""
    
    sqlite_cursor = sqlite_conn.cursor()
    pg_cursor = pg_conn.cursor()
    
    try:
        # Get data from SQLite
        sqlite_cursor.execute(f"SELECT * FROM {table_name}")
        rows = sqlite_cursor.fetchall()
        
        if not rows:
            print(f"  No data found in {table_name}")
            return
        
        # Get column names
        column_names = [description[0] for description in sqlite_cursor.description]
        print(f"  Found {len(rows)} rows with columns: {column_names}")
        
        # Handle special cases for different table structures
        if table_name == 'hosts':
            migrate_hosts(pg_cursor, rows, column_names)
        elif table_name == 'agents':
            migrate_agents(pg_cursor, rows, column_names)
        elif table_name == 'application_settings':
            migrate_application_settings(pg_cursor, rows, column_names)
        elif table_name == 'chatbot_conversations':
            migrate_chatbot_conversations(pg_cursor, rows, column_names)
        elif table_name == 'chatbot_messages':
            migrate_chatbot_messages(pg_cursor, rows, column_names)
        else:
            # Generic migration for other tables
            migrate_generic_table(pg_cursor, table_name, rows, column_names)
            
        print(f"  Successfully migrated {len(rows)} rows to {table_name}")
        
    except Exception as e:
        print(f"  Error migrating {table_name}: {e}")

def migrate_hosts(pg_cursor, rows, column_names):
    """Migrate hosts table"""
    for row in rows:
        row_dict = dict(row)
        pg_cursor.execute('''
            INSERT INTO hosts (name, ip_address, username, ssh_port, description, status, last_seen, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (name) DO NOTHING
        ''', (
            row_dict.get('name'),
            row_dict.get('ip_address'),
            row_dict.get('username', 'root'),
            row_dict.get('ssh_port', 22),
            row_dict.get('description'),
            row_dict.get('status', 'unknown'),
            row_dict.get('last_seen'),
            row_dict.get('created_at'),
            row_dict.get('updated_at')
        ))

def migrate_agents(pg_cursor, rows, column_names):
    """Migrate agents table"""
    for row in rows:
        row_dict = dict(row)
        pg_cursor.execute('''
            INSERT INTO agents (agent_id, hostname, ip_address, username, agent_version, status, 
                               last_heartbeat, last_scan, config_hash, error_message, build_date, 
                               last_update_date, platform, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (agent_id) DO NOTHING
        ''', (
            row_dict.get('agent_id'),
            row_dict.get('hostname'),
            row_dict.get('ip_address'),
            row_dict.get('username'),
            row_dict.get('agent_version'),
            row_dict.get('status', 'inactive'),
            row_dict.get('last_heartbeat'),
            row_dict.get('last_scan'),
            row_dict.get('config_hash'),
            row_dict.get('error_message'),
            row_dict.get('build_date'),
            row_dict.get('last_update_date'),
            row_dict.get('platform'),
            row_dict.get('created_at'),
            row_dict.get('updated_at')
        ))

def migrate_application_settings(pg_cursor, rows, column_names):
    """Migrate application_settings table"""
    for row in rows:
        row_dict = dict(row)
        pg_cursor.execute('''
            INSERT INTO application_settings (setting_key, setting_value, setting_type, description, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (setting_key) DO UPDATE SET
                setting_value = EXCLUDED.setting_value,
                setting_type = EXCLUDED.setting_type,
                description = EXCLUDED.description,
                updated_at = EXCLUDED.updated_at
        ''', (
            row_dict.get('setting_key'),
            row_dict.get('setting_value'),
            row_dict.get('setting_type', 'string'),
            row_dict.get('description'),
            row_dict.get('created_at'),
            row_dict.get('updated_at')
        ))

def migrate_chatbot_conversations(pg_cursor, rows, column_names):
    """Migrate chatbot_conversations table"""
    for row in rows:
        row_dict = dict(row)
        pg_cursor.execute('''
            INSERT INTO chatbot_conversations (id, user_id, state, created_at, updated_at, metadata)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO NOTHING
        ''', (
            row_dict.get('id'),
            row_dict.get('user_id'),
            row_dict.get('state', 'initial'),
            row_dict.get('created_at'),
            row_dict.get('updated_at'),
            row_dict.get('metadata')
        ))

def migrate_chatbot_messages(pg_cursor, rows, column_names):
    """Migrate chatbot_messages table"""
    for row in rows:
        row_dict = dict(row)
        pg_cursor.execute('''
            INSERT INTO chatbot_messages (id, conversation_id, message_type, content, timestamp, metadata)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO NOTHING
        ''', (
            row_dict.get('id'),
            row_dict.get('conversation_id'),
            row_dict.get('message_type', 'bot'),
            row_dict.get('content'),
            row_dict.get('timestamp'),
            row_dict.get('metadata')
        ))

def migrate_generic_table(pg_cursor, table_name, rows, column_names):
    """Generic table migration for simple tables"""
    
    # Skip id column for auto-increment tables
    columns_without_id = [col for col in column_names if col != 'id']
    placeholders = ', '.join(['%s'] * len(columns_without_id))
    column_list = ', '.join(columns_without_id)
    
    for row in rows:
        row_dict = dict(row)
        values = [row_dict.get(col) for col in columns_without_id]
        
        try:
            pg_cursor.execute(f'''
                INSERT INTO {table_name} ({column_list})
                VALUES ({placeholders})
            ''', values)
        except Exception as e:
            print(f"    Warning: Could not insert row into {table_name}: {e}")

if __name__ == '__main__':
    migrate_data()
