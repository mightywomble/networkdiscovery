#!/usr/bin/env python3
"""
Database Schema Update for NetworkMap Chatbot
Adds necessary tables to support the AI-powered chatbot features
"""

import sqlite3
import os
import json
from datetime import datetime
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def update_database_schema(db_path='networkmap.db'):
    """Add chatbot-related tables to the existing database"""
    try:
        logger.info(f"Updating database schema at {db_path}")
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        
        # Chatbot conversations table
        conn.execute('''
        CREATE TABLE IF NOT EXISTS chatbot_conversations (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            state TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            metadata TEXT
        )
        ''')
        
        # Chatbot messages table
        conn.execute('''
        CREATE TABLE IF NOT EXISTS chatbot_messages (
            id TEXT PRIMARY KEY,
            conversation_id TEXT,
            message_type TEXT,
            content TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            metadata TEXT,
            FOREIGN KEY (conversation_id) REFERENCES chatbot_conversations (id)
        )
        ''')
        
        # Generated scripts table
        conn.execute('''
        CREATE TABLE IF NOT EXISTS chatbot_scripts (
            id TEXT PRIMARY KEY,
            conversation_id TEXT,
            user_request TEXT,
            script_content TEXT,
            explanation TEXT,
            safety_level TEXT,
            template_used TEXT,
            generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            validated_at TIMESTAMP,
            validation_result TEXT,
            FOREIGN KEY (conversation_id) REFERENCES chatbot_conversations (id)
        )
        ''')
        
        # Script executions table
        conn.execute('''
        CREATE TABLE IF NOT EXISTS chatbot_executions (
            id TEXT PRIMARY KEY,
            conversation_id TEXT,
            script_id TEXT,
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            status TEXT,
            results TEXT,
            summary TEXT,
            FOREIGN KEY (conversation_id) REFERENCES chatbot_conversations (id),
            FOREIGN KEY (script_id) REFERENCES chatbot_scripts (id)
        )
        ''')
        
        # AI API settings table (update if not already present)
        try:
            conn.execute('''
            CREATE TABLE IF NOT EXISTS ai_api_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT UNIQUE NOT NULL,
                api_key TEXT,
                model_name TEXT,
                api_endpoint TEXT,
                temperature REAL DEFAULT 0.7,
                max_tokens INTEGER DEFAULT 1000,
                timeout INTEGER DEFAULT 30,
                enabled BOOLEAN DEFAULT 0,
                additional_config TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')
        except:
            logger.info("AI API settings table already exists")
        
        # Create indices
        conn.execute('CREATE INDEX IF NOT EXISTS idx_conversation_id ON chatbot_messages (conversation_id)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_script_conversation ON chatbot_scripts (conversation_id)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_execution_conversation ON chatbot_executions (conversation_id)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_execution_script ON chatbot_executions (script_id)')
        
        conn.commit()
        logger.info("Database schema updated successfully")
        
        return True
        
    except Exception as e:
        logger.error(f"Error updating database schema: {e}")
        return False
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    # Run the schema update
    success = update_database_schema()
    if success:
        print("Database schema updated successfully!")
    else:
        print("Failed to update database schema.")
