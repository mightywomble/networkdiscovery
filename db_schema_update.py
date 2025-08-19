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

def add_database_methods(db_path='networkmap.db'):
    """
    This function will generate SQL to be added to the Database class.
    The actual implementation should be manually added to database.py.
    """
    
    methods = '''
    # Chatbot database methods
    def save_chatbot_conversation(self, conversation):
        """Save or update chatbot conversation"""
        with self.get_connection() as conn:
            metadata = json.dumps(conversation) if isinstance(conversation, dict) else '{}'
            
            # Check if conversation exists
            cursor = conn.execute('SELECT id FROM chatbot_conversations WHERE id = ?', (conversation['id'],))
            if cursor.fetchone():
                # Update existing conversation
                conn.execute('''
                    UPDATE chatbot_conversations 
                    SET state = ?, updated_at = ?, metadata = ?
                    WHERE id = ?
                ''', (
                    conversation.get('state', 'initial'),
                    conversation.get('updated_at', datetime.now().isoformat()),
                    metadata,
                    conversation['id']
                ))
            else:
                # Insert new conversation
                conn.execute('''
                    INSERT INTO chatbot_conversations (id, user_id, state, created_at, updated_at, metadata)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    conversation['id'],
                    conversation.get('user_id'),
                    conversation.get('state', 'initial'),
                    conversation.get('created_at', datetime.now().isoformat()),
                    conversation.get('updated_at', datetime.now().isoformat()),
                    metadata
                ))
            
            # Save messages
            for message in conversation.get('messages', []):
                self.save_chatbot_message(message, conversation['id'])
            
            conn.commit()
    
    def save_chatbot_message(self, message, conversation_id):
        """Save a chatbot message"""
        with self.get_connection() as conn:
            metadata = json.dumps(message.get('metadata', {}))
            
            # Check if message exists
            cursor = conn.execute('SELECT id FROM chatbot_messages WHERE id = ?', (message['id'],))
            if cursor.fetchone():
                # Update existing message
                conn.execute('''
                    UPDATE chatbot_messages 
                    SET content = ?, metadata = ?
                    WHERE id = ?
                ''', (
                    message.get('content', ''),
                    metadata,
                    message['id']
                ))
            else:
                # Insert new message
                conn.execute('''
                    INSERT INTO chatbot_messages (id, conversation_id, message_type, content, timestamp, metadata)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    message['id'],
                    conversation_id,
                    message.get('type', 'bot'),
                    message.get('content', ''),
                    message.get('timestamp', datetime.now().isoformat()),
                    metadata
                ))
            
            conn.commit()
    
    def get_chatbot_conversation(self, conversation_id):
        """Get a chatbot conversation by ID"""
        with self.get_connection() as conn:
            # Get conversation
            cursor = conn.execute('SELECT * FROM chatbot_conversations WHERE id = ?', (conversation_id,))
            conversation_row = cursor.fetchone()
            
            if not conversation_row:
                return None
            
            # Get messages
            cursor = conn.execute('''
                SELECT * FROM chatbot_messages 
                WHERE conversation_id = ? 
                ORDER BY timestamp
            ''', (conversation_id,))
            message_rows = cursor.fetchall()
            
            # Convert to dict
            conversation = dict(conversation_row)
            
            # Parse metadata
            try:
                metadata = json.loads(conversation.get('metadata', '{}'))
                conversation.update(metadata)
            except:
                conversation['metadata'] = {}
            
            # Add messages
            conversation['messages'] = []
            for message_row in message_rows:
                message = dict(message_row)
                
                # Parse metadata
                try:
                    message_metadata = json.loads(message.get('metadata', '{}'))
                    message['metadata'] = message_metadata
                except:
                    message['metadata'] = {}
                
                conversation['messages'].append(message)
            
            return conversation
    
    def save_chatbot_script(self, script_data, conversation_id):
        """Save a generated script"""
        with self.get_connection() as conn:
            validation_result = json.dumps(script_data.get('validation_result', {}))
            
            # Check if script exists
            cursor = conn.execute('SELECT id FROM chatbot_scripts WHERE id = ?', (script_data['id'],))
            if cursor.fetchone():
                # Update existing script
                conn.execute('''
                    UPDATE chatbot_scripts 
                    SET script_content = ?, explanation = ?, safety_level = ?,
                        validated_at = ?, validation_result = ?
                    WHERE id = ?
                ''', (
                    script_data.get('script', ''),
                    script_data.get('explanation', ''),
                    script_data.get('safety_level', 'unknown'),
                    script_data.get('validated_at', datetime.now().isoformat()),
                    validation_result,
                    script_data['id']
                ))
            else:
                # Insert new script
                conn.execute('''
                    INSERT INTO chatbot_scripts 
                    (id, conversation_id, user_request, script_content, explanation, 
                     safety_level, template_used, generated_at, validated_at, validation_result)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    script_data['id'],
                    conversation_id,
                    script_data.get('user_request', ''),
                    script_data.get('script', ''),
                    script_data.get('explanation', ''),
                    script_data.get('safety_level', 'unknown'),
                    script_data.get('template_used', ''),
                    script_data.get('generated_at', datetime.now().isoformat()),
                    script_data.get('validated_at', datetime.now().isoformat()),
                    validation_result
                ))
            
            conn.commit()
    
    def save_chatbot_execution(self, execution_data, conversation_id, script_id):
        """Save script execution results"""
        with self.get_connection() as conn:
            results = json.dumps(execution_data.get('results', {}))
            summary = json.dumps(execution_data.get('summary', {}))
            
            # Check if execution exists
            cursor = conn.execute('SELECT id FROM chatbot_executions WHERE id = ?', (execution_data['execution_id'],))
            if cursor.fetchone():
                # Update existing execution
                conn.execute('''
                    UPDATE chatbot_executions 
                    SET completed_at = ?, status = ?, results = ?, summary = ?
                    WHERE id = ?
                ''', (
                    execution_data.get('completed_at', datetime.now().isoformat()),
                    execution_data.get('status', 'unknown'),
                    results,
                    summary,
                    execution_data['execution_id']
                ))
            else:
                # Insert new execution
                conn.execute('''
                    INSERT INTO chatbot_executions 
                    (id, conversation_id, script_id, started_at, completed_at, status, results, summary)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    execution_data['execution_id'],
                    conversation_id,
                    script_id,
                    execution_data.get('started_at', datetime.now().isoformat()),
                    execution_data.get('completed_at'),
                    execution_data.get('status', 'running'),
                    results,
                    summary
                ))
            
            conn.commit()
    
    def get_chatbot_execution(self, execution_id):
        """Get execution results by ID"""
        with self.get_connection() as conn:
            cursor = conn.execute('SELECT * FROM chatbot_executions WHERE id = ?', (execution_id,))
            row = cursor.fetchone()
            
            if not row:
                return None
            
            execution = dict(row)
            
            # Parse JSON fields
            try:
                execution['results'] = json.loads(execution.get('results', '{}'))
            except:
                execution['results'] = {}
                
            try:
                execution['summary'] = json.loads(execution.get('summary', '{}'))
            except:
                execution['summary'] = {}
            
            return execution
    
    def get_recent_chatbot_conversations(self, limit=10):
        """Get recent chatbot conversations"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT id, user_id, state, created_at, updated_at 
                FROM chatbot_conversations 
                ORDER BY updated_at DESC 
                LIMIT ?
            ''', (limit,))
            
            conversations = []
            for row in cursor.fetchall():
                conversations.append(dict(row))
            
            return conversations
    
    def save_ai_api_settings(self, provider, api_key, model_name, api_endpoint, 
                           temperature=0.7, max_tokens=1000, timeout=30, 
                           enabled=False, additional_config=None):
        """Save AI API settings"""
        with self.get_connection() as conn:
            # Convert additional_config to JSON
            if additional_config is not None:
                if isinstance(additional_config, dict):
                    additional_config_json = json.dumps(additional_config)
                else:
                    additional_config_json = additional_config
            else:
                additional_config_json = '{}'
                
            # Check if provider exists
            cursor = conn.execute('SELECT id FROM ai_api_settings WHERE provider = ?', (provider,))
            if cursor.fetchone():
                # Update existing provider
                conn.execute('''
                    UPDATE ai_api_settings 
                    SET api_key = ?, model_name = ?, api_endpoint = ?, 
                        temperature = ?, max_tokens = ?, timeout = ?,
                        enabled = ?, additional_config = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE provider = ?
                ''', (
                    api_key, model_name, api_endpoint, temperature, max_tokens, 
                    timeout, enabled, additional_config_json, provider
                ))
            else:
                # Insert new provider
                conn.execute('''
                    INSERT INTO ai_api_settings 
                    (provider, api_key, model_name, api_endpoint, temperature, max_tokens, timeout, enabled, additional_config)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    provider, api_key, model_name, api_endpoint, temperature, 
                    max_tokens, timeout, enabled, additional_config_json
                ))
            
            conn.commit()
    
    def get_ai_api_settings(self, provider):
        """Get AI API settings for a specific provider"""
        with self.get_connection() as conn:
            cursor = conn.execute('SELECT * FROM ai_api_settings WHERE provider = ?', (provider,))
            row = cursor.fetchone()
            
            if not row:
                return None
            
            settings = dict(row)
            
            # Parse additional_config JSON
            try:
                settings['additional_config'] = json.loads(settings.get('additional_config', '{}'))
            except:
                settings['additional_config'] = {}
            
            return settings
    
    def get_all_ai_api_settings(self):
        """Get all AI API settings"""
        with self.get_connection() as conn:
            cursor = conn.execute('SELECT * FROM ai_api_settings')
            
            settings = []
            for row in cursor.fetchall():
                setting = dict(row)
                
                # Parse additional_config JSON
                try:
                    setting['additional_config'] = json.loads(setting.get('additional_config', '{}'))
                except:
                    setting['additional_config'] = {}
                
                settings.append(setting)
            
            return settings
    
    def get_enabled_ai_apis(self):
        """Get all enabled AI APIs"""
        with self.get_connection() as conn:
            cursor = conn.execute('SELECT * FROM ai_api_settings WHERE enabled = 1')
            
            apis = []
            for row in cursor.fetchall():
                api = dict(row)
                
                # Parse additional_config JSON
                try:
                    api['additional_config'] = json.loads(api.get('additional_config', '{}'))
                except:
                    api['additional_config'] = {}
                
                apis.append(api)
            
            return apis
    
    def enable_ai_api(self, provider, enabled=True):
        """Enable or disable an AI API provider"""
        with self.get_connection() as conn:
            conn.execute('''
                UPDATE ai_api_settings 
                SET enabled = ?, updated_at = CURRENT_TIMESTAMP
                WHERE provider = ?
            ''', (enabled, provider))
            conn.commit()
            return True
    
    def delete_ai_api_settings(self, provider):
        """Delete AI API settings for a provider"""
        with self.get_connection() as conn:
            conn.execute('DELETE FROM ai_api_settings WHERE provider = ?', (provider,))
            conn.commit()
            return True
    '''
    
    # Create a database_methods.txt file
    with open('database_methods.txt', 'w') as f:
        f.write(methods)
    
    print("SQL for database methods generated and saved to database_methods.txt")
    print("Please manually add these methods to your database.py file")

if __name__ == "__main__":
    # Run the schema update
    update_database_schema()
    
    # Generate database methods
    add_database_methods()
