#!/usr/bin/env python3
"""
Fix chatbot_controller.py for PostgreSQL compatibility
"""

# Read the original file
with open('chatbot_controller.py', 'r') as f:
    lines = f.readlines()

# Find the line with the problematic save_chatbot_conversation call
for i, line in enumerate(lines):
    if 'self.db.save_chatbot_conversation(conversation)' in line:
        # Replace with proper parameter passing
        lines[i] = line.replace(
            'self.db.save_chatbot_conversation(conversation)',
            'self.db.save_chatbot_conversation(\n                    conversation_id=conversation["id"],\n                    user_id=conversation.get("user_id"),\n                    state=conversation.get("state", "initial"),\n                    metadata={\n                        "current_script": conversation.get("current_script"),\n                        "validation_result": conversation.get("validation_result"),\n                        "selected_hosts": conversation.get("selected_hosts", []),\n                        "execution_results": conversation.get("execution_results")\n                    }\n                )'
        )
        print(f"Fixed line {i+1}: save_chatbot_conversation call")

# Find and replace the get_conversation method
for i, line in enumerate(lines):
    if line.strip() == 'def get_conversation(self, conversation_id: str) -> Optional[Dict[str, Any]]:':
        # Replace the entire method
        start_line = i
        # Find the end of the method (next method or class end)
        end_line = start_line + 1
        while end_line < len(lines) and not (lines[end_line].strip().startswith('def ') and lines[end_line][0] != ' ' and lines[end_line][0] != '\t'):
            if lines[end_line].strip().startswith('def ') and lines[end_line].startswith('    '):
                break
            end_line += 1
        
        # Create the new method
        new_method = '''    def get_conversation(self, conversation_id: str) -> Optional[Dict[str, Any]]:
        \"\"\"Get conversation by ID, with database fallback\"\"\"
        # First check in-memory cache
        conversation = self.active_conversations.get(conversation_id)
        if conversation:
            return conversation
            
        # Fallback to database
        try:
            db_conversation = self.db.get_chatbot_conversation(conversation_id)
            if db_conversation:
                # Reconstruct conversation structure with required fields
                conversation = {
                    "id": db_conversation["id"],
                    "user_id": db_conversation.get("user_id"),
                    "created_at": db_conversation["created_at"].isoformat() if db_conversation.get("created_at") else datetime.now().isoformat(),
                    "updated_at": db_conversation["updated_at"].isoformat() if db_conversation.get("updated_at") else datetime.now().isoformat(),
                    "state": db_conversation.get("state", "initial"),
                    "messages": [],  # Messages are stored separately
                    "current_script": db_conversation.get("metadata", {}).get("current_script"),
                    "validation_result": db_conversation.get("metadata", {}).get("validation_result"),
                    "selected_hosts": db_conversation.get("metadata", {}).get("selected_hosts", []),
                    "execution_results": db_conversation.get("metadata", {}).get("execution_results")
                }
                # Store in cache for future use
                self.active_conversations[conversation_id] = conversation
                return conversation
        except Exception as e:
            logger.error(f"Error loading conversation from database: {e}")
        
        return None
    
'''
        
        # Replace the lines
        lines[start_line:end_line] = new_method.split('\n')
        print(f"Replaced get_conversation method (lines {start_line+1}-{end_line})")
        break

# Write the fixed file
with open('chatbot_controller.py', 'w') as f:
    f.writelines(lines)

print("Fixed chatbot_controller.py for PostgreSQL compatibility")
