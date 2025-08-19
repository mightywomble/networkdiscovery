# AI Network Assistant Chatbot

🤖 An intelligent conversational interface for network administration that generates and executes bash scripts safely on remote hosts using natural language processing.

## Features

### 🎯 Core Functionality
- **Natural Language Processing**: Convert plain English requests into executable bash scripts
- **Safety Validation**: Comprehensive script analysis with risk assessment and safety recommendations
- **Multi-Host Execution**: Execute scripts on selected hosts with real-time progress tracking
- **Conversation Memory**: Maintains context across conversation turns for complex multi-step tasks
- **Interactive Approval**: Review and approve scripts before execution with detailed security analysis

### 🛡️ Security Features
- **Risk Level Assessment**: LOW/MEDIUM/HIGH risk classification for generated scripts
- **Command Analysis**: Identifies dangerous commands and provides safety explanations
- **User Approval Required**: No scripts execute without explicit user consent
- **Audit Trail**: Complete conversation and execution history tracking
- **Host Selection Control**: Choose exactly which hosts to target for each operation

### 🎨 User Interface
- **PatternFly Design**: Professional, responsive web interface
- **Real-time Chat**: Live conversation with typing indicators and animations
- **Script Visualization**: Syntax-highlighted code blocks with copy functionality
- **Host Selection Panel**: Visual host status with online/offline indicators
- **Quick Actions**: Pre-built buttons for common network administration tasks
- **Mobile Responsive**: Works seamlessly on desktop, tablet, and mobile devices

## Architecture

### Backend Components

#### 1. `ChatbotController` (`chatbot_controller.py`)
- **Purpose**: Orchestrates conversation flow and state management
- **Responsibilities**:
  - Manages conversation states (greeting → script_generation → validation → execution)
  - Coordinates between AI generator, validator, and executor
  - Handles conversation persistence and history
  - Manages multi-host execution workflows

#### 2. `AICommandGenerator` (`ai_command_generator.py`)
- **Purpose**: Converts natural language to bash scripts
- **Capabilities**:
  - Template-based generation for common tasks
  - AI-powered generation using Gemini or ChatGPT APIs
  - Host-aware script customization
  - Safety-focused script design

#### 3. `CommandValidator` (`command_validator.py`)
- **Purpose**: Analyzes scripts for security and safety
- **Features**:
  - Risk level assessment (LOW/MEDIUM/HIGH)
  - Dangerous command detection
  - Safety recommendations
  - Detailed explanations of potential risks

### Frontend Components

#### Web Interface (`templates/chatbot.html`)
- **Chat Interface**: Real-time conversation with message history
- **Host Selection**: Interactive panel for choosing target hosts
- **Script Display**: Syntax-highlighted code blocks with validation results
- **Action Buttons**: Execute, Cancel, Copy script functionality
- **Notifications**: Toast messages for user feedback

### Database Schema

```sql
-- Conversations table
CREATE TABLE chatbot_conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id TEXT UNIQUE NOT NULL,
    user_id TEXT,
    state TEXT DEFAULT 'greeting',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Messages table
CREATE TABLE chatbot_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id TEXT NOT NULL,
    sender TEXT NOT NULL, -- 'user' or 'bot'
    message TEXT NOT NULL,
    metadata TEXT, -- JSON for additional data
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (conversation_id) REFERENCES chatbot_conversations(conversation_id)
);

-- Scripts table
CREATE TABLE chatbot_scripts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id TEXT NOT NULL,
    script_content TEXT NOT NULL,
    validation_result TEXT, -- JSON
    approved BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (conversation_id) REFERENCES chatbot_conversations(conversation_id)
);

-- Executions table
CREATE TABLE chatbot_executions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    execution_id TEXT UNIQUE NOT NULL,
    conversation_id TEXT NOT NULL,
    script_id INTEGER NOT NULL,
    selected_hosts TEXT, -- JSON array
    status TEXT DEFAULT 'pending',
    results TEXT, -- JSON
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    FOREIGN KEY (conversation_id) REFERENCES chatbot_conversations(conversation_id),
    FOREIGN KEY (script_id) REFERENCES chatbot_scripts(id)
);
```

## API Endpoints

### Conversation Management
- `POST /api/chatbot/start` - Start a new conversation
- `GET /api/chatbot/conversation/<id>` - Get conversation history

### Message Processing
- `POST /api/chatbot/message` - Send user message and get bot response

### Script Operations
- `POST /api/chatbot/validate_script` - Validate a bash script for safety
- `POST /api/chatbot/generate_script` - Generate script from natural language

### Execution Management
- `GET /api/chatbot/execution/<conversation_id>/<execution_id>` - Get execution results

## Setup and Installation

### 1. Database Schema Setup
```bash
# Apply the database schema updates
python3 db_schema_update.py
```

### 2. AI API Configuration
Configure AI providers in the Settings page (`/settings`):

**For Gemini API:**
- API Key: Your Google AI Studio API key
- Model: gemini-pro or gemini-1.5-pro
- Endpoint: https://generativelanguage.googleapis.com/

**For ChatGPT API:**
- API Key: Your OpenAI API key
- Model: gpt-3.5-turbo or gpt-4
- Endpoint: https://api.openai.com/v1/

### 3. Host Configuration
Add hosts via the Hosts page (`/hosts`) to enable script execution.

### 4. Testing
```bash
# Test the chatbot API endpoints
python3 test_chatbot_api.py

# Start the Flask application
python3 app.py
```

### 5. Access the Interface
Navigate to `http://localhost:5150/ai_chatbot` to use the chatbot.

## Usage Examples

### Example 1: System Status Check
**User Input:** "Check system status and uptime on all servers"

**Generated Script:**
```bash
#!/bin/bash
echo "=== System Status Report ==="
echo "Hostname: $(hostname)"
echo "Uptime: $(uptime)"
echo "Load Average: $(cat /proc/loadavg)"
echo "Memory Usage:"
free -h
echo "Disk Usage:"
df -h /
echo "Network Interfaces:"
ip addr show | grep inet
```

### Example 2: Network Configuration
**User Input:** "Show me all network interfaces and their IP addresses"

**Generated Script:**
```bash
#!/bin/bash
echo "=== Network Interface Configuration ==="
ip addr show
echo ""
echo "=== Routing Table ==="
ip route show
echo ""
echo "=== Active Network Connections ==="
ss -tuln
```

### Example 3: Security Audit
**User Input:** "Find all listening services and check for security issues"

**Generated Script:**
```bash
#!/bin/bash
echo "=== Listening Services Audit ==="
echo "TCP Listening Ports:"
ss -tlnp | grep LISTEN
echo ""
echo "UDP Listening Ports:"
ss -ulnp
echo ""
echo "Running Services:"
systemctl list-units --type=service --state=running
```

## Security Considerations

### Script Validation
- All scripts undergo safety analysis before execution
- Risk levels clearly displayed to users
- Dangerous commands flagged with explanations
- User approval required for all executions

### Risk Classifications

**LOW Risk:**
- Read-only operations (ls, cat, grep)
- System information commands (uptime, whoami)
- Network viewing commands (ip addr show)

**MEDIUM Risk:**
- Service status commands (systemctl status)
- Package queries (dpkg -l, rpm -qa)
- Log file access (tail /var/log/*)

**HIGH Risk:**
- System modifications (apt install, yum update)
- Service management (systemctl restart)
- File system changes (rm, mv, chmod)
- Network configuration changes

### Best Practices
1. **Review all scripts** before approval, especially MEDIUM and HIGH risk
2. **Test on non-production hosts** first
3. **Use specific host selection** rather than all hosts for risky operations
4. **Monitor execution results** for unexpected outcomes
5. **Keep AI API keys secure** and rotate regularly

## Troubleshooting

### Common Issues

**1. "Failed to start conversation"**
- Check database schema is applied: `python3 db_schema_update.py`
- Verify Flask app is running: `python3 app.py`

**2. "AI service timeout"**
- Check AI API keys in Settings
- Verify internet connectivity
- Try a different AI provider

**3. "No hosts available"**
- Add hosts via `/hosts` page
- Ensure hosts have SSH access configured
- Check host connectivity with ping

**4. "Script execution failed"**
- Verify SSH keys are set up for hosts
- Check host is online and accessible
- Review script for syntax errors

### Debug Mode
Enable debug logging by setting environment variable:
```bash
export CHATBOT_DEBUG=1
python3 app.py
```

## Contributing

### Adding New Script Templates
1. Edit `ai_command_generator.py`
2. Add template to `SCRIPT_TEMPLATES` dictionary
3. Update pattern matching in `generate_script_from_template()`

### Extending Safety Rules
1. Edit `command_validator.py`
2. Add patterns to risk classification lists
3. Update risk assessment logic

### UI Improvements
1. Edit `templates/chatbot.html`
2. Follow PatternFly design guidelines
3. Test responsive behavior on mobile devices

## License

This AI Chatbot feature is part of the NetworkMap project and follows the same licensing terms.

---

💡 **Need Help?** Check the test script output or Flask logs for detailed error messages and troubleshooting guidance.
