# Group Member Management System

A Flask + Supabase based group member score management system, supporting multi-group management, blacklist management, announcement management, and more.

## ✨ Features

### Core Features
- 👥 **Member Management** - Add, edit, delete group members
- 📊 **Score Management** - Rate members, support score filtering
- 🏷️ **Multi-Group Support** - WeChat groups, QQ groups, QQ channels
- 📝 **Group Info Management** - Group name, group announcement management
- ⚠️ **Blacklist Management** - Add, remove blacklist members
- 🔐 **Admin System** - Hierarchical permission management

### Admin Permission System
- 👑 **Super Admin** - Full permissions, can manage other admins
  - ✅ Create new admin accounts
  - ✅ Modify admin usernames
  - ✅ Reset admin passwords
  - ✅ Delete admin accounts
  - ✅ View all admin list
- 👤 **Regular Admin** - Manage group members and affairs
  - ✅ Manage members (add, delete, edit)
  - ✅ Manage blacklist
  - ✅ Manage group announcements
  - ✅ Change personal password

## 🚀 Quick Start

### Requirements
- Python 3.8+
- Supabase account

### Installation

1. **Clone the repository**
```bash
git clone <your-repo-url>
cd groupmember
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Configure environment variables**

In PowerShell:
```powershell
$env:SUPABASE_URL="https://your-project.supabase.co"
$env:SUPABASE_KEY="your-service-role-key"
```

Or in CMD:
```cmd
set SUPABASE_URL=https://your-project.supabase.co
set SUPABASE_KEY=your-service-role-key
```

4. **Run the application**
```bash
python run.py
```

5. **Access the admin panel**
Open browser and visit: `http://127.0.0.1:5000/admin/login`

## 📁 Project Structure

```
groupmember/
├── app/
│   ├── main.py              # Main application (routes, business logic)
│   ├── templates/           # HTML templates
│   │   ├── admin.html       # Admin panel
│   │   ├── login.html       # Login page
│   │   ├── index.html       # Frontend page
│   │   └── ...
│   └── static/
│       └── js/
│           └── admin.js     # Admin JavaScript
├── run.py                   # Startup script
├── wsgi.py                  # WSGI configuration
├── requirements.txt         # Python dependencies
└── *.sql                    # Database migration scripts
```

## 🗄️ Database Configuration

Execute SQL scripts in Supabase to create tables:

1. `create_groups_table.sql` - Groups table
2. `create_group_notices_table.sql` - Group notices table
3. `alter_table_script.sql` - Members table structure update
4. `add_super_admin_column.sql` - Add super admin field

### Create Initial Admin Account

Execute in Supabase SQL Editor:
```sql
INSERT INTO admin_users (username, password, is_super_admin)
VALUES (
  'admin',
  '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',  -- SHA-256('password')
  true
);
```

Default credentials: `admin` / Password: `password`

## 🔒 Security Notes

- Passwords are stored with SHA-256 encryption
- Uses Supabase `service_role` key for backend authentication
- Only super admins can manage other admins
- Cannot delete your own admin account

## 🛠️ Tech Stack

- **Backend**: Flask 2.3.2
- **Database**: Supabase (PostgreSQL)
- **Template**: Jinja2
- **HTTP Client**: Requests
- **Timezone**: pytz

## 📝 Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| SUPABASE_URL | Supabase project URL | https://xxx.supabase.co |
| SUPABASE_KEY | Supabase API key | eyJhbG... |
| PORT | Server port (optional) | 5000 |

## 📄 License

MIT License

## 🤝 Contributing

Issues and Pull Requests are welcome!

## 📧 Contact

For questions, please open an issue or contact the maintainer.
