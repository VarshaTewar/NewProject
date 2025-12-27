from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response, abort
from database import init_db, get_db, verify_user, get_user_by_id
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Initialize DB and tables
init_db()

# Role permissions configuration
ROLE_PERMISSIONS = {
    'admin': ['dashboard', 'patients', 'beds', 'staff', 'inventory', 'export', 'manage_users'],
    'doctor': ['dashboard', 'patients', 'beds', 'staff', 'inventory', 'export'],
    'nurse': ['dashboard', 'patients', 'beds', 'inventory'],
    'receptionist': ['dashboard', 'patients', 'beds', 'export']
}

from functools import wraps

def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapped

def role_required(*allowed_permissions):
    """Decorator to check if user has required permissions"""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please login to access this page', 'danger')
                return redirect(url_for('login'))
            
            user_role = session.get('role')
            user_permissions = ROLE_PERMISSIONS.get(user_role, [])
            
            # Check if user has at least one of the required permissions
            if not any(perm in user_permissions for perm in allowed_permissions):
                flash('You do not have permission to access this page', 'danger')
                return redirect(url_for('index'))
            
            return f(*args, **kwargs)
        return wrapped
    return decorator

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username','')
        password = request.form.get('password','')
        
        user = verify_user(username, password)
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['full_name'] = user['full_name']
            flash(f'Welcome back, {user["full_name"]}!', 'success')
            return redirect(url_for('index'))
        
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
@role_required('dashboard')
def index():
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT COUNT(*) FROM beds'); total_beds = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM beds WHERE status='occupied'"); occupied = cur.fetchone()[0]
    cur.execute('SELECT COUNT(*) FROM patients'); patients = cur.fetchone()[0]
    cur.execute('SELECT COUNT(*) FROM staff'); staff = cur.fetchone()[0]
    cur.execute('SELECT SUM(quantity) FROM inventory'); total_items = cur.fetchone()[0] or 0
    available = total_beds - occupied
    bed_chart = {'occupied': occupied, 'available': available}
    return render_template('index.html', total_beds=total_beds, occupied=occupied, 
                         patients=patients, staff=staff, total_items=total_items, 
                         bed_chart=bed_chart)

# Patients
@app.route('/patients')
@login_required
@role_required('patients')
def patients():
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT * FROM patients')
    rows = cur.fetchall()
    
    cur.execute('SELECT COUNT(*) FROM beds')
    total_beds = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM beds WHERE status='occupied'")
    occupied = cur.fetchone()[0]
    cur.execute('SELECT COUNT(*) FROM staff')
    staff_count = cur.fetchone()[0]
    cur.execute('SELECT SUM(quantity) FROM inventory')
    total_items = cur.fetchone()[0] or 0
    
    return render_template('patients.html', 
                         patients=rows,
                         total_beds=total_beds,
                         occupied=occupied,
                         staff=staff_count,
                         total_items=total_items)

@app.route('/patients/add', methods=['POST'])
@login_required
@role_required('patients')
def add_patient():
    name = request.form.get('name')
    age = request.form.get('age')
    gender = request.form.get('gender')
    reason = request.form.get('admission_reason')
    admission_date = request.form.get('admission_date')
    status = request.form.get('status', 'Stable')
    
    db = get_db(); cur = db.cursor()
    cur.execute('INSERT INTO patients (name, age, gender, admission_reason, admission_date, status, bed_id) VALUES (?,?,?,?,?,?,NULL)', 
                (name, age, gender, reason, admission_date, status))
    db.commit()
    flash('Patient added successfully', 'success')
    return redirect(url_for('patients'))

@app.route('/patients/assign/<int:pid>')
@login_required
@role_required('patients')
def assign_bed(pid):
    db = get_db(); cur = db.cursor()
    cur.execute("SELECT * FROM beds WHERE status='available'")
    beds = cur.fetchall()
    cur.execute('SELECT * FROM patients WHERE id=?', (pid,))
    patient = cur.fetchone()
    return render_template('assign_bed.html', patient=patient, beds=beds)

@app.route('/patients/assign/save', methods=['POST'])
@login_required
@role_required('patients')
def save_assigned_bed():
    pid = request.form.get('patient_id'); bed_id = request.form.get('bed_id')
    db = get_db(); cur = db.cursor()
    cur.execute("UPDATE beds SET status='occupied' WHERE id=?", (bed_id,))
    cur.execute("UPDATE patients SET bed_id=? WHERE id=?", (bed_id, pid))
    db.commit()
    flash('Bed assigned successfully', 'success')
    return redirect(url_for('patients'))

@app.route('/patients/discharge/<int:pid>', methods=['POST'])
@login_required
@role_required('patients')
def discharge(pid):
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT bed_id FROM patients WHERE id=?', (pid,))
    row = cur.fetchone()
    if row and row['bed_id']:
        cur.execute('UPDATE beds SET status="available" WHERE id=?', (row['bed_id'],))
    cur.execute('DELETE FROM patients WHERE id=?', (pid,))
    db.commit()
    flash('Patient discharged successfully', 'info')
    return redirect(url_for('patients'))

@app.route('/patients/edit/<int:pid>', methods=['POST'])
@login_required
@role_required('patients')
def edit_patient(pid):
    name = request.form.get('name')
    age = request.form.get('age')
    gender = request.form.get('gender')
    reason = request.form.get('admission_reason')
    admission_date = request.form.get('admission_date')
    status = request.form.get('status', 'Stable')
    
    db = get_db(); cur = db.cursor()
    cur.execute('UPDATE patients SET name=?, age=?, gender=?, admission_reason=?, admission_date=?, status=? WHERE id=?', 
                (name, age, gender, reason, admission_date, status, pid))
    db.commit()
    flash('Patient updated successfully', 'success')
    return redirect(url_for('patients'))

@app.route('/export/patients')
@login_required
@role_required('export')
def export_patients():
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT id, name, age, gender, admission_reason, admission_date, status, bed_id FROM patients')
    rows = cur.fetchall()
    output = []
    header = ['id','name','age','gender','admission_reason','admission_date','status','bed_id']
    output.append(','.join(header))
    for r in rows:
        vals = [str(r['id']), r['name'] or '', str(r['age'] or ''), 
                r['gender'] or '', r['admission_reason'] or '', 
                r['admission_date'] or '', r['status'] or '', str(r['bed_id'] or '')]
        safe = ['"%s"' % v.replace('"','""') for v in vals]
        output.append(','.join(safe))
    csv_data = '\n'.join(output)
    resp = make_response(csv_data)
    resp.headers['Content-Disposition'] = 'attachment; filename=patients_report.csv'
    resp.headers['Content-Type'] = 'text/csv'
    return resp

# Beds
@app.route('/beds')
@login_required
@role_required('beds')
def beds():
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT * FROM beds')
    rows = cur.fetchall()
    return render_template('beds.html', beds=rows)

@app.route('/beds/add', methods=['POST'])
@login_required
@role_required('beds')
def add_bed():
    # Only admin and doctor can add beds
    if session.get('role') not in ['admin', 'doctor']:
        flash('Only administrators and doctors can add beds', 'danger')
        return redirect(url_for('beds'))
    
    ward = request.form.get('ward'); bed_number = request.form.get('bed_number')
    db = get_db(); cur = db.cursor()
    cur.execute("INSERT INTO beds (ward, bed_number, status) VALUES (?,?,'available')", 
                (ward, bed_number))
    db.commit()
    flash('Bed added successfully', 'success')
    return redirect(url_for('beds'))

@app.route('/beds/edit', methods=['POST'])
@login_required
@role_required('beds')
def edit_bed():
    # Only admin and doctor can edit beds
    if session.get('role') not in ['admin', 'doctor']:
        flash('Only administrators and doctors can edit beds', 'danger')
        return redirect(url_for('beds'))
    
    bed_id = request.form.get('bed_id')
    ward = request.form.get('ward')
    bed_number = request.form.get('bed_number')
    db = get_db(); cur = db.cursor()
    cur.execute('UPDATE beds SET ward=?, bed_number=? WHERE id=?', (ward, bed_number, bed_id))
    db.commit()
    flash('Bed updated successfully', 'success')
    return redirect(url_for('beds'))

# Staff
@app.route('/staff')
@login_required
@role_required('staff')
def staff():
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT * FROM staff')
    rows = cur.fetchall()
    return render_template('staff.html', staff=rows)

@app.route('/staff/add', methods=['POST'])
@login_required
@role_required('staff')
def add_staff():
    # Only admin can add staff
    if session.get('role') != 'admin':
        flash('Only administrators can add staff members', 'danger')
        return redirect(url_for('staff'))
    
    name = request.form.get('name')
    role = request.form.get('role')
    speciality = request.form.get('speciality', '')
    on_duty = 1 if request.form.get('on_duty') == 'on' else 0
    
    db = get_db(); cur = db.cursor()
    cur.execute('INSERT INTO staff (name, role, speciality, on_duty) VALUES (?,?,?,?)', 
                (name, role, speciality, on_duty))
    db.commit()
    flash('Staff added successfully', 'success')
    return redirect(url_for('staff'))

@app.route('/staff/edit/<int:staff_id>', methods=['POST'])
@login_required
@role_required('staff')
def edit_staff(staff_id):
    # Only admin can edit staff
    if session.get('role') != 'admin':
        flash('Only administrators can edit staff members', 'danger')
        return redirect(url_for('staff'))
    
    name = request.form.get('name')
    role = request.form.get('role')
    speciality = request.form.get('speciality', '')
    
    db = get_db(); cur = db.cursor()
    cur.execute('UPDATE staff SET name=?, role=?, speciality=? WHERE id=?', 
                (name, role, speciality, staff_id))
    db.commit()
    flash('Staff updated successfully', 'success')
    return redirect(url_for('staff'))

@app.route('/staff/toggle/<int:staff_id>', methods=['POST'])
@login_required
@role_required('staff')
def toggle_staff(staff_id):
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT on_duty FROM staff WHERE id=?', (staff_id,))
    row = cur.fetchone()
    if row:
        new = 0 if row['on_duty'] else 1
        cur.execute('UPDATE staff SET on_duty=? WHERE id=?', (new, staff_id))
        db.commit()
        flash('Staff duty status updated', 'success')
    return redirect(url_for('staff'))

@app.route('/staff/delete/<int:staff_id>', methods=['POST'])
@login_required
@role_required('staff')
def delete_staff(staff_id):
    # Only admin can delete staff
    if session.get('role') != 'admin':
        flash('Only administrators can remove staff members', 'danger')
        return redirect(url_for('staff'))
    
    db = get_db(); cur = db.cursor()
    cur.execute('DELETE FROM staff WHERE id=?', (staff_id,))
    db.commit()
    flash('Staff member removed successfully', 'info')
    return redirect(url_for('staff'))

# Inventory
@app.route('/inventory')
@login_required
@role_required('inventory')
def inventory():
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT * FROM inventory')
    rows = cur.fetchall()
    low_items = [r for r in rows if (r['quantity'] or 0) <= 5]
    if low_items:
        flash(f"{len(low_items)} item(s) low in stock (≤5).", 'danger')
    return render_template('inventory.html', items=rows)

@app.route('/inventory/add', methods=['POST'])
@login_required
@role_required('inventory')
def add_item():
    name = request.form.get('name'); qty = int(request.form.get('quantity') or 0)
    db = get_db(); cur = db.cursor()
    cur.execute('INSERT INTO inventory (name, quantity) VALUES (?,?)', (name, qty))
    db.commit()
    flash('Inventory item added successfully', 'success')
    return redirect(url_for('inventory'))

@app.route('/inventory/update/<int:item_id>', methods=['POST'])
@login_required
@role_required('inventory')
def update_item(item_id):
    qty = int(request.form.get('quantity') or 0)
    db = get_db(); cur = db.cursor()
    cur.execute('UPDATE inventory SET quantity=? WHERE id=?', (qty, item_id))
    db.commit()
    flash('Quantity updated successfully', 'success')
    return redirect(url_for('inventory'))

# User Management (Admin only)
@app.route('/users')
@login_required
@role_required('manage_users')
def users():
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT id, username, role, full_name, created_at FROM users')
    rows = cur.fetchall()
    return render_template('users.html', users=rows)

@app.route('/users/add', methods=['POST'])
@login_required
@role_required('manage_users')
def add_user():
    from database import hash_password
    
    username = request.form.get('username')
    full_name = request.form.get('full_name')
    role = request.form.get('role')
    password = request.form.get('password')
    
    if not all([username, full_name, role, password]):
        flash('All fields are required', 'danger')
        return redirect(url_for('users'))
    
    db = get_db(); cur = db.cursor()
    
    # Check if username already exists
    cur.execute('SELECT id FROM users WHERE username = ?', (username,))
    if cur.fetchone():
        flash('Username already exists', 'danger')
        return redirect(url_for('users'))
    
    password_hash = hash_password(password)
    cur.execute('INSERT INTO users (username, password_hash, role, full_name) VALUES (?, ?, ?, ?)',
                (username, password_hash, role, full_name))
    db.commit()
    flash(f'User {username} added successfully', 'success')
    return redirect(url_for('users'))

@app.route('/users/edit/<int:user_id>', methods=['POST'])
@login_required
@role_required('manage_users')
def edit_user(user_id):
    from database import hash_password
    
    username = request.form.get('username')
    full_name = request.form.get('full_name')
    role = request.form.get('role')
    password = request.form.get('password')
    
    if not all([username, full_name, role]):
        flash('Username, full name, and role are required', 'danger')
        return redirect(url_for('users'))
    
    # Don't allow editing yourself to prevent lockout
    if user_id == session.get('user_id'):
        flash('You cannot edit your own account', 'danger')
        return redirect(url_for('users'))
    
    db = get_db(); cur = db.cursor()
    
    # Check if username already exists for another user
    cur.execute('SELECT id FROM users WHERE username = ? AND id != ?', (username, user_id))
    if cur.fetchone():
        flash('Username already exists', 'danger')
        return redirect(url_for('users'))
    
    # Update user info
    if password:
        # If password provided, update it too
        password_hash = hash_password(password)
        cur.execute('UPDATE users SET username=?, full_name=?, role=?, password_hash=? WHERE id=?',
                    (username, full_name, role, password_hash, user_id))
    else:
        # Only update username, full_name, and role
        cur.execute('UPDATE users SET username=?, full_name=?, role=? WHERE id=?',
                    (username, full_name, role, user_id))
    
    db.commit()
    flash(f'User {username} updated successfully', 'success')
    return redirect(url_for('users'))

@app.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required
@role_required('manage_users')
def delete_user(user_id):
    # Don't allow deleting yourself
    if user_id == session.get('user_id'):
        flash('You cannot delete your own account', 'danger')
        return redirect(url_for('users'))
    
    db = get_db(); cur = db.cursor()
    
    # Get username before deleting
    cur.execute('SELECT username FROM users WHERE id = ?', (user_id,))
    user = cur.fetchone()
    
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('users'))
    
    cur.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    flash(f'User {user["username"]} deleted successfully', 'info')
    return redirect(url_for('users'))

# Context processor to make role permissions available in templates
@app.context_processor
def inject_permissions():
    if 'role' in session:
        return {
            'user_permissions': ROLE_PERMISSIONS.get(session['role'], []),
            'user_role': session.get('role'),
            'user_name': session.get('full_name')
        }
    return {'user_permissions': [], 'user_role': None, 'user_name': None}

if __name__ == '__main__':
    app.run(debug=True)