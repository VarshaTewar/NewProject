from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
from database import init_db, get_db
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Initialize DB and tables
init_db()

# Simple credentials (change for production)
ADMIN_USER = 'admin'
ADMIN_PASS = 'admin123'

from functools import wraps
def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapped

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username','')
        password = request.form.get('password','')
        if username==ADMIN_USER and password==ADMIN_PASS:
            session['user'] = username
            flash('Logged in successfully','success')
            return redirect(url_for('index'))
        flash('Invalid credentials','danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Logged out','info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT COUNT(*) FROM beds'); total_beds = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM beds WHERE status='occupied'"); occupied = cur.fetchone()[0]
    cur.execute('SELECT COUNT(*) FROM patients'); patients = cur.fetchone()[0]
    cur.execute('SELECT COUNT(*) FROM staff'); staff = cur.fetchone()[0]
    cur.execute('SELECT SUM(quantity) FROM inventory'); total_items = cur.fetchone()[0] or 0
    available = total_beds - occupied
    bed_chart = {'occupied': occupied, 'available': available}
    return render_template('index.html', total_beds=total_beds, occupied=occupied, patients=patients, staff=staff, total_items=total_items, bed_chart=bed_chart)

# Patients
@app.route('/patients')
@login_required
def patients():
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT * FROM patients')
    rows = cur.fetchall()
    
    # Add these lines to provide stats for the layout
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
def add_patient():
    name = request.form.get('name'); age = request.form.get('age'); gender = request.form.get('gender'); reason = request.form.get('admission_reason')
    db = get_db(); cur = db.cursor()
    cur.execute('INSERT INTO patients (name, age, gender, admission_reason, bed_id) VALUES (?,?,?,?,NULL)', (name, age, gender, reason))
    db.commit()
    flash('Patient added','success')
    return redirect(url_for('patients'))

@app.route('/patients/assign/<int:pid>')
@login_required
def assign_bed(pid):
    db = get_db(); cur = db.cursor()
    cur.execute("SELECT * FROM beds WHERE status='available'")
    beds = cur.fetchall()
    cur.execute('SELECT * FROM patients WHERE id=?', (pid,))
    patient = cur.fetchone()
    return render_template('assign_bed.html', patient=patient, beds=beds)

@app.route('/patients/assign/save', methods=['POST'])
@login_required
def save_assigned_bed():
    pid = request.form.get('patient_id'); bed_id = request.form.get('bed_id')
    db = get_db(); cur = db.cursor()
    # set bed occupied and assign to patient
    cur.execute("UPDATE beds SET status='occupied' WHERE id=?", (bed_id,))
    cur.execute("UPDATE patients SET bed_id=? WHERE id=?", (bed_id, pid))
    db.commit()
    flash('Bed assigned','success')
    return redirect(url_for('patients'))

@app.route('/patients/discharge/<int:pid>', methods=['POST'])
@login_required
def discharge(pid):
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT bed_id FROM patients WHERE id=?', (pid,))
    row = cur.fetchone()
    if row and row['bed_id']:
        cur.execute('UPDATE beds SET status="available" WHERE id=?', (row['bed_id'],))
    cur.execute('DELETE FROM patients WHERE id=?', (pid,))
    db.commit()
    flash('Patient discharged','info')
    return redirect(url_for('patients'))

@app.route('/export/patients')
@login_required
def export_patients():
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT id, name, age, gender, admission_reason, bed_id FROM patients')
    rows = cur.fetchall()
    output = []
    header = ['id','name','age','gender','admission_reason','bed_id']
    output.append(','.join(header))
    for r in rows:
        vals = [str(r['id']), r['name'] or '', str(r['age'] or ''), r['gender'] or '', r['admission_reason'] or '', str(r['bed_id'] or '')]
        # escape quotes
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
def beds():
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT * FROM beds')
    rows = cur.fetchall()
    return render_template('beds.html', beds=rows)

@app.route('/beds/add', methods=['POST'])
@login_required
def add_bed():
    ward = request.form.get('ward'); bed_number = request.form.get('bed_number')
    db = get_db(); cur = db.cursor()
    cur.execute("INSERT INTO beds (ward, bed_number, status) VALUES (?,?,'available')", (ward, bed_number))
    db.commit()
    flash('Bed added','success')
    return redirect(url_for('beds'))

# Staff
@app.route('/staff')
@login_required
def staff():
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT * FROM staff')
    rows = cur.fetchall()
    return render_template('staff.html', staff=rows)

@app.route('/staff/add', methods=['POST'])
@login_required
def add_staff():
    name = request.form.get('name'); role = request.form.get('role'); on_duty = 1 if request.form.get('on_duty')=='on' else 0
    db = get_db(); cur = db.cursor()
    cur.execute('INSERT INTO staff (name, role, on_duty) VALUES (?,?,?)', (name, role, on_duty))
    db.commit()
    flash('Staff added','success')
    return redirect(url_for('staff'))

@app.route('/staff/toggle/<int:staff_id>', methods=['POST'])
@login_required
def toggle_staff(staff_id):
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT on_duty FROM staff WHERE id=?', (staff_id,))
    row = cur.fetchone()
    if row:
        new = 0 if row['on_duty'] else 1
        cur.execute('UPDATE staff SET on_duty=? WHERE id=?', (new, staff_id))
        db.commit()
    return redirect(url_for('staff'))

# Inventory
@app.route('/inventory')
@login_required
def inventory():
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT * FROM inventory')
    rows = cur.fetchall()
    low_items = [r for r in rows if (r['quantity'] or 0) <= 5]
    if low_items:
        flash(f"{len(low_items)} item(s) low in stock (<=5).", 'danger')
    return render_template('inventory.html', items=rows)

@app.route('/inventory/add', methods=['POST'])
@login_required
def add_item():
    name = request.form.get('name'); qty = int(request.form.get('quantity') or 0)
    db = get_db(); cur = db.cursor()
    cur.execute('INSERT INTO inventory (name, quantity) VALUES (?,?)', (name, qty))
    db.commit()
    flash('Inventory item added','success')
    return redirect(url_for('inventory'))

@app.route('/inventory/update/<int:item_id>', methods=['POST'])
@login_required
def update_item(item_id):
    qty = int(request.form.get('quantity') or 0)
    db = get_db(); cur = db.cursor()
    cur.execute('UPDATE inventory SET quantity=? WHERE id=?', (qty, item_id))
    db.commit()
    flash('Quantity updated','success')
    return redirect(url_for('inventory'))

if __name__ == '__main__':
    app.run(debug=True)
