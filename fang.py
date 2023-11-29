
#flask libraries
from flask import Flask, render_template, request, session, redirect, url_for, g
import os
import html

#python libraries
import nmap

#Security features 
import pyfile.otp
import pyfile.password_check
import pyfile.randomkey
import pyfile.dataconn

from flask_wtf.csrf import CSRFProtect


#establishing db connection
db_path="/home/fang/Database/enc.db"
dv_path="/home/fang/Database/encdev.db"
enc_pss=os.environ.get('datapragma2')

app = Flask(__name__)  

key=pyfile.randomkey.generate_key()
app.secret_key="secret!!key!!"
csrf=CSRFProtect(app)

user=[]
devices=[]


#Security headers
@app.after_request
def security_headers(resp):
    # preventing man-in-the-middle (MITM) attack
    resp.headers['Strict-Transport-Security'] = 'max-age=31536000'
    resp.headers['Content-Security-Policy'] = 'default-src "self" ' #https://cdn.jsdelivr.net/npm/water.css@2/out/water.css'
    # prevent cross-site scripting (XSS) attack.
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    # prevents external sites from embedding your site in an iframe (clickjacking)
    resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
    return resp



@app.route('/')
def index():
    session['attempt'] = 3
    
    return render_template('landing.html')

# if user exist direct to info_gather else deny access
@app.route('/form_login',methods=['POST','GET'])
def login():
    #if request.method=='POST':
        
        name=request.form["username"]
        password=request.form["password"]
        otp=request.form["otp"]

        newname=html.escape(name)
        newpass=html.escape(password)
        newotp=html.escape(otp)
        
        conn=pyfile.dataconn.create_connection(db_path)
        c=conn.cursor()
        c.execute(enc_pss)

        sql = "SELECT username, pass, otp FROM clients WHERE username = ? AND key = ? AND otp = ?"
        c.execute(sql,(newname,newpass,newotp))
        result=c.fetchall()
        attempt= session.get('attempt')
        attempt -= 1
        session['attempt']=attempt

        if attempt == 0:
            return render_template('block.html')
    #validate 
        if len(result)==0:
            error=("You did not provide the correct credentials.")
            return render_template('landing.html',error=error)

        else:
            conn.close()
            user.append(name)
            session.pop('user',None)
            session['user']=request.form['username']
            return redirect(url_for("intel"))


@app.route('/Intel_gather')
def intel(): 
    if g.user:
        return render_template('intel_gather.html', user=session['user'])
    return render_template('landing.html')

#Called when 'Scan' button is pressed on intel_gather.html
@app.route('/scan',methods=['POST','GET'])
def scan():
    if g.user:
        dev=pyfile.dataconn.create_connection(dv_path)

        d=dev.cursor()
        d.execute(enc_pss)

        for u in user:
            u=u

        nm = nmap.PortScanner()
        nm.scan(hosts='192.168.1.0/24', arguments='-sn')

        for host in nm.all_hosts():
            if 'mac' in nm[host]['addresses']:
                mac_address = nm[host]["addresses"]["mac"]
                manufacturer = nm[host]["vendor"].get(mac_address, "Unknown")
                device={"IP":host,"MAC":mac_address,"MAN":manufacturer}
                device=(host,mac_address,manufacturer,)
                devices.append(device)

                
                d.execute("INSERT INTO devices (user, ip, macaddress,manufacturer) VALUES(?,?,?,?)",(u,host, mac_address, manufacturer))
                dev.commit()
        
        dev.close()
    #-------------------------------------------------------------------------------#

        # return ("Scan complete")
        return redirect(url_for('list'))

    return render_template('landing.html')

@app.route("/list")
def list():
    if g.user:    
        dev=pyfile.dataconn.create_connection(dv_path)

        d=dev.cursor()
        d.execute(enc_pss)

        listd = "SELECT rowid, ip,macaddress, manufacturer FROM devices"
        d.execute(listd)

        rows = d.fetchall()
        dev.close()
        # Send the results of the SELECT to the list.html page
        # return render_template("list.html", rows=rows)
        msg=g.user
        return render_template('list.html',msg=msg)
    else:
        msg=g.user
        return render_template('landing.html',msg=msg)

@app.route('/delete',methods=['POST','GET'])
def delete():
    if g.user:
       if request.method == 'POST':
        try:
             # Use the hidden input value of id from the form to get the rowid
            rowid = request.form['id']
            # Connect to the database and DELETE a specific record based on rowid
            with pyfile.dataconn.create_connection(dv_path) as con:
                    cur = con.cursor()
                    deldev="DELETE FROM devices WHERE rowid = ?"
                    cur.execute(deldev,(rowid))
                    con.commit()
        except:
            con.rollback()

        finally:
            con.close()
        
        return redirect(url_for('list'))

    else:
        msg=("Your session expired please login")
        return render_template('landing.html',msg=msg)

@app.route("/exit")
def exit():
    g.user=None
    msg=("YOU ARE LOGGED OUT")
    return render_template("landing.html",msg=msg)


@app.route('/otp',methods=['POST','GET'])
def verify():
    key=pyfile.otp.key()
    pyfile.otp.generate_qr(key)

    return render_template('otp.html')

@app.before_request
def before_request():
    g.user=None
    if 'user' in session:
        g.user=session['user']