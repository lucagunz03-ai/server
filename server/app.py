import os, json, sqlite3, hmac, datetime
from flask import Flask, request, jsonify, render_template_string, Response

app=Flask(__name__)
DB=os.environ.get('DATABASE_PATH','reports.sqlite3')
UPLOAD_CODE=os.environ.get('UPLOAD_CODE','')
ADMIN_PASSWORD=os.environ.get('ADMIN_PASSWORD','')

def connect():
    db=sqlite3.connect(DB)
    db.execute('CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY AUTOINCREMENT, created TEXT, body TEXT)')
    return db

def admin_ok():
    auth=request.authorization
    return bool(ADMIN_PASSWORD and auth and hmac.compare_digest(auth.password or '',ADMIN_PASSWORD))

@app.route('/api/reports',methods=['POST'])
def submit():
    if not UPLOAD_CODE or not hmac.compare_digest(request.headers.get('X-Upload-Code',''),UPLOAD_CODE):
        return jsonify(error='Unauthorized'),401
    if request.content_length is None or request.content_length > 100000:
        return jsonify(error='Report too large'),413
    data=request.get_json(silent=True)
    if not isinstance(data,dict) or not isinstance(data.get('findings'),list) or len(data['findings'])>200:
        return jsonify(error='Invalid report'),400
    with connect() as db:
        cursor=db.execute('INSERT INTO reports(created,body) VALUES(?,?)',(datetime.datetime.now(datetime.timezone.utc).isoformat(),json.dumps(data)))
        rid=cursor.lastrowid
    return jsonify(id=rid),201

HTML='''<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>FiveM Scanner Dashboard</title><style>body{font:16px system-ui;background:#101725;color:#e6edf8;max-width:1000px;margin:40px auto;padding:20px}h1{color:#7aa7ff}.card{background:#1d293b;border:1px solid #34455d;border-radius:12px;padding:18px;margin:14px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;color:#c5d8ef}small{color:#9eafc9}</style><h1>FiveM Scanner Dashboard</h1><p>Freiwillig übermittelte Berichte. Treffer sind keine Cheat-Beweise.</p>{% for row in rows %}<div class="card"><strong>Bericht #{{row[0]}}</strong> <small>{{row[1]}}</small><pre>{{row[2]}}</pre></div>{% else %}<p>Keine Berichte vorhanden.</p>{% endfor %}</html>'''
@app.route('/')
def dashboard():
    if not admin_ok(): return Response('Admin login required',401,{'WWW-Authenticate':'Basic realm="Scanner Admin"'})
    with connect() as db: rows=db.execute('SELECT id,created,body FROM reports ORDER BY id DESC LIMIT 100').fetchall()
    return render_template_string(HTML,rows=rows)

@app.route('/health')
def health(): return jsonify(status='ok')

if __name__=='__main__':
    if not UPLOAD_CODE or not ADMIN_PASSWORD:
        raise SystemExit('Set UPLOAD_CODE and ADMIN_PASSWORD environment variables first.')
    app.run(host='127.0.0.1',port=5000)
