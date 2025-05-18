from flask import Flask, request, render_template_string
import malscan

app = Flask(__name__)

HTML = '''
<h2>Malscan Web Dashboard</h2>
<form method="post">
    <label>Directory to Scan:</label><br>
    <input name="directory" type="text" style="width:300px"/><br><br>
    <input type="submit" value="Scan Now"/>
</form>
{% if result %}
<h3>Results:</h3>
<pre>{{ result }}</pre>
{% endif %}
'''

@app.route('/', methods=['GET', 'POST'])
def home():
    result = ''
    if request.method == 'POST':
        directory = request.form.get('directory')
        signatures = malscan.load_signatures()
        static_hits = malscan.static_scan(directory, signatures)
        behavior_hits = malscan.behavioral_scan()
        result += "[Static Analysis]\n" + '\n'.join([f"{f}" for f, _ in static_hits])
        result += "\n\n[Behavioral Alerts]\n" + '\n'.join([str(p) for p in behavior_hits])
        malscan.log_result(static_hits, behavior_hits)
    return render_template_string(HTML, result=result)

if __name__ == "__main__":
    app.run(debug=True)
