from flask import Flask, render_template, request, redirect, jsonify
from docx import Document

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect('/')
    file = request.files['file']
    if file.filename == '':
        return redirect('/')
    if file and allowed_file(file.filename):
        document = Document(file)
        table_data = []
        unique_cells = set()
        for table in document.tables:
            for row in table.rows:
                row_data = []
                for cell in row.cells:
                    cell_text = cell.text.strip()
                    if cell_text not in unique_cells:
                        unique_cells.add(cell_text)
                        row_data.append(cell_text)
                if row_data:
                    table_data.append(row_data)
        return jsonify(table_data)
    return redirect('/')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'docx'

@app.route('/create_form', methods=['POST'])
def create_form():
    selected_cells = request.json
    form_html = '<form>'
    for cell_text in selected_cells:
        form_html += f'<label>{cell_text}:</label><input type="text" name="{cell_text}"><br>'
    form_html += '<input type="submit" value="Submit"></form>'
    return form_html

if __name__ == '__main__':
    app.run(debug=True, port=5001)