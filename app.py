import os
import tempfile
import uuid
from flask import Flask, render_template, request, redirect, jsonify, send_file, abort
from docx import Document

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    allowed_extensions = ['docx']
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

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
        if file.content_length > 10 * 1024 * 1024:  # Limit file size to 10MB
            abort(413)  # Request Entity Too Large
        unique_filename = str(uuid.uuid4()) + '.docx'
        file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        file.save(file_path)
        document = Document(file_path)
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
        return jsonify({'table_data': table_data, 'unique_filename': unique_filename})
    return redirect('/')

@app.route('/create_form', methods=['POST'])
def create_form():
    selected_cells = request.json
    form_html = '<form>'
    for cell_text in selected_cells:
        form_html += f'<label>{cell_text}:</label><input type="text" name="{cell_text}"><br>'
    form_html += '<input type="submit" value="Submit"></form>'
    return form_html

@app.route('/fill_data', methods=['POST'])
def fill_data():
    form_data = request.form
    unique_filename = form_data.get('unique_filename')
    file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
    document = Document(file_path)
    for cell_text, value in form_data.items():
        if cell_text != 'unique_filename':
            for table in document.tables:
                for row in table.rows:
                    for cell in row.cells:
                        if cell.text.strip() == cell_text:
                            # Preserve the original formatting and style of the cell
                            cell_paragraph = cell.paragraphs[0]
                            original_text = cell_paragraph.text
                            run = cell_paragraph.add_run(value)
                            run.font.name = cell_paragraph.runs[0].font.name
                            run.font.size = cell_paragraph.runs[0].font.size
                            run.bold = cell_paragraph.runs[0].bold
                            run.italic = cell_paragraph.runs[0].italic
                            run.underline = cell_paragraph.runs[0].underline

    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.docx')
    document.save(temp_file.name)
    temp_file.close()

    return jsonify({'file_url': '/download/' + os.path.basename(temp_file.name)})

@app.route('/download/<filename>')
def download_file(filename):
    temp_file_path = os.path.join(tempfile.gettempdir(), filename)
    return send_file(temp_file_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, port=5001)