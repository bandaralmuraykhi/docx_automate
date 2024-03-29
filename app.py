import os
import tempfile
from flask import Flask, render_template, request, redirect, jsonify, send_file
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
        file.save('uploaded_file.docx')  # Save the uploaded file
        document = Document('uploaded_file.docx')
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

@app.route('/fill_data', methods=['POST'])
def fill_data():
    form_data = request.form
    document = Document('uploaded_file.docx')  # Load the uploaded .docx file
    for cell_text, value in form_data.items():
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
    
    # Save the modified .docx file to a temporary file
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