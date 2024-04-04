# Dynamic Form Generator

The Dynamic Form Generator is a web application that allows users to upload a .docx file, select specific cells from the document, and generate a dynamic form based on the selected cells. Users can then share the generated form URL with others, who can fill in the form and download the modified .docx file with the filled data.

## Features

- User registration and authentication
- Email confirmation and password reset functionality
- File upload and validation (.docx files only)
- Extraction of table data from the uploaded .docx file
- Selection of specific cells for form generation
- Dynamic form creation based on the selected cells
- Sharing of the generated form URL
- Filling in the form data and downloading the modified .docx file
- Option to send the modified file to the user's email
- Option to allow or disallow visitors to download the modified file
- User dashboard to manage and view form responses
- Deleting and updating form responses
- Error handling and logging for improved reliability and debugging

## Technologies Used

- Python
- Flask (web framework)
- Flask-SQLAlchemy (database ORM)
- Flask-Login (user authentication)
- Flask-WTF (form handling)
- Flask-Mail (email sending)
- SQLite (database)
- Jinja2 (templating engine)
- HTML/CSS
- JavaScript
- jQuery
- Bulma (CSS framework)
- python-docx (library for working with .docx files)
- Node.js (JavaScript runtime)
- npm (Node.js package manager)

## Getting Started

1. Clone the repository:
   ```
   git clone https://github.com/bandaralmuraykhi/docx_automate
   ```

2. Backend Setup:
   - Create a virtual environment:
     ```
     python3 -m venv .flask-env
     ```
   - Activate the virtual environment:
     - For Windows:
       ```
       .flask-env\Scripts\activate
       ```
     - For macOS and Linux:
       ```
       source .flask-env/bin/activate
       ```
   - Install the backend dependencies:
     ```
     pip install -r requirements.txt
     ```
   - Create a `config.cfg` file in the same directory as `app.py` for SMTP server configuration:
     ```
     MAIL_SERVER='smtp.gmail.com'
     MAIL_PORT=587
     MAIL_USE_TLS=True
     MAIL_USERNAME='Youremail@example.com'
     MAIL_PASSWORD='appPassword'
     MAIL_DEFAULT_SENDER='Youremail@example.com'
     ```

3. Frontend Setup:
   - Install Node.js and npm:
     - Download the Node.js installer from the official Node.js website: [Node.js Downloads](https://nodejs.org/en/download/).
     - Follow the installation wizard instructions for your operating system.
   - Install Bulma CSS framework:
     ```
     npm install bulma
     ```

4. Set Environment Variable:
   - Windows (Command Prompt):
     ```
     set FLASK_SECRET_KEY=your_secret_key_here
     ```
   - macOS/Linux (Terminal):
     ```
     export FLASK_SECRET_KEY=your_secret_key_here
     ```

5. Run the application:
   ```
   python3 app.py
   ```

6. Open a web browser and navigate to `http://localhost:5001` to access the application.

## Usage

1. Register a new account or log in with an existing account.
2. Confirm your email address by clicking on the confirmation link sent to your email.
3. On the home page, click on the "Upload" button to select a .docx file from your computer.
4. After the file is uploaded, a table will be displayed with the extracted cell data.
5. Select the desired cells from the table by clicking on them individually.
6. Click on the "Submit Selected Cells" button to generate a dynamic form.
7. Share the generated form URL with others.
8. Fill in the form with the required data and submit it.
9. The modified .docx file with the filled data will be available for download.
10. Access the user dashboard to view and manage your form responses.

## Project Structure

```
project_directory/
├── app.py
├── img/
├── instance/
│   └── database.db
├── templates/
│   └── 404.html
│   └── 505.html
│   ├── base.html
│   ├── confirm_email.html
│   ├── confirm_email.txt
│   ├── dashboard.html
│   ├── fill_form.html
│   ├── home.html
│   ├── index.html
│   ├── login.html
│   ├── reset_password_email.html
│   ├── reset_password_request.html
│   ├── reset_password.html
│   ├── reset_password.txt
│   ├── signup.html
│   ├── unconfirmed.html
│   └── update_form.html
├── uploads/
└── requirements.txt
└── config.cfg
```

## Future Enhancements

Here are a few additional features and improvements we could consider adding to enhance the user experience and functionality of the application:

1. Progress Indicator: Add a progress indicator or loading spinner to provide visual feedback to the user while the file is being uploaded, processed, or downloaded. This can be especially useful for larger files or slower network connections.

2. Validation and Sanitization: Further enhance the validation of user inputs, especially for file uploads and form submissions, to prevent attacks like SQL injection or XSS.

3. Dockerization: Containerize the app with Docker for easier deployment and scaling.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE).

## Contact

For any inquiries or questions, please contact [balmuraykhi@gmail.com](mailto:balmuraykhi@gmail.com).
